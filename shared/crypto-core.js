// VaultShare cryptographic core.
// Isomorphic ES module: runs in the browser (Web Crypto API) and in Node >= 20
// (globalThis.crypto.subtle), so the exact same code is used by the client,
// the seed script, the automated tests and the evaluation harness.
//
// Scheme summary
//   password --PBKDF2-SHA256(salt, N)--> master (256 bit)
//   master   --HKDF-SHA256("vaultshare/auth/v1")--> authKey  (sent to server, which scrypt-hashes it)
//   master   --HKDF-SHA256("vaultshare/kek/v1")---> KEK      (AES-256-GCM, never leaves the browser)
//   KEK wraps the user's RSA-OAEP-2048 private key (PKCS#8) -> stored server-side as an opaque blob
//   Each document: random AES-256-GCM DEK + 96-bit IV, AAD = container header || document binding
//   DEK is wrapped (RSA-OAEP-SHA256) once per recipient -> grants table

export const CRYPTO_VERSION = 'vaultshare-crypto/1.0.0';
export const RSA_MODULUS_BITS = 2048;
export const RSA_WRAPPED_KEY_BYTES = RSA_MODULUS_BITS / 8;
export const GCM_IV_BYTES = 12;
export const GCM_TAG_BYTES = 16;
export const CONTAINER_MAGIC = [0x56, 0x53, 0x48, 0x31]; // "VSH1"
export const CONTAINER_VERSION = 1;
export const CONTAINER_HEADER_BYTES = 4 + 1 + 1 + GCM_IV_BYTES; // magic | version | ivLen | iv
export const CONTAINER_OVERHEAD_BYTES = CONTAINER_HEADER_BYTES + GCM_TAG_BYTES;

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

// ---------- encoding helpers ----------
export function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function fromB64(b64) {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) {
    throw new Error('INVALID_BASE64');
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export async function sha256Hex(data) {
  const bytes = typeof data === 'string' ? enc.encode(data) : data;
  return toHex(await subtle.digest('SHA-256', bytes));
}

/** Human-comparable fingerprint: SHA-256 of SPKI, grouped in 4-hex blocks. */
export async function publicKeyFingerprint(spkiB64) {
  const hex = await sha256Hex(fromB64(spkiB64));
  return hex;
}

export function formatFingerprint(hex) {
  return (hex.slice(0, 32).match(/.{4}/g) || []).join(' ').toUpperCase();
}

// ---------- password-derived keys ----------
export async function derivePasswordKeys(password, saltB64, iterations, userId) {
  if (typeof password !== 'string' || password.length === 0) throw new Error('PASSWORD_REQUIRED');
  const base = await subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const masterBits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations },
    base,
    256
  );
  const master = await subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const authBits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('vaultshare/auth/v1') },
    master,
    256
  );
  const kek = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(`vaultshare/kek/v1:${userId}`) },
    master,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
  return { authKey: toB64(authBits), kek };
}

// ---------- user key pair ----------
export async function generateUserKeyPair() {
  return subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: RSA_MODULUS_BITS, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['wrapKey', 'unwrapKey']
  );
}

export async function exportPublicKey(publicKey) {
  return toB64(await subtle.exportKey('spki', publicKey));
}

export async function importPublicKey(spkiB64) {
  return subtle.importKey('spki', fromB64(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['wrapKey']);
}

export async function wrapPrivateKey(privateKey, kek, userId) {
  const iv = randomBytes(GCM_IV_BYTES);
  const wrapped = await subtle.wrapKey('pkcs8', privateKey, kek, {
    name: 'AES-GCM',
    iv,
    additionalData: enc.encode(`vaultshare/privkey/v1:${userId}`),
  });
  return { wrappedPrivateKey: toB64(wrapped), wrapIv: toB64(iv) };
}

export async function unwrapPrivateKey(wrappedB64, ivB64, kek, userId) {
  try {
    return await subtle.unwrapKey(
      'pkcs8',
      fromB64(wrappedB64),
      kek,
      { name: 'AES-GCM', iv: fromB64(ivB64), additionalData: enc.encode(`vaultshare/privkey/v1:${userId}`) },
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['unwrapKey']
    );
  } catch {
    throw new Error('PRIVATE_KEY_UNWRAP_FAILED');
  }
}

// ---------- document encryption ----------
export async function generateDek() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function wrapDekFor(dek, recipientPublicKey) {
  return toB64(await subtle.wrapKey('raw', dek, recipientPublicKey, { name: 'RSA-OAEP' }));
}

/** extractable=true only when the owner must re-wrap the DEK for a new recipient. */
export async function unwrapDek(wrappedB64, privateKey, extractable = false) {
  try {
    return await subtle.unwrapKey('raw', fromB64(wrappedB64), privateKey, { name: 'RSA-OAEP' }, { name: 'AES-GCM', length: 256 }, extractable, ['decrypt']);
  } catch {
    throw new Error('DEK_UNWRAP_FAILED');
  }
}

function buildHeader(iv) {
  const h = new Uint8Array(CONTAINER_HEADER_BYTES);
  h.set(CONTAINER_MAGIC, 0);
  h[4] = CONTAINER_VERSION;
  h[5] = GCM_IV_BYTES;
  h.set(iv, 6);
  return h;
}

function aadFor(header, binding) {
  const b = enc.encode(binding);
  const out = new Uint8Array(header.length + b.length);
  out.set(header, 0);
  out.set(b, header.length);
  return out;
}

/**
 * Structural validation of an encrypted container. Needs no key, so the server
 * uses it to reject malformed uploads without ever seeing plaintext.
 */
export function parseContainer(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u8.length < CONTAINER_OVERHEAD_BYTES) return { ok: false, reason: 'CONTAINER_TOO_SHORT' };
  for (let i = 0; i < 4; i++) if (u8[i] !== CONTAINER_MAGIC[i]) return { ok: false, reason: 'CONTAINER_BAD_MAGIC' };
  if (u8[4] !== CONTAINER_VERSION) return { ok: false, reason: 'CONTAINER_UNSUPPORTED_VERSION' };
  if (u8[5] !== GCM_IV_BYTES) return { ok: false, reason: 'CONTAINER_BAD_IV_LENGTH' };
  return {
    ok: true,
    version: u8[4],
    header: u8.subarray(0, CONTAINER_HEADER_BYTES),
    iv: u8.subarray(6, 6 + GCM_IV_BYTES),
    body: u8.subarray(CONTAINER_HEADER_BYTES),
    plaintextLength: u8.length - CONTAINER_OVERHEAD_BYTES,
  };
}

export async function encryptDocument(dek, plaintext, binding) {
  const iv = randomBytes(GCM_IV_BYTES);
  const header = buildHeader(iv);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aadFor(header, binding), tagLength: 128 }, dek, plaintext)
  );
  const out = new Uint8Array(header.length + ct.length);
  out.set(header, 0);
  out.set(ct, header.length);
  return out;
}

export async function decryptDocument(dek, container, binding) {
  const p = parseContainer(container);
  if (!p.ok) throw new Error(p.reason);
  try {
    return new Uint8Array(
      await subtle.decrypt({ name: 'AES-GCM', iv: p.iv, additionalData: aadFor(p.header, binding), tagLength: 128 }, dek, p.body)
    );
  } catch {
    // GCM tag mismatch: ciphertext, IV, header or binding was altered, or wrong key.
    throw new Error('INTEGRITY_CHECK_FAILED');
  }
}

export function documentBinding(docId, ownerId) {
  return `vaultshare/doc/v1:${docId}:${ownerId}`;
}
