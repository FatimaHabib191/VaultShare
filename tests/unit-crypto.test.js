import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../shared/crypto-core.js';

const enc = new TextEncoder();
const binding = C.documentBinding('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222');

test('AES-GCM round trip restores the exact plaintext', async () => {
  const dek = await C.generateDek();
  const pt = enc.encode('confidential sample text ✓');
  const ct = await C.encryptDocument(dek, pt, binding);
  assert.equal(ct.length, pt.length + C.CONTAINER_OVERHEAD_BYTES);
  assert.deepEqual(await C.decryptDocument(dek, ct, binding), pt);
});

test('ciphertext does not contain the plaintext and IVs never repeat', async () => {
  const dek = await C.generateDek();
  const pt = enc.encode('PLAINTEXT-MARKER-PLAINTEXT-MARKER');
  const a = await C.encryptDocument(dek, pt, binding);
  const b = await C.encryptDocument(dek, pt, binding);
  assert.ok(!Buffer.from(a).includes(Buffer.from('PLAINTEXT-MARKER')));
  assert.notDeepEqual(a.subarray(6, 18), b.subarray(6, 18));
  assert.notDeepEqual(a, b);
});

for (const [name, mutate] of [
  ['magic header byte', (c) => (c[0] ^= 1)],
  ['IV byte', (c) => (c[8] ^= 1)],
  ['first ciphertext byte', (c) => (c[C.CONTAINER_HEADER_BYTES] ^= 1)],
  ['last tag byte', (c) => (c[c.length - 1] ^= 0x80)],
]) {
  test(`altering the ${name} is rejected`, async () => {
    const dek = await C.generateDek();
    const ct = await C.encryptDocument(dek, enc.encode('integrity matters'), binding);
    mutate(ct);
    await assert.rejects(C.decryptDocument(dek, ct, binding), /INTEGRITY_CHECK_FAILED|CONTAINER_BAD_MAGIC/);
  });
}

test('truncated ciphertext and wrong binding are rejected', async () => {
  const dek = await C.generateDek();
  const ct = await C.encryptDocument(dek, enc.encode('bound to one document'), binding);
  await assert.rejects(C.decryptDocument(dek, ct.subarray(0, ct.length - 1), binding), /INTEGRITY_CHECK_FAILED/);
  await assert.rejects(C.decryptDocument(dek, ct, binding.replace('1111', '3333')), /INTEGRITY_CHECK_FAILED/);
});

test('a different key cannot decrypt', async () => {
  const ct = await C.encryptDocument(await C.generateDek(), enc.encode('x'), binding);
  await assert.rejects(C.decryptDocument(await C.generateDek(), ct, binding), /INTEGRITY_CHECK_FAILED/);
});

test('parseContainer reports structural problems without a key', () => {
  assert.equal(C.parseContainer(new Uint8Array(10)).reason, 'CONTAINER_TOO_SHORT');
  const bad = new Uint8Array(40);
  assert.equal(C.parseContainer(bad).reason, 'CONTAINER_BAD_MAGIC');
  bad.set(C.CONTAINER_MAGIC);
  bad[4] = 9;
  assert.equal(C.parseContainer(bad).reason, 'CONTAINER_UNSUPPORTED_VERSION');
  bad[4] = 1;
  bad[5] = 16;
  assert.equal(C.parseContainer(bad).reason, 'CONTAINER_BAD_IV_LENGTH');
  bad[5] = 12;
  assert.equal(C.parseContainer(bad).ok, true);
});

test('DEK wrapped for one recipient opens only with that recipient key', async () => {
  const alice = await C.generateUserKeyPair();
  const bob = await C.generateUserKeyPair();
  const dek = await C.generateDek();
  const wrapped = await C.wrapDekFor(dek, alice.publicKey);
  assert.equal(C.fromB64(wrapped).length, C.RSA_WRAPPED_KEY_BYTES);
  const opened = await C.unwrapDek(wrapped, alice.privateKey);
  const ct = await C.encryptDocument(dek, enc.encode('shared'), binding);
  assert.equal(new TextDecoder().decode(await C.decryptDocument(opened, ct, binding)), 'shared');
  await assert.rejects(C.unwrapDek(wrapped, bob.privateKey), /DEK_UNWRAP_FAILED/);
});

test('private key is wrapped by the password-derived KEK; wrong password fails', async () => {
  const salt = C.toB64(C.randomBytes(16));
  const uid = 'user-1';
  const right = await C.derivePasswordKeys('correct horse battery', salt, 1000, uid);
  const wrong = await C.derivePasswordKeys('incorrect horse battery', salt, 1000, uid);
  assert.notEqual(right.authKey, wrong.authKey);
  const kp = await C.generateUserKeyPair();
  const w = await C.wrapPrivateKey(kp.privateKey, right.kek, uid);
  await C.unwrapPrivateKey(w.wrappedPrivateKey, w.wrapIv, right.kek, uid);
  await assert.rejects(C.unwrapPrivateKey(w.wrappedPrivateKey, w.wrapIv, wrong.kek, uid), /PRIVATE_KEY_UNWRAP_FAILED/);
  await assert.rejects(C.unwrapPrivateKey(w.wrappedPrivateKey, w.wrapIv, right.kek, 'user-2'), /PRIVATE_KEY_UNWRAP_FAILED/);
});

test('authKey is deterministic and independent of the KEK', async () => {
  const salt = C.toB64(C.randomBytes(16));
  const a = await C.derivePasswordKeys('same password', salt, 1000, 'u');
  const b = await C.derivePasswordKeys('same password', salt, 1000, 'u');
  assert.equal(a.authKey, b.authKey);
  assert.equal(C.fromB64(a.authKey).length, 32);
});

test('fingerprint is the SHA-256 of the SPKI', async () => {
  const kp = await C.generateUserKeyPair();
  const spki = await C.exportPublicKey(kp.publicKey);
  const fp = await C.publicKeyFingerprint(spki);
  assert.match(fp, /^[0-9a-f]{64}$/);
  assert.equal(C.formatFingerprint(fp).split(' ').length, 8);
});

test('base64 decoder rejects malformed input', () => {
  assert.throws(() => C.fromB64('abc'), /INVALID_BASE64/);
  assert.throws(() => C.fromB64('ab$='), /INVALID_BASE64/);
});
