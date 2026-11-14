// Client key custody. The unwrapped private key exists only in memory as a
// non-extractable CryptoKey; reloading the page locks the vault again.
import * as C from '/shared/crypto-core.js';
import { get, post, setCsrf } from './api.js';

export const state = { user: null, privateKey: null, publicKey: null, kdf: null, keys: null, session: null };

export function isUnlocked() {
  return !!state.privateKey;
}

export async function loadSession() {
  try {
    const me = await get('/api/auth/me');
    if (!me.user) return false;
    setCsrf(me.csrfToken);
    Object.assign(state, { user: me.user, kdf: me.kdf, keys: me.keys, session: me.session });
    return true;
  } catch {
    return false;
  }
}

export async function signIn(username, password) {
  const pre = await post('/api/auth/prelogin', { username });
  const { authKey, kek } = await C.derivePasswordKeys(password, pre.kdfSalt, pre.kdfIterations, pre.userId);
  const res = await post('/api/auth/login', { username, authKey });
  setCsrf(res.csrfToken);
  state.user = res.user;
  state.keys = res.keys;
  state.kdf = { kdfSalt: pre.kdfSalt, kdfIterations: pre.kdfIterations };
  state.privateKey = await C.unwrapPrivateKey(res.keys.wrappedPrivateKey, res.keys.wrapIv, kek, res.user.id);
  state.publicKey = await C.importPublicKey(res.keys.publicKey);
  return res.user;
}

/** Session cookie still valid but key not in memory (page reload). */
export async function unlock(password) {
  const { kek } = await C.derivePasswordKeys(password, state.kdf.kdfSalt, state.kdf.kdfIterations, state.user.id);
  try {
    state.privateKey = await C.unwrapPrivateKey(state.keys.wrappedPrivateKey, state.keys.wrapIv, kek, state.user.id);
  } catch {
    throw new Error('That password does not open your key. Check it and try again.');
  }
  state.publicKey = await C.importPublicKey(state.keys.publicKey);
}

export async function startEnrollment(username, code) {
  return post('/api/auth/enroll/start', { username, code });
}

export async function completeEnrollment(username, code, password, start, onStep = () => {}) {
  onStep('derive');
  const { authKey, kek } = await C.derivePasswordKeys(password, start.kdfSalt, start.kdfIterations, start.userId);
  onStep('keypair');
  const kp = await C.generateUserKeyPair();
  const publicKey = await C.exportPublicKey(kp.publicKey);
  const { wrappedPrivateKey, wrapIv } = await C.wrapPrivateKey(kp.privateKey, kek, start.userId);
  onStep('register');
  const res = await post('/api/auth/enroll/complete', { username, code, authKey, publicKey, wrappedPrivateKey, wrapIv });
  setCsrf(res.csrfToken);
  state.user = res.user;
  state.keys = res.keys;
  state.kdf = { kdfSalt: start.kdfSalt, kdfIterations: start.kdfIterations };
  state.privateKey = await C.unwrapPrivateKey(wrappedPrivateKey, wrapIv, kek, start.userId);
  state.publicKey = await C.importPublicKey(publicKey);
  return res.user;
}

export async function changePassword(current, next) {
  const cur = await C.derivePasswordKeys(current, state.kdf.kdfSalt, state.kdf.kdfIterations, state.user.id);
  // The in-memory key is non-extractable, so unwrap an extractable copy with the
  // current password (this also proves the password) and re-wrap it with the new one.
  let priv;
  try {
    priv = await crypto.subtle.unwrapKey(
      'pkcs8',
      C.fromB64(state.keys.wrappedPrivateKey),
      cur.kek,
      { name: 'AES-GCM', iv: C.fromB64(state.keys.wrapIv), additionalData: new TextEncoder().encode(`vaultshare/privkey/v1:${state.user.id}`) },
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['unwrapKey']
    );
  } catch {
    throw new Error('Current password is incorrect.');
  }
  const nxt = await C.derivePasswordKeys(next, state.kdf.kdfSalt, state.kdf.kdfIterations, state.user.id);
  const wrapped = await C.wrapPrivateKey(priv, nxt.kek, state.user.id);
  const res = await post('/api/auth/password', { currentAuthKey: cur.authKey, newAuthKey: nxt.authKey, ...wrapped });
  setCsrf(res.csrfToken);
  state.keys = { ...state.keys, ...wrapped };
}

export async function signOut() {
  try {
    await post('/api/auth/logout');
  } catch {
    /* already signed out */
  }
  Object.assign(state, { user: null, privateKey: null, publicKey: null, kdf: null, keys: null, session: null });
  setCsrf(null);
}
