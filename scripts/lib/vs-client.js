// Headless VaultShare client that behaves exactly like the browser client
// (same shared crypto core). Used by the seed script, automated tests and the
// evaluation harness.
import * as C from '../../shared/crypto-core.js';
import { describeContent } from '../../shared/content-sniff.js';

export class VSClient {
  constructor(baseUrl) {
    this.base = baseUrl.replace(/\/$/, '');
    this.cookie = null;
    this.csrf = null;
    this.user = null;
    this.privateKey = null;
  }

  async req(method, path, body, { headers = {}, raw = false } = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (this.csrf && method !== 'GET') h['x-csrf-token'] = this.csrf;
    let payload;
    if (body !== undefined) {
      if (raw) payload = body;
      else {
        h['content-type'] = 'application/json';
        payload = JSON.stringify(body);
      }
    } else if (method !== 'GET') {
      h['content-type'] = 'application/json';
      payload = '{}';
    }
    const t0 = performance.now();
    const res = await fetch(this.base + path, { method, headers: h, body: payload });
    const ms = performance.now() - t0;
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const m = /vs_sid=([^;]*)/.exec(setCookie);
      if (m) this.cookie = m[1] ? `vs_sid=${m[1]}` : null;
    }
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('json') ? await res.json() : await res.text();
    return { status: res.status, body: data, headers: res.headers, ms };
  }

  async enroll(username, code, password) {
    const start = await this.req('POST', '/api/auth/enroll/start', { username, code });
    if (start.status !== 200) return start;
    const { userId, kdfSalt, kdfIterations } = start.body;
    const { authKey, kek } = await C.derivePasswordKeys(password, kdfSalt, kdfIterations, userId);
    const kp = await C.generateUserKeyPair();
    const publicKey = await C.exportPublicKey(kp.publicKey);
    const { wrappedPrivateKey, wrapIv } = await C.wrapPrivateKey(kp.privateKey, kek, userId);
    const res = await this.req('POST', '/api/auth/enroll/complete', { username, code, authKey, publicKey, wrappedPrivateKey, wrapIv });
    if (res.status === 201) {
      this.csrf = res.body.csrfToken;
      this.user = res.body.user;
      this.privateKey = await C.unwrapPrivateKey(wrappedPrivateKey, wrapIv, kek, userId);
    }
    return res;
  }

  async login(username, password) {
    const pre = await this.req('POST', '/api/auth/prelogin', { username });
    if (pre.status !== 200) return pre;
    const { authKey, kek } = await C.derivePasswordKeys(password, pre.body.kdfSalt, pre.body.kdfIterations, pre.body.userId);
    const res = await this.req('POST', '/api/auth/login', { username, authKey });
    if (res.status === 200) {
      this.csrf = res.body.csrfToken;
      this.user = res.body.user;
      this.privateKey = await C.unwrapPrivateKey(res.body.keys.wrappedPrivateKey, res.body.keys.wrapIv, kek, res.body.user.id);
    }
    return res;
  }

  async logout() {
    const r = await this.req('POST', '/api/auth/logout');
    this.cookie = this.csrf = this.user = this.privateKey = null;
    return r;
  }

  /** Encrypt in "the browser" and upload. Returns { status, body, docId }. */
  async upload(filename, mimeType, plaintext) {
    const bytes = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const init = await this.req('POST', '/api/documents', { filename, mimeType, sizeBytes: bytes.length, content: describeContent(bytes) });
    if (init.status !== 201) return init;
    const dek = await C.generateDek();
    const container = await C.encryptDocument(dek, bytes, init.body.binding);
    const ownPub = await C.importPublicKey((await this.req('GET', '/api/auth/me')).body.keys.publicKey);
    const wrappedKey = await C.wrapDekFor(dek, ownPub);
    const up = await this.req('PUT', `/api/documents/${init.body.id}/content`, { ciphertext: C.toB64(container), wrappedKey });
    return { ...up, docId: init.body.id, binding: init.body.binding, container };
  }

  async directory() {
    return (await this.req('GET', '/api/directory')).body.users;
  }

  async share(docId, recipientUsername, { minutes = 60, maxDownloads = 3, fingerprintOverride } = {}) {
    const dir = await this.directory();
    const r = dir.find((u) => u.username === recipientUsername);
    if (!r) throw new Error(`recipient ${recipientUsername} not in directory`);
    const pk = (await this.req('GET', `/api/directory/${r.id}/public-key`)).body;
    const own = await this.req('GET', `/api/documents/${docId}/owner-key`);
    if (own.status !== 200) return own;
    const dek = await C.unwrapDek(own.body.wrappedKey, this.privateKey, true);
    const wrappedKey = await C.wrapDekFor(dek, await C.importPublicKey(pk.publicKey));
    return this.req('POST', `/api/documents/${docId}/grants`, {
      recipientId: r.id,
      wrappedKey,
      recipientKeyFingerprint: fingerprintOverride || pk.keyFingerprint,
      expiresInMinutes: minutes,
      maxDownloads,
    });
  }

  /** Request, unwrap and decrypt. Returns { status, body, plaintext?, error? } */
  async download(docId, { tamper } = {}) {
    const res = await this.req('POST', `/api/documents/${docId}/download`);
    if (res.status !== 200) return res;
    let ct = C.fromB64(res.body.ciphertext);
    if (tamper) ct = tamper(ct);
    try {
      const dek = await C.unwrapDek(res.body.wrappedKey, this.privateKey);
      const plaintext = await C.decryptDocument(dek, ct, res.body.binding);
      return { ...res, plaintext };
    } catch (e) {
      const report = await this.req('POST', `/api/documents/${docId}/integrity-failure`, { downloadId: res.body.watermark.downloadId, check: e.message });
      return { ...res, error: e.message, report };
    }
  }
}
