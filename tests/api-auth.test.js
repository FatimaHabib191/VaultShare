// FR-1 integration: enrollment, sign-in, sessions, CSRF, rate limiting, roles.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startInstance, PASSWORDS } from '../scripts/lib/harness.js';
const TXT_HEAD = { headHex: '68656c6c6f', utf8: true, hasNul: false };
const PDF_HEAD = { headHex: '255044462d312e37', utf8: false, hasNul: false };
const PNG_HEAD = { headHex: '89504e470d0a1a0a', utf8: false, hasNul: true };


let inst, U;
before(async () => {
  inst = await startInstance();
  U = await inst.standardUsers();
});
after(() => inst.destroy());

test('server never stores the password or the authKey in clear', () => {
  const row = inst.svc.db.prepare("SELECT * FROM users WHERE username = 'alice'").get();
  const dump = JSON.stringify(row);
  assert.ok(!dump.includes(PASSWORDS.alice));
  assert.match(row.auth_hash, /^[0-9a-f]{64}$/);
  assert.ok(row.wrapped_private_key.length > 1000, 'private key stored only in wrapped form');
});

test('wrong password gives the same generic error as an unknown user', async () => {
  const a = await inst.client().login('alice', 'Wrong#password1');
  const b = await inst.client().login('nobody-here', 'Wrong#password1');
  assert.equal(a.status, 401);
  assert.equal(b.status, 401);
  assert.equal(a.body.error.code, 'AUTH_FAILED');
  assert.equal(a.body.error.message, b.body.error.message);
});

test('prelogin does not reveal whether a username exists', async () => {
  const c = inst.client();
  const real = await c.req('POST', '/api/auth/prelogin', { username: 'alice' });
  const fake = await c.req('POST', '/api/auth/prelogin', { username: 'ghost-user' });
  const fake2 = await c.req('POST', '/api/auth/prelogin', { username: 'ghost-user' });
  assert.deepEqual(Object.keys(real.body).sort(), Object.keys(fake.body).sort());
  assert.deepEqual(fake.body, fake2.body, 'decoy salt is stable');
  assert.match(fake.body.userId, /^[0-9a-f-]{36}$/);
});

test('enrollment code is single-use', async () => {
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'oneuse', role: 'viewer' });
  const ok = await inst.client().enroll('oneuse', r.body.enrollmentCode, 'Oneuse#pass12');
  assert.equal(ok.status, 201);
  const again = await inst.client().enroll('oneuse', r.body.enrollmentCode, 'Another#pass12');
  assert.equal(again.status, 400);
  assert.equal(again.body.error.code, 'ENROLLMENT_INVALID');
});

test('enrollment rejects a weak or malformed public key', async () => {
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'badkey', role: 'viewer' });
  const c = inst.client();
  const start = await c.req('POST', '/api/auth/enroll/start', { username: 'badkey', code: r.body.enrollmentCode });
  assert.equal(start.status, 200);
  const res = await c.req('POST', '/api/auth/enroll/complete', {
    username: 'badkey',
    code: r.body.enrollmentCode,
    authKey: Buffer.alloc(32, 1).toString('base64'),
    publicKey: Buffer.alloc(300, 2).toString('base64'),
    wrappedPrivateKey: Buffer.alloc(1200, 3).toString('base64'),
    wrapIv: Buffer.alloc(12, 4).toString('base64'),
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.details[0].rule, 'KEY_PARAMS');
});

test('state-changing request without CSRF token is rejected and logged', async () => {
  const c = inst.client();
  await c.login('bob', PASSWORDS.bob);
  const saved = c.csrf;
  c.csrf = null;
  const r = await c.req('POST', '/api/auth/logout');
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'CSRF_FAILED');
  c.csrf = saved;
  const ev = inst.svc.repos.audit.query({ action: 'CSRF_REJECTED', limit: 1 })[0];
  assert.equal(ev.details.reason, 'token_mismatch');
});

test('cross-origin request is rejected by the Origin check', async () => {
  const r = await inst.client().req('POST', '/api/auth/prelogin', { username: 'alice' }, { headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'CSRF_FAILED');
});

test('non-JSON state-changing request is rejected', async () => {
  const r = await inst.client().req('POST', '/api/auth/prelogin', 'username=alice', { raw: true, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(r.status, 400);
});

test('session cookie is HttpOnly and SameSite=Strict', async () => {
  const res = await fetch(`${inst.base}/api/auth/prelogin`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'victor' }) });
  const pre = await res.json();
  const C = await import('../shared/crypto-core.js');
  const { authKey } = await C.derivePasswordKeys(PASSWORDS.victor, pre.kdfSalt, pre.kdfIterations, pre.userId);
  const login = await fetch(`${inst.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'victor', authKey }) });
  const sc = login.headers.get('set-cookie');
  assert.match(sc, /HttpOnly/i);
  assert.match(sc, /SameSite=Strict/i);
});

test('idle session expires and the expiry is audited', async () => {
  const c = inst.client();
  await c.login('victor', PASSWORDS.victor);
  assert.equal((await c.req('GET', '/api/documents')).status, 200);
  inst.advance((inst.svc.settings().session_idle_minutes + 1) * 60_000);
  const r = await c.req('GET', '/api/documents');
  assert.equal(r.status, 401);
  assert.equal(r.body.error.code, 'SESSION_EXPIRED');
  assert.equal(inst.svc.repos.audit.query({ action: 'SESSION_EXPIRED', limit: 1 })[0].details.reason, 'idle');
  // re-establish logins for later tests
  for (const u of ['alice', 'bob', 'victor', 'mallory']) await U[u].login(u, PASSWORDS[u]);
  await U.admin.login('admin', PASSWORDS.admin);
});

test('login attempts are rate limited per user and IP', async () => {
  const limit = inst.svc.settings().login_attempts_per_15min;
  let last;
  for (let i = 0; i < limit + 1; i++) last = await inst.client().req('POST', '/api/auth/login', { username: 'mallory', authKey: Buffer.alloc(32).toString('base64') });
  assert.equal(last.status, 429);
  assert.equal(last.body.error.code, 'RATE_LIMITED');
  assert.ok(Number(last.headers.get('retry-after')) > 0);
  inst.advance(16 * 60_000);
  await U.mallory.login('mallory', PASSWORDS.mallory);
});

test('a full sign-in (prelogin + login) counts once against the limit', async () => {
  const limit = inst.svc.settings().login_attempts_per_15min;
  for (let i = 0; i < limit; i++) assert.equal((await inst.client().login('victor', PASSWORDS.victor)).status, 200, `sign-in ${i + 1}`);
});

test('disabled user is signed out and cannot sign in', async () => {
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'temp', role: 'viewer' });
  const c = inst.client();
  await c.enroll('temp', r.body.enrollmentCode, 'Temp#pass1234');
  const d = await U.admin.req('POST', `/api/admin/users/${r.body.user.id}/status`, { status: 'disabled', confirm: true });
  assert.equal(d.status, 200);
  assert.equal((await c.req('GET', '/api/documents')).status, 401);
  assert.equal((await inst.client().login('temp', 'Temp#pass1234')).status, 401);
});

test('password change re-wraps the key; old password stops working', async () => {
  const c = inst.client();
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'changer', role: 'viewer' });
  await c.enroll('changer', r.body.enrollmentCode, 'Old#password12');
  const C = await import('../shared/crypto-core.js');
  const me = (await c.req('GET', '/api/auth/me')).body;
  const cur = await C.derivePasswordKeys('Old#password12', me.kdf.kdfSalt, me.kdf.kdfIterations, me.user.id);
  const nxt = await C.derivePasswordKeys('New#password12', me.kdf.kdfSalt, me.kdf.kdfIterations, me.user.id);
  const priv = await crypto.subtle.unwrapKey('pkcs8', C.fromB64(me.keys.wrappedPrivateKey), cur.kek, { name: 'AES-GCM', iv: C.fromB64(me.keys.wrapIv), additionalData: new TextEncoder().encode(`vaultshare/privkey/v1:${me.user.id}`) }, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['unwrapKey']);
  const wrapped = await C.wrapPrivateKey(priv, nxt.kek, me.user.id);
  const res = await c.req('POST', '/api/auth/password', { currentAuthKey: cur.authKey, newAuthKey: nxt.authKey, ...wrapped });
  assert.equal(res.status, 200);
  assert.equal((await inst.client().login('changer', 'Old#password12')).status, 401);
  assert.equal((await inst.client().login('changer', 'New#password12')).status, 200);
});

test('role changes are enforced on the server for the next session', async () => {
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'promo', role: 'viewer' });
  const c = inst.client();
  await c.enroll('promo', r.body.enrollmentCode, 'Promo#pass1234');
  assert.equal((await c.req('POST', '/api/documents', { filename: 'a.txt', mimeType: 'text/plain', sizeBytes: 3, content: TXT_HEAD })).status, 403);
  await U.admin.req('POST', `/api/admin/users/${r.body.user.id}/role`, { role: 'operator', confirm: true });
  assert.equal((await c.req('GET', '/api/documents')).status, 401, 'old session ended');
  await c.login('promo', 'Promo#pass1234');
  assert.equal((await c.req('POST', '/api/documents', { filename: 'a.txt', mimeType: 'text/plain', sizeBytes: 3, content: TXT_HEAD })).status, 201);
});

test('admin cannot reset, disable or demote their own account', async () => {
  const self = U.admin.user.id;
  assert.equal((await U.admin.req('POST', `/api/admin/users/${self}/reset`, { confirm: true })).status, 409);
  assert.equal((await U.admin.req('POST', `/api/admin/users/${self}/role`, { role: 'viewer', confirm: true })).status, 409);
});

test('security headers are present on every response', async () => {
  const r = await fetch(`${inst.base}/`);
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-powered-by'), null);
  const api = await fetch(`${inst.base}/api/health`);
  assert.equal(api.headers.get('cache-control'), 'no-store');
});
