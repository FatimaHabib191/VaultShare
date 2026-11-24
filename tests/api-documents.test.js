// FR-2..FR-6 integration: encryption, wrapping, expiry/revocation, watermark, audit.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startInstance, PASSWORDS } from '../scripts/lib/harness.js';
import * as C from '../shared/crypto-core.js';
import * as WM from '../shared/watermark-codec.js';
const TXT_HEAD = { headHex: '68656c6c6f', utf8: true, hasNul: false };
const PDF_HEAD = { headHex: '255044462d312e37', utf8: false, hasNul: false };
const PNG_HEAD = { headHex: '89504e470d0a1a0a', utf8: false, hasNul: true };


const SECRET = 'TOP-SECRET-MARKER: launch codes are 0000';
let inst, U, docId;
const td = (b) => new TextDecoder().decode(b);

before(async () => {
  inst = await startInstance();
  U = await inst.standardUsers();
  const up = await U.alice.upload('briefing.txt', 'text/plain', SECRET);
  assert.equal(up.status, 200);
  docId = up.docId;
});
after(() => inst.destroy());

// ---------------- T1 confidentiality
test('T1: plaintext never reaches the server or database', () => {
  const raw = Buffer.from(inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(docId).content);
  assert.ok(!raw.includes(Buffer.from('TOP-SECRET')));
  const everything = JSON.stringify(inst.svc.db.prepare('SELECT * FROM audit_events').all()) + JSON.stringify(inst.svc.db.prepare('SELECT * FROM decisions').all());
  assert.ok(!everything.includes('TOP-SECRET'));
});

test('T1: owner can decrypt; recipient can decrypt after share', async () => {
  const own = await U.alice.download(docId);
  assert.equal(td(own.plaintext), SECRET);
  const s = await U.alice.share(docId, 'bob', { minutes: 60, maxDownloads: 5 });
  assert.equal(s.status, 201);
  assert.equal(s.body.decision.rule, 'ALLOW_SHARE');
  const got = await U.bob.download(docId);
  assert.equal(got.status, 200);
  assert.equal(td(got.plaintext), SECRET);
  assert.equal(got.body.decision.rule, 'ALLOW_GRANT');
});

test("T1: one recipient's wrapped key is useless to another user", async () => {
  const bobsWrapped = inst.svc.repos.grants.latestFor(docId, U.bob.user.id).wrapped_key;
  await assert.rejects(C.unwrapDek(bobsWrapped, U.mallory.privateKey), /DEK_UNWRAP_FAILED/);
});

// ---------------- T2 altered ciphertext
test('T2: altered ciphertext in storage is rejected by the GCM tag on download', async () => {
  const up = await U.alice.upload('tamper.txt', 'text/plain', 'do not alter me');
  const row = inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(up.docId);
  const buf = Buffer.from(row.content);
  buf[buf.length - 5] ^= 0x01;
  inst.svc.db.prepare('UPDATE documents SET content = ? WHERE id = ?').run(buf, up.docId);
  const r = await U.alice.download(up.docId);
  assert.equal(r.status, 200);
  assert.equal(r.error, 'INTEGRITY_CHECK_FAILED');
  assert.equal(r.plaintext, undefined);
  // the browser reports it, so the failure is recorded server-side
  assert.equal(r.report.status, 201);
  assert.equal(r.report.body.decision.severity, 'high');
  assert.ok(inst.svc.repos.audit.query({ action: 'DOWNLOAD_INTEGRITY_FAILURE', limit: 1 })[0]);
});

test('T2: integrity reports are accepted only for your own download', async () => {
  const r = await U.mallory.req('POST', `/api/documents/${docId}/integrity-failure`, { downloadId: '0b5e3a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c', check: 'INTEGRITY_CHECK_FAILED' });
  assert.equal(r.status, 404);
});

test('T2: altered ciphertext in transit is rejected', async () => {
  const r = await U.bob.download(docId, { tamper: (ct) => ((ct[30] ^= 0xff), ct) });
  assert.equal(r.error, 'INTEGRITY_CHECK_FAILED');
});

test('T2: malformed or length-mismatched uploads are rejected by the server', async () => {
  const init = await U.alice.req('POST', '/api/documents', { filename: 'x.txt', mimeType: 'text/plain', sizeBytes: 10, content: TXT_HEAD });
  const wrappedKey = C.toB64(new Uint8Array(256));
  let r = await U.alice.req('PUT', `/api/documents/${init.body.id}/content`, { ciphertext: C.toB64(new Uint8Array(44)), wrappedKey });
  assert.equal(r.body.error.decision.rule, 'CIPHERTEXT_MALFORMED');
  const fake = new Uint8Array(10 + C.CONTAINER_OVERHEAD_BYTES + 1);
  fake.set([0x56, 0x53, 0x48, 0x31, 1, 12]);
  r = await U.alice.req('PUT', `/api/documents/${init.body.id}/content`, { ciphertext: C.toB64(fake), wrappedKey });
  assert.equal(r.body.error.decision.rule, 'CIPHERTEXT_LENGTH_MISMATCH');
});

// ---------------- T3 access control
test('T3: user with no grant gets a generic 404 and the attempt is logged', async () => {
  const r = await U.mallory.req('POST', `/api/documents/${docId}/download`);
  assert.equal(r.status, 404);
  assert.equal(r.body.error.code, 'NOT_FOUND');
  assert.ok(!JSON.stringify(r.body).includes('briefing'));
  const ev = inst.svc.repos.audit.query({ action: 'DOWNLOAD_DENY', actor: 'mallory', limit: 1 })[0];
  assert.equal(ev.details.rule, 'NO_GRANT');
  const meta = await U.mallory.req('GET', `/api/documents/${docId}`);
  assert.equal(meta.status, 404);
});

test('T3: non-existent and malformed document ids are indistinguishable', async () => {
  const a = await U.mallory.req('POST', `/api/documents/${'0'.repeat(8)}-0000-4000-8000-${'0'.repeat(12)}/download`);
  const b = await U.mallory.req('POST', '/api/documents/not-a-uuid/download');
  assert.equal(a.status, 404);
  assert.equal(b.status, 404);
});

test('T3: role matrix is enforced by the server', async () => {
  const expectations = [
    [U.victor, 'POST', '/api/documents', { filename: 'a.txt', mimeType: 'text/plain', sizeBytes: 1, content: TXT_HEAD }, 403],
    [U.victor, 'GET', '/api/directory', undefined, 403],
    [U.victor, 'GET', '/api/admin/audit', undefined, 403],
    [U.bob, 'GET', '/api/admin/users', undefined, 403],
    [U.bob, 'PUT', '/api/admin/settings', { changes: { max_file_size_mb: 1 }, reason: 'hack', confirm: true }, 403],
    [U.admin, 'POST', `/api/documents/${docId}/download`, undefined, 403],
    [U.admin, 'POST', '/api/documents', { filename: 'a.txt', mimeType: 'text/plain', sizeBytes: 1, content: TXT_HEAD }, 403],
    [U.admin, 'GET', '/api/admin/audit', undefined, 200],
    [U.bob, 'GET', '/api/documents', undefined, 200],
  ];
  for (const [c, m, p, b, want] of expectations) {
    const r = await c.req(m, p, b);
    assert.equal(r.status, want, `${c.user.username} ${m} ${p}`);
  }
});

test('T3: only the owner can share, and nobody can share to an admin', async () => {
  const notOwner = await U.bob.share(docId, 'victor');
  assert.equal(notOwner.status, 404);
  const dir = await U.alice.directory();
  assert.ok(!dir.some((u) => u.role === 'admin'), 'admins are not offered as recipients');
});

test('upload policy endpoint reports the live limits to operators and viewers only', async () => {
  const r = await U.victor.req('GET', '/api/documents/policy');
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.allowedExtensions, inst.svc.settings().allowed_extensions);
  assert.equal(r.body.maxFileSizeMb, inst.svc.settings().max_file_size_mb);
  assert.equal((await U.admin.req('GET', '/api/documents/policy')).status, 403);
});

test('T3: unauthenticated requests are refused', async () => {
  const r = await inst.client().req('GET', '/api/documents');
  assert.equal(r.status, 401);
});

// ---------------- T4 expiry & revocation
test('T4: grant works until expiry, then is denied with GRANT_EXPIRED', async () => {
  const s = await U.alice.share(docId, 'victor', { minutes: 1, maxDownloads: 5 });
  assert.equal(s.status, 201);
  assert.equal((await U.victor.download(docId)).status, 200);
  inst.advance(61_000);
  await U.victor.login('victor', PASSWORDS.victor); // session idle window is longer; refresh anyway
  const r = await U.victor.req('POST', `/api/documents/${docId}/download`);
  assert.equal(r.status, 403);
  assert.equal(r.body.error.decision.rule, 'GRANT_EXPIRED');
  assert.ok(r.body.error.decision.evidence.expiresAt);
});

test('T4: revocation takes effect immediately and destroys the wrapped key', async () => {
  const s = await U.alice.share(docId, 'victor', { minutes: 60, maxDownloads: 5 });
  const grantId = s.body.grantId;
  assert.equal((await U.victor.download(docId)).status, 200);
  const rev = await U.alice.req('POST', `/api/grants/${grantId}/revoke`, { confirm: true, reason: 'test' });
  assert.equal(rev.status, 200);
  const r = await U.victor.req('POST', `/api/documents/${docId}/download`);
  assert.equal(r.body.error.decision.rule, 'GRANT_REVOKED');
  assert.equal(inst.svc.repos.grants.byId(grantId).wrapped_key, null);
  const again = await U.alice.req('POST', `/api/grants/${grantId}/revoke`, { confirm: true });
  assert.equal(again.status, 409);
});

test('T4: revoke requires explicit confirmation', async () => {
  const s = await U.alice.share(docId, 'victor', { minutes: 60, maxDownloads: 2 });
  const r = await U.alice.req('POST', `/api/grants/${s.body.grantId}/revoke`, {});
  assert.equal(r.status, 400);
  await U.alice.req('POST', `/api/grants/${s.body.grantId}/revoke`, { confirm: true });
});

test('T4: download limit is enforced', async () => {
  const s = await U.alice.share(docId, 'victor', { minutes: 60, maxDownloads: 2 });
  assert.equal(s.status, 201);
  assert.equal((await U.victor.download(docId)).status, 200);
  assert.equal((await U.victor.download(docId)).status, 200);
  const r = await U.victor.req('POST', `/api/documents/${docId}/download`);
  assert.equal(r.body.error.decision.rule, 'DOWNLOAD_LIMIT_REACHED');
});

test('T4: concurrent downloads cannot exceed the limit', async () => {
  const up = await U.alice.upload('race.txt', 'text/plain', 'race');
  await U.alice.share(up.docId, 'bob', { minutes: 60, maxDownloads: 1 });
  const results = await Promise.all(Array.from({ length: 5 }, () => U.bob.req('POST', `/api/documents/${up.docId}/download`)));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
});

test('T4: share expiry beyond the configured maximum is denied with evidence', async () => {
  const max = inst.svc.settings().max_grant_ttl_hours * 60;
  const up = await U.alice.upload('ttl.txt', 'text/plain', 'ttl');
  const r = await U.alice.share(up.docId, 'bob', { minutes: max + 1 });
  assert.equal(r.status, 403);
  assert.equal(r.body.error.decision.rule, 'GRANT_TTL_OUT_OF_RANGE');
  assert.equal(r.body.error.decision.evidence.maxMinutes, max);
});

test('repeated submission: duplicate active grant and duplicate upload are rejected', async () => {
  const up = await U.alice.upload('dup.txt', 'text/plain', 'dup');
  assert.equal((await U.alice.share(up.docId, 'bob')).status, 201);
  const dup = await U.alice.share(up.docId, 'bob');
  assert.equal(dup.status, 409);
  assert.equal(dup.body.error.decision.rule, 'DUPLICATE_ACTIVE_GRANT');
  const again = await U.alice.req('PUT', `/api/documents/${up.docId}/content`, { ciphertext: C.toB64(up.container), wrappedKey: C.toB64(new Uint8Array(256)) });
  assert.equal(again.status, 409);
  assert.equal(again.body.error.decision.rule, 'ALREADY_UPLOADED');
});

// ---------------- T5 key loss
test('T5: after a key reset, old grants fail with KEY_MISMATCH and owner data is unrecoverable', async () => {
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'kim', role: 'operator' });
  const kim = inst.client();
  await kim.enroll('kim', r.body.enrollmentCode, 'Kim#password12');
  const own = await kim.upload('kims-notes.txt', 'text/plain', 'only kim');
  const shared = await U.alice.upload('for-kim.txt', 'text/plain', 'for kim');
  await U.alice.share(shared.docId, 'kim', { minutes: 120, maxDownloads: 5 });
  assert.equal((await kim.download(shared.docId)).status, 200);

  // kim forgets the password: admin issues a new key
  const reset = await U.admin.req('POST', `/api/admin/users/${r.body.user.id}/reset`, { confirm: true });
  assert.equal(reset.status, 200);
  assert.equal((await kim.req('GET', '/api/documents')).status, 401, 'old sessions ended');
  const kim2 = inst.client();
  assert.equal((await kim2.enroll('kim', reset.body.enrollmentCode, 'Kim#newpass123')).status, 201);
  assert.equal(kim2.user.keyVersion, 2);

  const denied = await kim2.req('POST', `/api/documents/${shared.docId}/download`);
  assert.equal(denied.body.error.decision.rule, 'KEY_MISMATCH');
  const ownDenied = await kim2.req('POST', `/api/documents/${own.docId}/download`);
  assert.equal(ownDenied.body.error.decision.rule, 'KEY_MISMATCH');

  // owner can re-share to the new key after revoking the stale grant
  const g = inst.svc.repos.grants.latestFor(shared.docId, kim2.user.id);
  await U.alice.req('POST', `/api/grants/${g.id}/revoke`, { confirm: true });
  assert.equal((await U.alice.share(shared.docId, 'kim')).status, 201);
  assert.equal(td((await kim2.download(shared.docId)).plaintext), 'for kim');
});

test('T5: sharing to a stale fingerprint is refused', async () => {
  const up = await U.alice.upload('fp.txt', 'text/plain', 'fp');
  const r = await U.alice.share(up.docId, 'bob', { fingerprintOverride: 'a'.repeat(64) });
  assert.equal(r.body.error.decision.rule, 'RECIPIENT_KEY_CHANGED');
});

// ---------------- FR-5 watermark
test('FR-5: each download gets a unique signed watermark that traces to the recipient', async () => {
  const a = await U.bob.download(docId);
  const b = await U.bob.download(docId);
  assert.notEqual(a.body.watermark.payload, b.body.watermark.payload);
  const marked = WM.embedText(td(a.plaintext), a.body.watermark.payload, a.body.watermark.label);
  const found = WM.extractFromText(marked.split('\n').slice(1).join('\n') + marked.split('\n')[0]);
  assert.deepEqual(found, [a.body.watermark.payload]);
  const t = await U.admin.req('POST', '/api/admin/trace', { payload: found[0] });
  assert.equal(t.body.valid, true);
  assert.equal(t.body.evidence.recipient, 'bob');
  assert.equal(t.body.evidence.document, 'briefing.txt');
  const forged = await U.admin.req('POST', '/api/admin/trace', { payload: a.body.watermark.payload.slice(0, -4) + 'AAAA' });
  assert.equal(forged.body.rule, 'WATERMARK_FORGED');
});

// ---------------- uploads & config traceability
test('upload rejects disallowed type, MIME mismatch and oversize with explainable rules', async () => {
  const cases = [
    [{ filename: 'run.exe', mimeType: 'application/octet-stream', sizeBytes: 10 }, 'TYPE_NOT_ALLOWED', 415],
    [{ filename: 'x.pdf', mimeType: 'text/plain', sizeBytes: 10 }, 'TYPE_NOT_ALLOWED', 415],
    [{ filename: 'invoice.exe.pdf', mimeType: 'application/pdf', sizeBytes: 10 }, 'TYPE_NOT_ALLOWED', 415],
    [{ filename: 'big.txt', mimeType: 'text/plain', sizeBytes: 50 * 1024 * 1024 }, 'FILE_TOO_LARGE', 413],
    [{ filename: 'empty.txt', mimeType: 'text/plain', sizeBytes: 0 }, 'FILE_EMPTY', 400],
    // seeded adverse samples: contents do not match the name
    [{ filename: 'not-really.pdf', mimeType: 'application/pdf', sizeBytes: 43, content: TXT_HEAD }, 'CONTENT_TYPE_MISMATCH', 415],
    [{ filename: 'photo.png', mimeType: 'image/png', sizeBytes: 25, content: { headHex: '4d5a90000300', utf8: false, hasNul: true } }, 'CONTENT_TYPE_MISMATCH', 415],
    [{ filename: 'notes.txt', mimeType: 'text/plain', sizeBytes: 9, content: { headHex: '0001ff', utf8: false, hasNul: true } }, 'CONTENT_TYPE_MISMATCH', 415],
  ];
  for (const [b, rule, status] of cases) {
    const body = { content: b.filename.endsWith('.pdf') ? PDF_HEAD : TXT_HEAD, ...b };
    const r = await U.alice.req('POST', '/api/documents', body);
    assert.equal(r.status, status, body.filename);
    assert.equal(r.body.error.decision.rule, rule);
    assert.ok(r.body.error.decision.recommendedAction, 'every decision carries a recommended action');
    assert.ok(['info', 'low', 'medium', 'high'].includes(r.body.error.decision.severity));
  }
  // the rejected adverse sample is stored in history and the audit trail
  const hist = await U.alice.req('GET', '/api/decisions?rule=CONTENT_TYPE_MISMATCH');
  assert.equal(hist.body.decisions.length, 3);
  assert.equal(hist.body.decisions.at(-1).severity, 'high');
  assert.match(hist.body.decisions.at(-1).reason, /named \.pdf but its contents are plain text/);
  const ev = inst.svc.repos.audit.query({ action: 'DOC_UPLOAD_REJECTED', limit: 5 }).find((e) => e.details.rule === 'CONTENT_TYPE_MISMATCH');
  assert.ok(ev && ev.details.detected);
});

test('admin rule change is versioned, audited and recorded on later decisions', async () => {
  inst.advance(61_000); // new per-minute rate-limit window
  const before = await U.alice.req('POST', '/api/documents', { filename: 'pic.png', mimeType: 'image/png', sizeBytes: 100, content: PNG_HEAD });
  assert.equal(before.status, 201);
  const v0 = before.body.decision.configVersion;
  const change = await U.admin.req('PUT', '/api/admin/settings', { changes: { allowed_extensions: ['txt', 'md', 'csv', 'pdf'] }, reason: 'images paused for review', confirm: true });
  assert.equal(change.status, 200);
  const after = await U.alice.req('POST', '/api/documents', { filename: 'pic.png', mimeType: 'image/png', sizeBytes: 100, content: PNG_HEAD });
  assert.equal(after.body.error.decision.rule, 'TYPE_NOT_ALLOWED');
  assert.equal(after.body.error.decision.configVersion, v0 + 1);
  const ev = inst.svc.repos.audit.query({ action: 'CONFIG_CHANGE', limit: 1 })[0];
  assert.deepEqual(ev.details.diff.allowed_extensions.to, ['txt', 'md', 'csv', 'pdf']);
  assert.equal(ev.details.reason, 'images paused for review');
  const bad = await U.admin.req('PUT', '/api/admin/settings', { changes: { max_file_size_mb: 9999 }, reason: 'too big', confirm: true });
  assert.equal(bad.status, 400);
  await U.admin.req('PUT', '/api/admin/settings', { changes: { allowed_extensions: ['txt', 'md', 'csv', 'pdf', 'png', 'jpg', 'jpeg'] }, reason: 'restore', confirm: true });
});

// ---------------- T-final
test('T-final: malformed JSON and oversized bodies get safe errors without stack traces', async () => {
  const bad = await U.alice.req('POST', '/api/documents', '{"filename": ', { raw: true, headers: { 'content-type': 'application/json' } });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'MALFORMED_JSON');
  const huge = await U.alice.req('POST', '/api/documents', JSON.stringify({ filename: 'x'.repeat(40 * 1024 * 1024) }), { raw: true, headers: { 'content-type': 'application/json' } });
  assert.equal(huge.status, 413);
  for (const r of [bad, huge]) assert.ok(!/at .*\.js:\d+/.test(JSON.stringify(r.body)), 'no stack trace');
});

test('T-final: SQL-injection style input is treated as data', async () => {
  const r = await U.admin.req('GET', `/api/admin/audit?actor=${encodeURIComponent("x' OR 1=1 --")}`);
  assert.equal(r.status, 200);
  const r2 = await inst.client().req('POST', '/api/auth/prelogin', { username: "admin'--" });
  assert.equal(r2.status, 400);
  const u = await U.admin.req('POST', '/api/admin/users', { username: "a'; DROP TABLE users;--", role: 'viewer' });
  assert.equal(u.status, 400);
  assert.ok(inst.svc.repos.users.count() > 0);
});

test('T-final: CSV export neutralises spreadsheet formulas', async () => {
  await U.alice.req('POST', '/api/documents', { filename: '=cmd.txt', mimeType: 'text/plain', sizeBytes: 5, content: TXT_HEAD });
  const r = await U.alice.req('GET', '/api/reports/export?format=csv');
  assert.equal(r.status, 200);
  assert.ok(!/(^|,)=cmd/m.test(r.body));
});

test('T-final: exported report is sanitised', async () => {
  const r = await U.admin.req('GET', '/api/reports/export?scope=all');
  const s = JSON.stringify(r.body);
  assert.ok(r.body.auditVerification.ok, JSON.stringify(r.body.auditVerification));
  for (const secret of ['TOP-SECRET', 'wrappedKey":"', 'auth_hash', PASSWORDS.alice]) assert.ok(!s.includes(secret), secret);
});

test('T-final: state, sessions and audit chain survive a restart', async () => {
  await inst.restart();
  const chain = inst.svc.audit.verify();
  assert.equal(chain.ok, true, JSON.stringify(chain));
  const bob = inst.client();
  await bob.login('bob', PASSWORDS.bob);
  const r = await bob.download(docId);
  assert.equal(td(r.plaintext), SECRET);
  const start = inst.svc.repos.audit.query({ action: 'SYSTEM_START', limit: 1 })[0];
  assert.equal(start.details.auditChain, 'CHAIN_INTACT');
});

test('FR-6: audit trail covers the security-relevant actions and verifies', async () => {
  await inst.client().login('bob', 'Definitely#wrong1');
  const actions = new Set(inst.svc.repos.audit.actions());
  for (const a of ['AUTH_LOGIN_SUCCESS', 'AUTH_LOGIN_FAILURE', 'USER_CREATE', 'USER_RESET', 'CONFIG_CHANGE', 'DOC_UPLOAD', 'DOC_UPLOAD_REJECTED', 'GRANT_CREATE', 'GRANT_REVOKE', 'GRANT_DENIED', 'DOWNLOAD_ALLOW', 'DOWNLOAD_DENY', 'REPORT_EXPORT', 'WATERMARK_TRACE', 'REQUEST_REJECTED', 'SYSTEM_START']) {
    assert.ok(actions.has(a), `missing ${a}`);
  }
  const admin = inst.client(); // the restart moved the instance to a new port
  await admin.login('admin', PASSWORDS.admin);
  const res = await admin.req('POST', '/api/admin/audit/verify');
  assert.equal(res.body.ok, true);
});
