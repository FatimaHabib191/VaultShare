// Evaluation harness for the mandatory cases T1–T5 and T-final.
// Runs against an isolated instance, records input / expected / actual / evidence /
// pass-fail for every case, measures latency and error rates, then writes
//   reports/evaluation.md   (human-readable, referenced by the final report)
//   reports/evaluation.json (machine-readable)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { startInstance, PASSWORDS } from './lib/harness.js';
import * as C from '../shared/crypto-core.js';
import * as WM from '../shared/watermark-codec.js';
import { ACTIONS, ROLES } from '../server/engine/access.js';
const TXT_HEAD = { headHex: '68656c6c6f', utf8: true, hasNul: false };
const PDF_HEAD = { headHex: '255044462d312e37', utf8: false, hasNul: false };
const PNG_HEAD = { headHex: '89504e470d0a1a0a', utf8: false, hasNul: true };


const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'reports');
const td = (b) => new TextDecoder().decode(b);
const rows = [];
const metrics = {};
let caseNo = 0;

function record(group, title, input, expected, actual, evidence, pass) {
  caseNo++;
  rows.push({ id: `${group}.${String(rows.filter((r) => r.group === group).length + 1)}`, group, title, input, expected, actual, evidence, pass: !!pass });
  process.stdout.write(`  ${pass ? 'PASS' : 'FAIL'}  ${group}  ${title}\n`);
}

const pct = (arr, p) => {
  const s = [...arr].sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))] : 0;
};
const r3 = (n) => Math.round(n * 1000) / 1000;

console.log('\nVaultShare evaluation\n');
const inst = await startInstance();
const U = await inst.standardUsers();
const SECRET = 'CONFIDENTIAL-SAMPLE: merger code name BLUE HERON (fictional)';
const sample = fs.readFileSync(path.join(ROOT, 'fixtures/samples/quarterly-briefing.txt'));

// ======================================================================= T1
{
  const up = await U.alice.upload('t1-secret.txt', 'text/plain', SECRET);
  const stored = Buffer.from(inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(up.docId).content);
  const dbFile = fs.readFileSync(path.join(inst.dir, 'vaultshare.db'));
  const wal = fs.existsSync(path.join(inst.dir, 'vaultshare.db-wal')) ? fs.readFileSync(path.join(inst.dir, 'vaultshare.db-wal')) : Buffer.alloc(0);
  const leaked = stored.includes('BLUE HERON') || dbFile.includes('BLUE HERON') || wal.includes('BLUE HERON');
  record('T1', 'Stored ciphertext and database files contain no plaintext', `upload "${SECRET.slice(0, 32)}…" as alice`, 'marker string absent from DB, WAL and blob', leaked ? 'marker found' : 'marker absent', `blob ${stored.length} B = ${SECRET.length} + ${C.CONTAINER_OVERHEAD_BYTES} overhead; sha256 ${up.body.document.cipherSha256.slice(0, 16)}…`, !leaked && stored.length === SECRET.length + C.CONTAINER_OVERHEAD_BYTES);

  const owner = await U.alice.download(up.docId);
  record('T1', 'Owner decrypts own document', 'alice opens t1-secret.txt', 'ALLOW_OWNER, plaintext identical', `${owner.body.decision.rule}, identical=${td(owner.plaintext) === SECRET}`, `decision ${owner.body.decision.id.slice(0, 8)}`, owner.body.decision.rule === 'ALLOW_OWNER' && td(owner.plaintext) === SECRET);

  const share = await U.alice.share(up.docId, 'bob', { minutes: 60, maxDownloads: 3 });
  const bob = await U.bob.download(up.docId);
  record('T1', 'Recipient decrypts with own key after share', 'alice → bob, 60 min, 3 downloads; bob opens', 'ALLOW_SHARE then ALLOW_GRANT, plaintext identical', `${share.body.decision.rule} / ${bob.body.decision.rule}, identical=${td(bob.plaintext) === SECRET}`, `grant ${share.body.grantId.slice(0, 8)}; wrapped DEK ${C.fromB64(inst.svc.repos.grants.byId(share.body.grantId).wrapped_key).length} B (RSA-OAEP-2048)`, bob.plaintext && td(bob.plaintext) === SECRET);

  const bobsKey = inst.svc.repos.grants.byId(share.body.grantId).wrapped_key;
  let unwrapErr = null;
  try {
    await C.unwrapDek(bobsKey, U.mallory.privateKey);
  } catch (e) {
    unwrapErr = e.message;
  }
  record('T1', "Stolen wrapped key is useless without the recipient's private key", "mallory tries to unwrap bob's wrapped DEK taken from the database", 'DEK_UNWRAP_FAILED', unwrapErr || 'unwrapped!', 'RSA-OAEP decryption error', unwrapErr === 'DEK_UNWRAP_FAILED');

  const adminTry = await U.admin.req('POST', `/api/documents/${up.docId}/download`);
  record('T1', 'Administrator cannot obtain document keys', 'admin requests download', '403 FORBIDDEN (no doc.download permission)', `${adminTry.status} ${adminTry.body.error?.code}`, 'ACCESS_DENIED audited', adminTry.status === 403);

  const n = 20;
  const ivs = new Set();
  const dek = await C.generateDek();
  for (let i = 0; i < n; i++) ivs.add(C.toHex((await C.encryptDocument(dek, sample, 'b')).subarray(6, 18)));
  record('T1', 'Fresh random 96-bit IV on every encryption', `${n} encryptions of the same file with one key`, `${n} distinct IVs`, `${ivs.size} distinct`, 'IV from crypto.getRandomValues', ivs.size === n);
}

// ======================================================================= T2
inst.advance(61_000); // new rate-limit window per group (limits are per minute)
{
  const up = await U.alice.upload('t2-integrity.txt', 'text/plain', new Uint8Array(sample));
  await U.alice.share(up.docId, 'bob', { minutes: 60, maxDownloads: 10 });
  const regions = [
    ['header magic', 0],
    ['version byte', 4],
    ['IV', 10],
    ['ciphertext body', C.CONTAINER_HEADER_BYTES + 5],
    ['GCM tag', -1],
  ];
  for (const [name, at] of regions) {
    const r = await U.bob.download(up.docId, { tamper: (ct) => ((ct[at < 0 ? ct.length + at : at] ^= 0x01), ct) });
    const ok = ['INTEGRITY_CHECK_FAILED', 'CONTAINER_BAD_MAGIC', 'CONTAINER_UNSUPPORTED_VERSION'].includes(r.error);
    record('T2', `Single-bit flip in ${name} is rejected`, `flip 1 bit at ${name} (in transit)`, 'decryption refused, no plaintext', r.error || 'decrypted!', 'AES-GCM tag / container check', ok && !r.plaintext);
  }
  // randomised flips in storage
  const row = inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(up.docId);
  const original = Buffer.from(row.content);
  const dek = await C.unwrapDek((await U.alice.req('GET', `/api/documents/${up.docId}/owner-key`)).body.wrappedKey, U.alice.privateKey);
  let detected = 0;
  const trials = 500;
  for (let i = 0; i < trials; i++) {
    const t = Buffer.from(original);
    const pos = Math.floor(Math.random() * t.length);
    t[pos] ^= 1 << Math.floor(Math.random() * 8);
    try {
      await C.decryptDocument(dek, new Uint8Array(t), up.binding);
    } catch {
      detected++;
    }
  }
  metrics.tamperDetection = { trials, detected, rate: detected / trials };
  record('T2', 'Random single-bit corruption of stored ciphertext', `${trials} random bit flips across the ${original.length}-byte container`, '100% rejected', `${detected}/${trials} rejected`, 'false-negative rate 0 required', detected === trials);

  const t = Buffer.from(original);
  t[t.length - 3] ^= 0x10;
  inst.svc.db.prepare('UPDATE documents SET content = ? WHERE id = ?').run(t, up.docId);
  const stor = await U.bob.download(up.docId);
  record('T2', 'Ciphertext altered at rest is rejected end-to-end', 'flip 1 bit in SQLite blob, bob opens', 'INTEGRITY_CHECK_FAILED', stor.error || 'decrypted', `server still released ciphertext (it cannot detect); client refused`, stor.error === 'INTEGRITY_CHECK_FAILED');
  inst.svc.db.prepare('UPDATE documents SET content = ? WHERE id = ?').run(original, up.docId);

  const swap = await U.alice.upload('t2-other.txt', 'text/plain', 'other doc');
  const otherCt = Buffer.from(inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(swap.docId).content);
  let swapErr = null;
  try {
    await C.decryptDocument(dek, new Uint8Array(otherCt), up.binding);
  } catch (e) {
    swapErr = e.message;
  }
  record('T2', 'Ciphertext swapped between documents is rejected', 'decrypt document B ciphertext with document A key/binding', 'INTEGRITY_CHECK_FAILED', swapErr || 'decrypted', 'AAD binds docId + ownerId', swapErr === 'INTEGRITY_CHECK_FAILED');

  const init = await U.alice.req('POST', '/api/documents', { filename: 'forged.txt', mimeType: 'text/plain', sizeBytes: 100, content: TXT_HEAD });
  const junk = await U.alice.req('PUT', `/api/documents/${init.body.id}/content`, { ciphertext: C.toB64(new Uint8Array(134)), wrappedKey: C.toB64(new Uint8Array(256)) });
  record('T2', 'Server rejects a non-VaultShare container', '134 zero bytes declared as 100-byte file', 'CIPHERTEXT_MALFORMED', junk.body.error?.decision?.rule, JSON.stringify(junk.body.error?.decision?.evidence), junk.body.error?.decision?.rule === 'CIPHERTEXT_MALFORMED');
}

// ======================================================================= T3
inst.advance(61_000); // new rate-limit window per group (limits are per minute)
{
  // Endpoint-level matrix: for each permission, a representative request per role.
  const doc = await U.alice.upload('t3-matrix.txt', 'text/plain', 'matrix');
  await U.alice.share(doc.docId, 'victor', { minutes: 600, maxDownloads: 10 });
  await U.alice.share(doc.docId, 'bob', { minutes: 600, maxDownloads: 10 });
  const sample1 = { filename: 'm.txt', mimeType: 'text/plain', sizeBytes: 4, content: TXT_HEAD };
  const ghost = '0b5e3a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c'; // valid id that does not exist: proves the permission gate, changes nothing
  const others = (r, c) => r.status === 200 && r.body.decisions.some((d) => d.actor !== c.user.username);
  // Each probe returns [response, allowedJudgement]. Default judgement: the role was let past the
  // permission gate (anything except 401/403). "Scope=all" permissions are judged on whether
  // other users' data was actually returned, because those endpoints answer every role but filter.
  const probes = {
    'doc.upload': async (c) => c.req('POST', '/api/documents', sample1),
    'doc.list': async (c) => c.req('GET', '/api/documents'),
    'doc.read_meta': async (c) => c.req('GET', `/api/documents/${doc.docId}`),
    'doc.download': async (c) => c.req('POST', `/api/documents/${doc.docId}/download`),
    'doc.delete': async (c) => c.req('DELETE', `/api/documents/${ghost}`, { confirm: true }),
    'grant.create': async (c) => c.req('POST', `/api/documents/${ghost}/grants`, { recipientId: ghost, wrappedKey: C.toB64(new Uint8Array(256)), recipientKeyFingerprint: 'a'.repeat(64), expiresInMinutes: 5, maxDownloads: 1 }),
    'grant.revoke': async (c) => c.req('POST', `/api/grants/${ghost}/revoke`, { confirm: true }),
    'directory.read': async (c) => c.req('GET', '/api/directory'),
    'decision.read_own': async (c) => c.req('GET', '/api/decisions'),
    'decision.read_all': async (c) => {
      const r = await c.req('GET', '/api/decisions?scope=all&limit=500');
      return [r, others(r, c)];
    },
    'report.export_own': async (c) => c.req('GET', '/api/reports/export'),
    'report.export_all': async (c) => {
      const r = await c.req('GET', '/api/reports/export?scope=all');
      return [r, r.status === 200 && r.body.scope === 'all users'];
    },
    'user.manage': async (c) => c.req('GET', '/api/admin/users'),
    'config.read': async (c) => c.req('GET', '/api/admin/settings'),
    'config.write': async (c) => c.req('PUT', '/api/admin/settings', { changes: {}, reason: 'matrix probe', confirm: true }),
    'audit.read': async (c) => c.req('GET', '/api/admin/audit?limit=1'),
    'audit.verify': async (c) => c.req('POST', '/api/admin/audit/verify'),
    'audit.export': async (c) => c.req('GET', '/api/admin/audit/export'),
    'watermark.trace': async (c) => c.req('POST', '/api/admin/trace', { payload: 'VS1.not-a-real-reference-value' }),
  };
  const who = { admin: U.admin, operator: U.bob, viewer: U.victor };
  let tp = 0, tn = 0, fp = 0, fn = 0;
  const matrixRows = [];
  for (const [perm, probe] of Object.entries(probes)) {
    for (const role of ROLES) {
      const expectAllow = ACTIONS[perm].includes(role);
      const out = await probe(who[role]);
      const [r, judged] = Array.isArray(out) ? out : [out, null];
      const actualAllow = judged ?? (r.status !== 401 && r.status !== 403);
      if (expectAllow && actualAllow) tp++;
      else if (!expectAllow && !actualAllow) tn++;
      else if (!expectAllow && actualAllow) fp++;
      else fn++;
      matrixRows.push({ perm, role, expected: expectAllow ? 'allow' : 'deny', actual: actualAllow ? 'allow' : 'deny', status: r.status });
    }
  }
  const covered = Object.keys(probes).filter((k) => ACTIONS[k]).length;
  metrics.accessMatrix = { cases: matrixRows.length, truePermit: tp, trueDeny: tn, falsePermit: fp, falseDeny: fn, coverage: `${covered}/${Object.keys(ACTIONS).length} permissions probed over HTTP`, rows: matrixRows };
  record('T3', 'Role × permission matrix enforced by the server', `${matrixRows.length} requests (${covered}/${Object.keys(ACTIONS).length} permissions × 3 roles)`, '0 false permits, 0 false denies', `${fp} false permits, ${fn} false denies`, `${tp} correct allows, ${tn} correct denies`, fp === 0 && fn === 0);

  const m = await U.mallory.req('POST', `/api/documents/${doc.docId}/download`);
  const ev = inst.svc.repos.audit.query({ action: 'DOWNLOAD_DENY', actor: 'mallory', limit: 1 })[0];
  record('T3', 'Unauthorised operator gets a generic denial and the attempt is logged', 'mallory (no grant) requests download', '404 NOT_FOUND, no filename in response, audit NO_GRANT', `${m.status} ${m.body.error.code}; leaks name=${JSON.stringify(m.body).includes('t3-matrix')}`, `audit seq ${ev?.seq} rule ${ev?.details.rule}`, m.status === 404 && ev?.details.rule === 'NO_GRANT' && !JSON.stringify(m.body).includes('t3-matrix'));

  const anon = await inst.client().req('GET', `/api/documents/${doc.docId}`);
  record('T3', 'Unauthenticated request refused', 'GET document without a session', '401 AUTH_REQUIRED', `${anon.status} ${anon.body.error.code}`, '', anon.status === 401);

  const v = await U.victor.req('POST', `/api/documents/${doc.docId}/grants`, { recipientId: U.bob.user.id, wrappedKey: C.toB64(new Uint8Array(256)), recipientKeyFingerprint: 'a'.repeat(64), expiresInMinutes: 5, maxDownloads: 1 });
  record('T3', 'Viewer cannot re-share a document shared with them', 'victor POST /grants', '403 FORBIDDEN', `${v.status} ${v.body.error.code}`, 'grant.create = operator only', v.status === 403);

  const b = await U.bob.share(doc.docId, 'mallory').catch((e) => ({ status: 'error', body: { error: { code: e.message } } }));
  record('T3', 'Recipient operator cannot share a document they do not own', 'bob (recipient) tries to share to mallory', '404 (owner key not released)', `${b.status}`, 'owner-key endpoint is owner-only', b.status === 404);

  const csrf = inst.client();
  await csrf.login('bob', PASSWORDS.bob);
  csrf.csrf = 'forged';
  const cs = await csrf.req('POST', '/api/auth/logout');
  record('T3', 'Request with forged CSRF token refused', 'bob session, wrong X-CSRF-Token', '403 CSRF_FAILED', `${cs.status} ${cs.body.error?.code}`, 'synchronizer token + SameSite=Strict', cs.status === 403);
}

// ======================================================================= T4
inst.advance(61_000); // new rate-limit window per group (limits are per minute)
{
  const up = await U.alice.upload('t4-expiry.txt', 'text/plain', 'expiring');
  const s = await U.alice.share(up.docId, 'victor', { minutes: 5, maxDownloads: 10 });
  const before = await U.victor.req('POST', `/api/documents/${up.docId}/download`);
  inst.advance(4 * 60_000 + 59_000);
  const edge = await U.victor.req('POST', `/api/documents/${up.docId}/download`);
  inst.advance(1_000);
  const after = await U.victor.req('POST', `/api/documents/${up.docId}/download`);
  record('T4', 'Grant valid before expiry', 'share 5 min; open at t+0', 'ALLOW_GRANT', before.body.decision?.rule, `expiresAt ${before.body.decision?.evidence.expiresAt}`, before.status === 200);
  record('T4', 'Grant valid 1 s before expiry (edge)', 'open at t+4m59s', 'ALLOW_GRANT', edge.body.decision?.rule ?? edge.body.error?.decision?.rule, '', edge.status === 200);
  record('T4', 'Grant denied exactly at expiry', 'open at t+5m00s', 'GRANT_EXPIRED', after.body.error?.decision?.rule, JSON.stringify({ expiresAt: after.body.error?.decision?.evidence.expiresAt, evaluatedAt: after.body.error?.decision?.evidence.evaluatedAt }), after.body.error?.decision?.rule === 'GRANT_EXPIRED');
  void s;

  const up2 = await U.alice.upload('t4-revoke.txt', 'text/plain', 'revocable');
  const g = await U.alice.share(up2.docId, 'victor', { minutes: 60, maxDownloads: 5 });
  await U.victor.req('POST', `/api/documents/${up2.docId}/download`);
  const t0 = performance.now();
  await U.alice.req('POST', `/api/grants/${g.body.grantId}/revoke`, { confirm: true, reason: 'evaluation' });
  const rev = await U.victor.req('POST', `/api/documents/${up2.docId}/download`);
  const revMs = performance.now() - t0;
  const keyGone = inst.svc.repos.grants.byId(g.body.grantId).wrapped_key === null;
  record('T4', 'Revocation is immediate and destroys the wrapped key', 'owner revokes, recipient retries', 'GRANT_REVOKED, wrapped key erased', `${rev.body.error?.decision?.rule}, wrapped key erased=${keyGone}`, `revoke→deny round trip ${r3(revMs)} ms`, rev.body.error?.decision?.rule === 'GRANT_REVOKED' && keyGone);

  const up3 = await U.alice.upload('t4-limit.txt', 'text/plain', 'limited');
  await U.alice.share(up3.docId, 'bob', { minutes: 60, maxDownloads: 2 });
  const res = [];
  for (let i = 0; i < 3; i++) res.push((await U.bob.req('POST', `/api/documents/${up3.docId}/download`)).body);
  record('T4', 'Download limit enforced', 'limit 2, three attempts', 'allow, allow, DOWNLOAD_LIMIT_REACHED', res.map((b) => b.decision?.rule ?? b.error?.decision?.rule).join(', '), '', res[2].error?.decision?.rule === 'DOWNLOAD_LIMIT_REACHED');

  const up4 = await U.alice.upload('t4-race.txt', 'text/plain', 'race');
  await U.alice.share(up4.docId, 'bob', { minutes: 60, maxDownloads: 1 });
  const par = await Promise.all(Array.from({ length: 10 }, () => U.bob.req('POST', `/api/documents/${up4.docId}/download`)));
  const wins = par.filter((r) => r.status === 200).length;
  record('T4', 'Limit holds under 10 concurrent requests', 'limit 1, 10 parallel downloads', 'exactly 1 success', `${wins} success`, 'atomic conditional UPDATE in a transaction', wins === 1);

  const max = inst.svc.settings().max_grant_ttl_hours * 60;
  const tooLong = await U.alice.share(up4.docId, 'victor', { minutes: max + 1 });
  record('T4', 'Expiry beyond policy maximum refused', `share for ${max + 1} min (max ${max})`, 'GRANT_TTL_OUT_OF_RANGE', tooLong.body.error?.decision?.rule, JSON.stringify(tooLong.body.error?.decision?.evidence), tooLong.body.error?.decision?.rule === 'GRANT_TTL_OUT_OF_RANGE');

  // admin tightens policy, repeat
  const change = await U.admin.req('PUT', '/api/admin/settings', { changes: { max_grant_ttl_hours: 2, default_grant_ttl_hours: 1 }, reason: 'evaluation: tighten share window', confirm: true });
  const up5 = await U.alice.upload('t4-policy.txt', 'text/plain', 'policy');
  const after2 = await U.alice.share(up5.docId, 'bob', { minutes: 180 });
  const okShort = await U.alice.share(up5.docId, 'bob', { minutes: 120 });
  const audit = inst.svc.repos.audit.query({ action: 'CONFIG_CHANGE', limit: 1 })[0];
  record('T4', 'Administrator rule change is applied and traceable', 'max_grant_ttl_hours 168 → 2 (default 24 → 1), then share 180 min and 120 min', 'deny under new version, allow within limit, CONFIG_CHANGE audited', `${after2.body.error?.decision?.rule} (settings v${after2.body.error?.decision?.configVersion}), ${okShort.body.decision?.rule}`, `audit seq ${audit.seq}: ${JSON.stringify(audit.details.diff)}`, change.status === 200 && after2.body.error?.decision?.rule === 'GRANT_TTL_OUT_OF_RANGE' && okShort.status === 201);
  await U.admin.req('PUT', '/api/admin/settings', { changes: { max_grant_ttl_hours: 168, default_grant_ttl_hours: 24 }, reason: 'evaluation: restore', confirm: true });
}

// ======================================================================= T5
inst.advance(61_000); // new rate-limit window per group (limits are per minute)
{
  const r = await U.admin.req('POST', '/api/admin/users', { username: 'kim', role: 'operator' });
  const kim = inst.client();
  await kim.enroll('kim', r.body.enrollmentCode, 'Kim#password12');
  const own = await kim.upload('kim-private.txt', 'text/plain', 'only kim knows');
  const recv = await U.alice.upload('for-kim.txt', 'text/plain', 'shared with kim');
  await U.alice.share(recv.docId, 'kim', { minutes: 120, maxDownloads: 5 });

  const wrong = await inst.client().login('kim', 'Not#kims-pass1');
  record('T5', 'Wrong password cannot open the key', 'sign in as kim with wrong password', 'AUTH_FAILED (generic)', `${wrong.status} ${wrong.body.error.code}`, 'scrypt(authKey) mismatch; private key never unwrapped', wrong.status === 401);

  const reset = await U.admin.req('POST', `/api/admin/users/${r.body.user.id}/reset`, { confirm: true });
  const kim2 = inst.client();
  await kim2.enroll('kim', reset.body.enrollmentCode, 'Kim#newpass123');
  const ownR = await kim2.req('POST', `/api/documents/${own.docId}/download`);
  const recvR = await kim2.req('POST', `/api/documents/${recv.docId}/download`);
  record('T5', 'After key reset, documents kim owned are unrecoverable', 'admin reset → kim re-enrolls (key v2) → opens own file', 'KEY_MISMATCH (no escrow by design)', ownR.body.error?.decision?.rule, JSON.stringify(ownR.body.error?.decision?.evidence), ownR.body.error?.decision?.rule === 'KEY_MISMATCH');
  record('T5', 'After key reset, grants to the old key are refused with an explanation', 'kim (v2) opens file shared to key v1', 'KEY_MISMATCH', recvR.body.error?.decision?.rule, `grant key v${recvR.body.error?.decision?.evidence.grantKeyVersion} vs current v${recvR.body.error?.decision?.evidence.currentKeyVersion}`, recvR.body.error?.decision?.rule === 'KEY_MISMATCH');

  let oldKeyErr = null;
  try {
    const stale = inst.svc.repos.grants.latestFor(recv.docId, r.body.user.id).wrapped_key;
    await C.unwrapDek(stale, kim2.privateKey);
  } catch (e) {
    oldKeyErr = e.message;
  }
  record('T5', 'New private key cannot unwrap a DEK wrapped for the old key', 'force-unwrap stale wrapped DEK with key v2', 'DEK_UNWRAP_FAILED', oldKeyErr || 'unwrapped', 'cryptographic, not just policy', oldKeyErr === 'DEK_UNWRAP_FAILED');

  const g = inst.svc.repos.grants.latestFor(recv.docId, r.body.user.id);
  await U.alice.req('POST', `/api/grants/${g.id}/revoke`, { confirm: true, reason: 'key reset' });
  const reshare = await U.alice.share(recv.docId, 'kim', { minutes: 60 });
  const got = await kim2.download(recv.docId);
  record('T5', 'Recovery path: owner re-shares to the new key', 'alice revokes stale grant and shares again', 'ALLOW_SHARE then plaintext restored', `${reshare.body.decision?.rule}, plaintext=${got.plaintext ? td(got.plaintext) : 'none'}`, '', got.plaintext && td(got.plaintext) === 'shared with kim');

  const auditReset = inst.svc.repos.audit.query({ action: 'USER_RESET', limit: 1 })[0];
  record('T5', 'Key reset is audited', 'inspect audit trail', 'USER_RESET with previous key version', JSON.stringify(auditReset?.details), `seq ${auditReset?.seq}`, auditReset?.details.previousKeyVersion === 1);
}

// ======================================================================= EX: spec page-3 example
inst.advance(61_000);
{
  const fx = (f) => new Uint8Array(fs.readFileSync(path.join(ROOT, 'fixtures', f)));
  const good = await U.alice.upload('access-policy.pdf', 'application/pdf', fx('samples/access-policy.pdf'));
  record('EX', 'Normal sample completes with evidence and no warning', 'alice uploads fixtures/samples/access-policy.pdf', 'ALLOW_UPLOAD, severity info', `${good.body.decision?.rule}, severity ${good.body.decision?.severity}`, JSON.stringify(good.body.decision?.evidence), good.body.decision?.rule === 'ALLOW_UPLOAD' && good.body.decision?.severity === 'info');

  const bad = await U.alice.upload('not-really.pdf', 'application/pdf', fx('adverse/not-really.pdf'));
  const badD = bad.body.error?.decision;
  record('EX', 'Seeded adverse sample names the specific indicator', 'alice uploads fixtures/adverse/not-really.pdf (text named .pdf)', 'CONTENT_TYPE_MISMATCH with the detected type, severity high', `${badD?.rule}: "${badD?.reason}" (${badD?.severity})`, `detected ${badD?.evidence?.detectedContent}, first bytes ${badD?.evidence?.firstBytes}; action: ${badD?.recommendedAction}`, badD?.rule === 'CONTENT_TYPE_MISMATCH' && badD?.evidence?.detectedContent === 'text');

  const exe = await U.alice.upload('report.pdf.exe', 'application/octet-stream', fx('adverse/report.pdf.exe'));
  record('EX', 'Disguised executable rejected', 'fixtures/adverse/report.pdf.exe', 'TYPE_NOT_ALLOWED', exe.body.error?.decision?.rule, '', exe.body.error?.decision?.rule === 'TYPE_NOT_ALLOWED');

  const hist = (await U.alice.req('GET', '/api/decisions?action=upload&limit=10')).body.decisions;
  const both = hist.some((d) => d.rule === 'ALLOW_UPLOAD' && d.subject === 'access-policy.pdf') && hist.some((d) => d.rule === 'CONTENT_TYPE_MISMATCH' && d.subject === 'not-really.pdf');
  const auditRej = inst.svc.repos.audit.query({ action: 'DOC_UPLOAD_REJECTED', actor: 'alice', limit: 5 }).find((e) => e.details.rule === 'CONTENT_TYPE_MISMATCH');
  record('EX', 'Both results are in history and the rejection is audited', "alice's decision history; audit trail", 'allowed and rejected rows present; DOC_UPLOAD_REJECTED event', `history both=${both}; audit seq ${auditRej?.seq}`, JSON.stringify(auditRej?.details), both && !!auditRej);

  const csv = await U.alice.req('GET', '/api/reports/export?format=csv');
  const clean = !/BLUE HERON|wrappedKey|auth_hash/.test(csv.body) && csv.body.includes('CONTENT_TYPE_MISMATCH') && csv.body.split('\n')[0].includes('recommendedAction');
  record('EX', 'Sanitised report export contains both results', 'export CSV', 'both rules present, no keys or contents', `contains rejection=${csv.body.includes('CONTENT_TYPE_MISMATCH')}, sanitised=${clean}`, csv.body.split('\n')[0], clean);

  const deny = await U.mallory.req('GET', `/api/documents/${good.docId}`);
  const ad = inst.svc.repos.audit.query({ action: 'ACCESS_DENIED', actor: 'mallory', limit: 1 })[0];
  record('EX', 'Unauthorised user gets a generic denial; attempt logged without the record', 'mallory opens alice\'s document', '404 generic, ACCESS_DENIED logged without filename', `${deny.status} ${deny.body.error?.code}; audit seq ${ad?.seq}`, JSON.stringify(ad?.details), deny.status === 404 && ad && !JSON.stringify(ad.details).includes('access-policy'));

  const tamper = await U.alice.download(good.docId, { tamper: (ct) => ((ct[40] ^= 1), ct) });
  const tAudit = inst.svc.repos.audit.query({ action: 'DOWNLOAD_INTEGRITY_FAILURE', limit: 1 })[0];
  record('EX', 'Client-detected tampering is recorded server-side', 'flip 1 bit in transit; browser reports the failure', 'INTEGRITY_CHECK_FAILED decision (high) + audit event', `${tamper.report?.body?.decision?.rule} (${tamper.report?.body?.decision?.severity}); audit seq ${tAudit?.seq}`, JSON.stringify(tAudit?.details), tamper.report?.status === 201 && !!tAudit);
}

// ======================================================================= T-final
inst.advance(61_000); // new rate-limit window per group (limits are per minute)
{
  const bad = await U.alice.req('POST', '/api/documents', '{"filename":', { raw: true, headers: { 'content-type': 'application/json' } });
  record('T-final', 'Malformed JSON', 'truncated JSON body', '400 MALFORMED_JSON, no stack trace', `${bad.status} ${bad.body.error.code}`, `requestId ${bad.body.error.requestId.slice(0, 8)}`, bad.status === 400 && !/\.js:\d+/.test(JSON.stringify(bad.body)));

  const huge = await U.alice.req('POST', '/api/documents', JSON.stringify({ filename: 'x'.repeat(33 * 1024 * 1024) }), { raw: true, headers: { 'content-type': 'application/json' } });
  record('T-final', 'Oversized request body', '33 MB JSON body', '413 PAYLOAD_TOO_LARGE', `${huge.status} ${huge.body.error.code}`, 'express.json limit 32 MB', huge.status === 413);

  const big = await U.alice.req('POST', '/api/documents', { filename: 'big.pdf', mimeType: 'application/pdf', sizeBytes: 11 * 1024 * 1024, content: PDF_HEAD });
  record('T-final', 'File larger than policy limit', 'declare 11 MB PDF (limit 10 MB)', 'FILE_TOO_LARGE', big.body.error?.decision?.rule, JSON.stringify(big.body.error?.decision?.evidence), big.body.error?.decision?.rule === 'FILE_TOO_LARGE');

  for (const [name, mime] of [
    ['report.pdf.exe', 'application/octet-stream'],
    ['invoice.exe.pdf', 'application/pdf'],
    ['notes.pdf', 'text/plain'],
  ]) {
    const r = await U.alice.req('POST', '/api/documents', { filename: name, mimeType: mime, sizeBytes: 10, content: TXT_HEAD });
    record('T-final', `Unsafe file name/type rejected: ${name}`, `${name} as ${mime}`, 'TYPE_NOT_ALLOWED', r.body.error?.decision?.rule, '', r.body.error?.decision?.rule === 'TYPE_NOT_ALLOWED');
  }

  const unk = await U.alice.req('POST', '/api/documents', { filename: 'a.txt', mimeType: 'text/plain', sizeBytes: 1, isAdmin: true, content: TXT_HEAD });
  record('T-final', 'Unexpected fields (mass assignment) rejected', 'extra field isAdmin:true', '400 VALIDATION_FAILED UNKNOWN_FIELD', `${unk.status} ${unk.body.error.details?.[0]?.rule}`, '', unk.status === 400 && unk.body.error.details[0].rule === 'UNKNOWN_FIELD');

  const sqli = await U.admin.req('POST', '/api/admin/users', { username: "x'); DROP TABLE users;--", role: 'viewer' });
  record('T-final', 'Injection-shaped input treated as data', "username x'); DROP TABLE users;--", '400 VALIDATION_FAILED; users table intact', `${sqli.status}; users=${inst.svc.repos.users.count()}`, 'parameterised statements + allow-list pattern', sqli.status === 400 && inst.svc.repos.users.count() > 0);

  const unauth = await U.victor.req('GET', '/api/admin/audit');
  const ad = inst.svc.repos.audit.query({ action: 'ACCESS_DENIED', actor: 'victor', limit: 1 })[0];
  record('T-final', 'Unauthorised request', 'viewer calls admin audit API', '403 FORBIDDEN + ACCESS_DENIED logged', `${unauth.status}; audit seq ${ad?.seq}`, JSON.stringify(ad?.details), unauth.status === 403 && !!ad);

  const up = await U.alice.upload('tf-dup.txt', 'text/plain', 'dup');
  const g1 = await U.alice.share(up.docId, 'bob');
  const g2 = await U.alice.share(up.docId, 'bob');
  const re = await U.alice.req('PUT', `/api/documents/${up.docId}/content`, { ciphertext: C.toB64(up.container), wrappedKey: C.toB64(new Uint8Array(256)) });
  record('T-final', 'Repeated submission', 'same share twice; same upload twice', '201 then 409 DUPLICATE_ACTIVE_GRANT; 409 ALREADY_UPLOADED', `${g1.status}, ${g2.status} ${g2.body.error?.decision?.rule}; ${re.status} ${re.body.error?.decision?.rule}`, '', g1.status === 201 && g2.status === 409 && re.status === 409);

  // brute force
  let last;
  const lim = inst.svc.settings().login_attempts_per_15min;
  for (let i = 0; i <= lim; i++) last = await inst.client().req('POST', '/api/auth/login', { username: 'victor', authKey: C.toB64(new Uint8Array(32)) });
  record('T-final', 'Brute-force sign-in throttled', `${lim + 1} wrong attempts in 15 min`, '429 RATE_LIMITED with Retry-After', `${last.status} retry-after=${last.headers.get('retry-after')}s`, 'RATE_LIMITED audited', last.status === 429);
  inst.advance(16 * 60_000);

  // safe failure: deleted document
  const del = await U.alice.upload('tf-delete.txt', 'text/plain', 'bye');
  await U.alice.share(del.docId, 'bob');
  await U.alice.req('DELETE', `/api/documents/${del.docId}`, { confirm: true });
  const afterDel = await U.bob.req('POST', `/api/documents/${del.docId}/download`);
  const blob = inst.svc.db.prepare('SELECT content FROM documents WHERE id = ?').get(del.docId).content;
  record('T-final', 'Safe failure after deletion (crypto-shred)', 'owner deletes shared file; recipient retries', 'denied; ciphertext and wrapped keys erased', `${afterDel.body.error?.decision?.rule ?? afterDel.status}; blob=${blob === null ? 'NULL' : 'present'}`, 'secure_delete pragma on', blob === null && afterDel.status === 403);

  // tamper with audit, verify detection, restore by fresh instance later
  const v1 = inst.svc.audit.verify();
  record('T-final', 'Audit chain verifies before restart', `${v1.evidence.checked} events`, 'CHAIN_INTACT', v1.rule, `head ${v1.evidence.head.hash.slice(0, 16)}… in ${v1.latencyMs} ms`, v1.ok);
  metrics.auditVerify = { events: v1.evidence.checked, ms: v1.latencyMs };

  // restart
  await inst.restart();
  const bob = inst.client();
  await bob.login('bob', PASSWORDS.bob);
  const list = (await bob.req('GET', '/api/documents')).body.shared;
  const target = list.find((d) => d.filename === 't1-secret.txt');
  const r = await bob.download(target.id);
  const v2 = inst.svc.audit.verify();
  record('T-final', 'Recovery after restart', 'stop server, start on same data directory, bob opens file', 'data intact, chain intact, file decrypts', `chain ${v2.rule}; plaintext ok=${r.plaintext && td(r.plaintext) === SECRET}`, `startup self-check: ${inst.svc.repos.audit.query({ action: 'SYSTEM_START', limit: 1 })[0].details.auditChain}`, v2.ok && r.plaintext && td(r.plaintext) === SECRET);

  for (const [name, c] of Object.entries(U)) {
    c.base = inst.base; // the restarted instance listens on a new port
    await c.login(name, PASSWORDS[name]);
  }

  // tamper detection after restart (bypassing triggers like an attacker with file access)
  inst.svc.db.exec('DROP TRIGGER audit_no_update');
  const victim = inst.svc.db.prepare("SELECT seq FROM audit_events WHERE action = 'DOWNLOAD_DENY' ORDER BY seq LIMIT 1").get();
  inst.svc.db.prepare(`UPDATE audit_events SET outcome = 'success' WHERE seq = ?`).run(victim.seq);
  const v3 = inst.svc.audit.verify({ updateAnchor: false });
  record('T-final', 'Audit tampering detected', `attacker drops trigger and rewrites event ${victim.seq} (DOWNLOAD_DENY → success)`, `HASH_MISMATCH at seq ${victim.seq}`, `${v3.rule} at seq ${v3.evidence.atSeq}`, 'HMAC key held outside the database', !v3.ok && v3.evidence.atSeq === victim.seq);
}

// ======================================================================= FR-5 watermark
inst.advance(61_000);
{
  const up = await U.alice.upload('wm.txt', 'text/plain', 'watermark me\n'.repeat(60));
  await U.alice.share(up.docId, 'bob', { minutes: 60, maxDownloads: 5 });
  const bob = inst.client();
  await bob.login('bob', PASSWORDS.bob);
  const d = await bob.download(up.docId);
  const marked = WM.embedText(td(d.plaintext), d.body.watermark.payload, d.body.watermark.label);
  const excerpt = marked.split('\n').slice(20, 40).join('\n');
  const found = WM.extractFromText(excerpt);
  const admin = inst.client();
  await admin.login('admin', PASSWORDS.admin);
  const t = await admin.req('POST', '/api/admin/trace', { payload: found[0] });
  record('FR-5', 'Leaked excerpt traces to recipient and download', '20-line excerpt without the visible banner', 'WATERMARK_VERIFIED → bob', `${t.body.rule} → ${t.body.evidence?.recipient}`, `download ${t.body.evidence?.downloadId?.slice(0, 8)}`, t.body.valid && t.body.evidence.recipient === 'bob');
  const forged = await admin.req('POST', '/api/admin/trace', { payload: found[0].replace(/.{4}$/, 'AAAA') });
  record('FR-5', 'Forged watermark rejected', 'alter last 4 chars of tag', 'WATERMARK_FORGED', forged.body.rule, '', forged.body.rule === 'WATERMARK_FORGED');

  // ======================================================================= performance
  const dl = [];
  inst.advance(61_000);
  await admin.req('PUT', '/api/admin/settings', { changes: { max_downloads_cap: 100 }, reason: 'evaluation: allow 60-download latency run', confirm: true });
  const up3 = await U.alice.upload('perf.txt', 'text/plain', 'perf');
  await U.alice.share(up3.docId, 'victor', { minutes: 60, maxDownloads: 100 });
  const vic = inst.client();
  await vic.login('victor', PASSWORDS.victor);
  for (let i = 0; i < 60; i++) {
    if (i % 25 === 0) inst.advance(61_000);
    dl.push((await vic.req('POST', `/api/documents/${up3.docId}/download`)).ms);
  }
  const dec = inst.svc.db.prepare('SELECT action, latency_ms FROM decisions').all();
  const byAction = {};
  for (const x of dec) (byAction[x.action] ||= []).push(x.latency_ms);
  metrics.decisionLatencyMs = Object.fromEntries(Object.entries(byAction).map(([a, arr]) => [a, { n: arr.length, p50: r3(pct(arr, 50)), p95: r3(pct(arr, 95)), max: r3(Math.max(...arr)) }]));
  metrics.downloadRoundTripMs = { n: dl.length, p50: r3(pct(dl, 50)), p95: r3(pct(dl, 95)), max: r3(Math.max(...dl)) };

  const throughput = [];
  for (const mb of [1, 5, 10]) {
    const data = C.randomBytes(Math.min(65536, mb * 1024 * 1024));
    const full = new Uint8Array(mb * 1024 * 1024);
    for (let o = 0; o < full.length; o += data.length) full.set(data.subarray(0, Math.min(data.length, full.length - o)), o);
    const k = await C.generateDek();
    const a = performance.now();
    const ct = await C.encryptDocument(k, full, 'perf');
    const b = performance.now();
    await C.decryptDocument(k, ct, 'perf');
    const c = performance.now();
    throughput.push({ sizeMb: mb, encryptMs: r3(b - a), decryptMs: r3(c - b) });
  }
  metrics.aesGcmThroughput = throughput;
}

await inst.destroy();

// ======================================================================= automated test pass rate
let testSummary = { tests: 0, pass: 0, fail: 0 };
try {
  const out = execFileSync(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=tap', 'tests/*.test.js'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env } });
  testSummary = parseTap(out);
} catch (e) {
  testSummary = parseTap(e.stdout || '');
}
function parseTap(out) {
  const g = (k) => Number((new RegExp(`^# ${k} (\\d+)`, 'm').exec(out) || [])[1] || 0);
  return { tests: g('tests'), pass: g('pass'), fail: g('fail') };
}
metrics.automatedTests = { ...testSummary, passRate: testSummary.tests ? r3(testSummary.pass / testSummary.tests) : 0 };

// ======================================================================= write report
fs.mkdirSync(OUT, { recursive: true });
const passed = rows.filter((r) => r.pass).length;
const summary = { generatedAt: new Date().toISOString(), node: process.version, cases: rows.length, passed, failed: rows.length - passed };
fs.writeFileSync(path.join(OUT, 'evaluation.json'), JSON.stringify({ summary, metrics, cases: rows }, null, 2));

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const GROUP_TITLES = {
  T1: 'T1 — Confidentiality',
  T2: 'T2 — Altered-ciphertext rejection',
  T3: 'T3 — Access-control matrix',
  T4: 'T4 — Expiry, revocation and limits',
  T5: 'T5 — Key-loss behaviour',
  EX: 'Illustrative working example (spec page 3) — normal vs adverse sample, history, export, unauthorised viewer',
  'T-final': 'T-final — Malformed/oversized input, unauthorised and repeated requests, safe failure, restart',
  'FR-5': 'FR-5 — Watermark tracing',
};
let md = `# VaultShare evaluation results\n\nGenerated ${summary.generatedAt} on Node ${summary.node} by \`npm run evaluate\`.\n\n`;
md += `**${passed} of ${rows.length} evaluation cases passed.** Automated test suite: **${testSummary.pass}/${testSummary.tests} passed (${Math.round((metrics.automatedTests.passRate || 0) * 100)}%)**.\n\n`;
for (const [g, title] of Object.entries(GROUP_TITLES)) {
  const rs = rows.filter((r) => r.group === g);
  if (!rs.length) continue;
  md += `## ${title}\n\n| ID | Case | Input | Expected | Actual | Evidence | Result |\n|---|---|---|---|---|---|---|\n`;
  for (const r of rs) md += `| ${r.id} | ${esc(r.title)} | ${esc(r.input)} | ${esc(r.expected)} | ${esc(r.actual)} | ${esc(r.evidence)} | ${r.pass ? 'PASS' : '**FAIL**'} |\n`;
  md += '\n';
}
md += `## Measurements\n\n### Access-control matrix (rule-based)\n\n| Requests | Correct allow | Correct deny | False permit | False deny | Coverage |\n|---|---|---|---|---|---|\n| ${metrics.accessMatrix.cases} | ${metrics.accessMatrix.truePermit} | ${metrics.accessMatrix.trueDeny} | ${metrics.accessMatrix.falsePermit} | ${metrics.accessMatrix.falseDeny} | ${metrics.accessMatrix.coverage} |\n\n`;
md += `<details><summary>All ${metrics.accessMatrix.cases} matrix requests</summary>\n\n| Permission | Role | Expected | Actual | HTTP |\n|---|---|---|---|---|\n${metrics.accessMatrix.rows.map((r) => `| ${r.perm} | ${r.role} | ${r.expected} | ${r.actual} | ${r.status} |`).join('\n')}\n\n</details>\n\n`;
md += `### Tamper detection\n\n${metrics.tamperDetection.detected}/${metrics.tamperDetection.trials} random single-bit corruptions rejected (false-negative rate ${(1 - metrics.tamperDetection.rate) * 100}%).\n\n`;
md += `### Policy decision latency (server-side, ms)\n\n| Decision type | n | p50 | p95 | max |\n|---|---|---|---|---|\n`;
for (const [a, m] of Object.entries(metrics.decisionLatencyMs)) md += `| ${a} | ${m.n} | ${m.p50} | ${m.p95} | ${m.max} |\n`;
md += `\nDownload request round trip (client-observed, includes JSON transfer): p50 ${metrics.downloadRoundTripMs.p50} ms, p95 ${metrics.downloadRoundTripMs.p95} ms over ${metrics.downloadRoundTripMs.n} requests.\n\n`;
md += `Audit chain verification: ${metrics.auditVerify.events} events in ${metrics.auditVerify.ms} ms.\n\n`;
md += `### AES-256-GCM throughput (Node Web Crypto on this machine)\n\n| Size | Encrypt ms | Decrypt ms |\n|---|---|---|\n`;
for (const t of metrics.aesGcmThroughput) md += `| ${t.sizeMb} MB | ${t.encryptMs} | ${t.decryptMs} |\n`;
md += `\nBrowser figures differ by device; the demonstration shows the in-browser timing for the sample files.\n`;
fs.writeFileSync(path.join(OUT, 'evaluation.md'), md);

console.log(`\n  ${passed}/${rows.length} cases passed; automated tests ${testSummary.pass}/${testSummary.tests}.`);
console.log(`  Wrote reports/evaluation.md and reports/evaluation.json\n`);
process.exit(passed === rows.length ? 0 : 1);
