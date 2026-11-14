// Security engine units: policy rules, permission matrix, validation, settings, watermark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PDFDocument } from 'pdf-lib';
import * as PDFLib from 'pdf-lib';
import { evaluateDownload, evaluateGrant, evaluateUploadMeta, evaluateUploadContent, RULES, RULE_META, ruleMeta } from '../server/engine/policy.js';
import { can, matrix, ACTIONS } from '../server/engine/access.js';
import { validate, v, sanitizeFilename } from '../server/engine/validation.js';
import { validateSettingsChange, defaultSettings, SUPPORTED_TYPES } from '../server/engine/settings.js';
import { issuePayload, verifyPayload, parsePayload } from '../server/engine/watermark.js';
import { redact } from '../server/engine/redact.js';
import * as WM from '../shared/watermark-codec.js';
import { parseContainer, CONTAINER_OVERHEAD_BYTES } from '../shared/crypto-core.js';

const NOW = Date.parse('2026-10-20T12:00:00Z');
const user = { id: 'u1', status: 'active', key_version: 1, key_fingerprint: 'f'.repeat(64) };
const doc = { id: 'd1', status: 'active', owner_id: 'o1', size_plain: 100 };
const grant = (o = {}) => ({ id: 'g1', is_owner: 0, revoked_at: null, expires_at: NOW + 60_000, max_downloads: 3, download_count: 0, recipient_key_version: 1, recipient_key_fingerprint: 'f'.repeat(64), ...o });

test('download policy: every rule fires with explainable evidence', () => {
  const cases = [
    [{ grant: grant() }, 'allow', 'ALLOW_GRANT'],
    [{ grant: grant({ is_owner: 1, expires_at: null, max_downloads: null }) }, 'allow', 'ALLOW_OWNER'],
    [{ grant: null }, 'deny', 'NO_GRANT'],
    [{ grant: grant(), user: { ...user, status: 'disabled' } }, 'deny', 'ACCOUNT_INACTIVE'],
    [{ grant: grant(), document: { ...doc, status: 'deleted' } }, 'deny', 'DOCUMENT_UNAVAILABLE'],
    [{ grant: grant({ revoked_at: NOW - 1 }) }, 'deny', 'GRANT_REVOKED'],
    [{ grant: grant({ expires_at: NOW }) }, 'deny', 'GRANT_EXPIRED'],
    [{ grant: grant({ expires_at: NOW - 1 }) }, 'deny', 'GRANT_EXPIRED'],
    [{ grant: grant({ expires_at: NOW + 1 }) }, 'allow', 'ALLOW_GRANT'],
    [{ grant: grant({ download_count: 3 }) }, 'deny', 'DOWNLOAD_LIMIT_REACHED'],
    [{ grant: grant({ download_count: 2 }) }, 'allow', 'ALLOW_GRANT'],
    [{ grant: grant({ recipient_key_version: 0 }) }, 'deny', 'KEY_MISMATCH'],
  ];
  for (const [over, decision, rule] of cases) {
    const d = evaluateDownload({ user, document: doc, now: NOW, ...over });
    assert.equal(d.decision, decision, rule);
    assert.equal(d.rule, rule);
    assert.equal(d.reason, RULES[rule]);
    assert.ok(d.engine);
  }
});

test('revocation outranks expiry and limit (first failing rule wins)', () => {
  const d = evaluateDownload({ user, document: doc, now: NOW, grant: grant({ revoked_at: NOW - 5, expires_at: NOW - 1, download_count: 9 }) });
  assert.equal(d.rule, 'GRANT_REVOKED');
});

test('share policy rules', () => {
  const settings = defaultSettings();
  const actor = { id: 'o1' };
  const recipient = { id: 'r1', username: 'bob', role: 'operator', status: 'active', public_key: 'x', key_fingerprint: 'a'.repeat(64) };
  const req = (o = {}) => ({ recipientKeyFingerprint: 'a'.repeat(64), expiresInMinutes: 60, maxDownloads: 3, ...o });
  const run = (o = {}) => evaluateGrant({ actor, document: doc, recipient, request: req(), activeGrant: null, settings, wrappedKeyBytes: 256, ...o }).rule;
  assert.equal(run(), 'ALLOW_SHARE');
  assert.equal(run({ actor: { id: 'other' } }), 'NOT_OWNER');
  assert.equal(run({ recipient: null }), 'RECIPIENT_INVALID');
  assert.equal(run({ recipient: { ...recipient, status: 'pending' } }), 'RECIPIENT_INVALID');
  assert.equal(run({ recipient: { ...recipient, id: 'o1' } }), 'RECIPIENT_IS_OWNER');
  assert.equal(run({ recipient: { ...recipient, role: 'admin' } }), 'RECIPIENT_ROLE_NOT_ALLOWED');
  assert.equal(run({ request: req({ recipientKeyFingerprint: 'b'.repeat(64) }) }), 'RECIPIENT_KEY_CHANGED');
  assert.equal(run({ wrappedKeyBytes: 128 }), 'WRAPPED_KEY_INVALID');
  assert.equal(run({ request: req({ expiresInMinutes: settings.max_grant_ttl_hours * 60 + 1 }) }), 'GRANT_TTL_OUT_OF_RANGE');
  assert.equal(run({ request: req({ expiresInMinutes: settings.max_grant_ttl_hours * 60 }) }), 'ALLOW_SHARE');
  assert.equal(run({ request: req({ maxDownloads: settings.max_downloads_cap + 1 }) }), 'DOWNLOAD_LIMIT_OUT_OF_RANGE');
  assert.equal(run({ activeGrant: { id: 'g0' } }), 'DUPLICATE_ACTIVE_GRANT');
  assert.equal(run({ document: { ...doc, status: 'deleted' } }), 'DOCUMENT_UNAVAILABLE');
});

test('upload policy: type allow-list, MIME match, size, empty', () => {
  const settings = defaultSettings();
  const run = (o) => evaluateUploadMeta({ extension: 'txt', mimeType: 'text/plain', sizeBytes: 10, settings, supported: SUPPORTED_TYPES, ...o }).rule;
  assert.equal(run({}), 'ALLOW_UPLOAD');
  assert.equal(run({ extension: 'exe', mimeType: 'application/octet-stream' }), 'TYPE_NOT_ALLOWED');
  assert.equal(run({ mimeType: 'application/pdf' }), 'TYPE_NOT_ALLOWED');
  assert.equal(run({ sizeBytes: 0 }), 'FILE_EMPTY');
  assert.equal(run({ sizeBytes: settings.max_file_size_mb * 1024 * 1024 }), 'ALLOW_UPLOAD');
  assert.equal(run({ sizeBytes: settings.max_file_size_mb * 1024 * 1024 + 1 }), 'FILE_TOO_LARGE');
  assert.equal(run({ settings: { ...settings, allowed_extensions: ['pdf'] } }), 'TYPE_NOT_ALLOWED');
});

test('content sniffing: name must match the first bytes', () => {
  const run = (ext, mime, content) => evaluateUploadMeta({ extension: ext, mimeType: mime, sizeBytes: 10, settings: defaultSettings(), supported: SUPPORTED_TYPES, content });
  assert.equal(run('pdf', 'application/pdf', { headHex: '255044462d31', utf8: false, hasNul: false }).rule, 'ALLOW_UPLOAD');
  const fake = run('pdf', 'application/pdf', { headHex: '546869732069', utf8: true, hasNul: false });
  assert.equal(fake.rule, 'CONTENT_TYPE_MISMATCH');
  assert.match(fake.reason, /contents are plain text, not a PDF/);
  assert.equal(fake.severity, 'high');
  assert.equal(fake.evidence.detectedContent, 'text');
  assert.equal(run('png', 'image/png', { headHex: '4d5a9000', utf8: false, hasNul: true }).evidence.detectedContent, 'exe');
  assert.equal(run('jpg', 'image/jpeg', { headHex: 'ffd8ffe0', utf8: false, hasNul: true }).rule, 'ALLOW_UPLOAD');
  assert.equal(run('txt', 'text/plain', { headHex: '68690a', utf8: true, hasNul: false }).rule, 'ALLOW_UPLOAD');
  assert.equal(run('csv', 'text/csv', { headHex: '0000', utf8: true, hasNul: true }).rule, 'CONTENT_TYPE_MISMATCH');
});

test('every rule has a severity and a recommended action', () => {
  for (const rule of Object.keys(RULES)) {
    const m = ruleMeta(rule);
    assert.ok(['info', 'low', 'medium', 'high'].includes(m.severity), rule);
    assert.ok(m.recommendedAction.length > 5, rule);
    assert.ok(RULE_META[rule], `${rule} missing from RULE_META`);
  }
});

test('upload content policy: structure and exact length', () => {
  const good = new Uint8Array(100 + CONTAINER_OVERHEAD_BYTES);
  good.set([0x56, 0x53, 0x48, 0x31, 1, 12]);
  const run = (o) => evaluateUploadContent({ document: { ...doc, status: 'pending' }, parsed: parseContainer(good), ciphertextBytes: good.length, overhead: CONTAINER_OVERHEAD_BYTES, wrappedKeyBytes: 256, ...o }).rule;
  assert.equal(run({}), 'ALLOW_UPLOAD');
  assert.equal(run({ ciphertextBytes: good.length + 1 }), 'CIPHERTEXT_LENGTH_MISMATCH');
  assert.equal(run({ parsed: parseContainer(new Uint8Array(50)) }), 'CIPHERTEXT_MALFORMED');
  assert.equal(run({ document: doc }), 'ALREADY_UPLOADED');
  assert.equal(run({ wrappedKeyBytes: 10 }), 'WRAPPED_KEY_INVALID');
});

test('permission matrix enforces least privilege', () => {
  assert.equal(can('admin', 'doc.download'), false, 'admins never hold document keys');
  assert.equal(can('admin', 'doc.upload'), false);
  assert.equal(can('viewer', 'doc.upload'), false);
  assert.equal(can('viewer', 'grant.create'), false);
  assert.equal(can('viewer', 'doc.download'), true);
  assert.equal(can('operator', 'audit.read'), false);
  assert.equal(can('operator', 'nonexistent.action'), false);
  assert.equal(Object.keys(matrix()).length, Object.keys(ACTIONS).length);
});

test('validator rejects unknown fields, wrong types and control characters', () => {
  const schema = { name: v.str({ max: 5 }), n: v.int({ min: 1, max: 3 }), k: v.b64({ exactBytes: 3 }) };
  assert.deepEqual({ ...validate(schema, { name: ' ab ', n: 2, k: 'YWJj' }) }, { name: 'ab', n: 2, k: 'YWJj' });
  const codes = (b) => {
    try {
      validate(schema, b);
      return [];
    } catch (e) {
      return e.details.map((d) => `${d.field}:${d.rule}`);
    }
  };
  assert.ok(codes({ name: 'a', n: 2, k: 'YWJj', extra: 1 }).includes('extra:UNKNOWN_FIELD'));
  assert.ok(codes({ name: 'toolong', n: 2, k: 'YWJj' }).includes('name:TOO_LONG'));
  assert.ok(codes({ name: 'a\u202Eb', n: 2, k: 'YWJj' }).includes('name:CONTROL_CHARS'));
  assert.ok(codes({ name: 'a', n: '2', k: 'YWJj' }).includes('n:TYPE'));
  assert.ok(codes({ name: 'a', n: 9, k: 'YWJj' }).includes('n:OUT_OF_RANGE'));
  assert.ok(codes({ name: 'a', n: 2, k: 'YWJjZA==' }).includes('k:LENGTH'));
  assert.ok(codes({ n: 2, k: 'YWJj' }).includes('name:REQUIRED'));
  assert.throws(() => validate(schema, [1, 2]), (e) => e.code === 'VALIDATION_FAILED');
});

test('filename sanitiser blocks traversal, hidden and double-extension names', () => {
  assert.deepEqual(sanitizeFilename('report.pdf'), { name: 'report.pdf', extension: 'pdf' });
  assert.deepEqual(sanitizeFilename('../../etc/passwd.txt'), { name: 'passwd.txt', extension: 'txt' });
  assert.deepEqual(sanitizeFilename('C:\\Users\\x\\notes.MD'), { name: 'notes.MD', extension: 'md' });
  for (const bad of ['.env', 'noext', 'invoice.exe.pdf', 'a<b>.txt', 'x\u0000.txt', 'page.html.txt']) assert.equal(sanitizeFilename(bad), null, bad);
});

test('settings validation enforces bounds and consistency', () => {
  const cur = defaultSettings();
  assert.equal(validateSettingsChange(cur, { max_file_size_mb: 5 }).ok, true);
  assert.equal(validateSettingsChange(cur, { max_file_size_mb: 500 }).ok, false);
  assert.equal(validateSettingsChange(cur, { unknown: 1 }).errors[0].rule, 'UNKNOWN_SETTING');
  assert.equal(validateSettingsChange(cur, { allowed_extensions: ['exe'] }).ok, false);
  assert.equal(validateSettingsChange(cur, { allowed_extensions: [] }).ok, false);
  assert.equal(validateSettingsChange(cur, { max_grant_ttl_hours: 2, default_grant_ttl_hours: 24 }).errors[0].rule, 'DEFAULT_EXCEEDS_MAX');
});

test('watermark payload: verify, forged tag, unknown, malformed', () => {
  const key = Buffer.alloc(32, 7);
  const rec = { id: '0b5e3a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c', grant_id: 'g', user_id: 'u', document_id: 'd' };
  const p = issuePayload(key, { downloadId: rec.id, grantId: 'g', userId: 'u', documentId: 'd' });
  assert.match(p, /^VS1\./);
  assert.equal(verifyPayload(key, p, rec).rule, 'WATERMARK_VERIFIED');
  assert.equal(verifyPayload(key, p, { ...rec, user_id: 'someone-else' }).rule, 'WATERMARK_FORGED');
  assert.equal(verifyPayload(Buffer.alloc(32, 8), p, rec).rule, 'WATERMARK_FORGED');
  assert.equal(verifyPayload(key, p, null).rule, 'WATERMARK_UNKNOWN');
  assert.equal(verifyPayload(key, 'hello', rec).rule, 'WATERMARK_MALFORMED');
  assert.equal(parsePayload(p).downloadId, rec.id);
});

const PAYLOAD = 'VS1.0b5e3a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c.AAAAAAAAAAAAAAAAAAAAAA';

test('text watermark survives and is extractable, including after partial copy', () => {
  const text = Array.from({ length: 80 }, (_, i) => `line ${i}`).join('\n');
  const marked = WM.embedText(text, PAYLOAD, 'Issued to bob', { format: 'txt' });
  assert.ok(marked.startsWith('VaultShare confidential copy.'));
  assert.deepEqual(WM.extractFromText(marked), [PAYLOAD]);
  const excerpt = marked.split('\n').slice(40, 60).join('\n'); // banner cut off
  assert.deepEqual(WM.extractFromText(excerpt), [PAYLOAD]);
  assert.ok(WM.embedText('a,b', PAYLOAD, 'x', { format: 'csv' }).startsWith('# '));
  assert.deepEqual(WM.extractFromText('no watermark here'), []);
});

test('PNG tEXt watermark round trip', () => {
  // minimal valid 1x1 PNG
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
  const out = WM.insertPngText(new Uint8Array(png), WM.WM_KEYWORD, PAYLOAD);
  assert.deepEqual(WM.extractFromPng(out), [PAYLOAD]);
  assert.deepEqual(WM.extractFromPng(new Uint8Array(png)), []);
  assert.throws(() => WM.insertPngText(new Uint8Array([1, 2, 3]), 'k', 'v'), /NOT_A_PNG/);
});

test('PDF watermark is stamped on every page and stored in metadata', async () => {
  const d = await PDFDocument.create();
  d.addPage();
  d.addPage();
  const marked = await WM.embedPdf(PDFLib, await d.save(), PAYLOAD, 'Issued to bob');
  assert.deepEqual(await WM.extractFromPdf(PDFLib, marked), [PAYLOAD]);
  const reloaded = await PDFDocument.load(marked);
  assert.equal(reloaded.getPageCount(), 2);
});

test('redaction removes secrets but keeps descriptive fields', () => {
  const r = redact({ password: 'x', authKey: 'y', wrappedKey: 'z', ciphertext: 'c', ciphertextBytes: 10, session_idle_minutes: 5, nested: { csrfToken: 't', ok: 1 } });
  assert.equal(r.password, '[redacted]');
  assert.equal(r.authKey, '[redacted]');
  assert.equal(r.wrappedKey, '[redacted]');
  assert.equal(r.ciphertext, '[redacted]');
  assert.equal(r.ciphertextBytes, 10);
  assert.equal(r.session_idle_minutes, 5);
  assert.deepEqual(r.nested, { csrfToken: '[redacted]', ok: 1 });
});
