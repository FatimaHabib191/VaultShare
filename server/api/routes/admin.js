// Administrator functions: users and roles (FR-1), settings (traceable rule
// changes), audit review/verification/export (FR-6) and leak tracing (FR-5).
import { Router } from 'express';
import { randomUUID, randomBytes } from 'node:crypto';
import { AppError } from '../../lib/errors.js';
import { validate, v, USERNAME, UUID_RE } from '../../engine/validation.js';
import { requirePerm } from '../middleware.js';
import { newEnrollmentCode, hashCode } from '../../lib/passwords.js';
import { SETTINGS_SCHEMA, validateSettingsChange, diffSettings } from '../../engine/settings.js';
import { matrix, ROLES } from '../../engine/access.js';
import { verifyPayload, parsePayload } from '../../engine/watermark.js';
import { RULES, RULE_META, ENGINE_VERSION } from '../../engine/policy.js';
import { CRYPTO_VERSION } from '../../../shared/crypto-core.js';

export default function adminRoutes(svc) {
  const r = Router();
  const uid = (req) => {
    if (!UUID_RE.test(req.params.id)) throw new AppError('NOT_FOUND');
    const u = svc.repos.users.byId(req.params.id);
    if (!u) throw new AppError('NOT_FOUND');
    return u;
  };
  const userView = (u) => ({
    id: u.id,
    username: u.username,
    role: u.role,
    status: u.status,
    keyFingerprint: u.key_fingerprint,
    keyVersion: u.key_version,
    createdAt: new Date(u.created_at).toISOString(),
    lastLoginAt: u.last_login_at ? new Date(u.last_login_at).toISOString() : null,
    enrollmentExpiresAt: u.enroll_expires_at ? new Date(u.enroll_expires_at).toISOString() : null,
  });

  function issueEnrollment() {
    const code = newEnrollmentCode();
    const cfg = svc.settings();
    return {
      code,
      fields: {
        kdf_salt: randomBytes(16).toString('base64'),
        kdf_iterations: cfg.kdf_iterations,
        enroll_code_hash: hashCode(code),
        enroll_expires_at: svc.now() + cfg.enrollment_code_hours * 3_600_000,
      },
    };
  }

  // ---------- overview ----------
  r.get('/overview', requirePerm('audit.read'), (req, res) => {
    const users = svc.repos.users.list();
    res.json({
      users: { total: users.length, byRole: Object.fromEntries(ROLES.map((x) => [x, users.filter((u) => u.role === x).length])), pending: users.filter((u) => u.status === 'pending').length },
      auditEvents: svc.repos.audit.count(),
      decisionStats: svc.repos.decisions.stats(),
      versions: { engine: ENGINE_VERSION, crypto: CRYPTO_VERSION, settings: svc.settingsVersion() },
      permissions: matrix(),
      rules: Object.fromEntries(Object.entries(RULES).map(([k, reason]) => [k, { reason, severity: RULE_META[k]?.[0] ?? 'info', recommendedAction: RULE_META[k]?.[1] ?? '' }])),
    });
  });

  // ---------- users ----------
  r.get('/users', requirePerm('user.manage'), (req, res) => res.json({ users: svc.repos.users.list().map(userView) }));

  r.post('/users', requirePerm('user.manage'), (req, res) => {
    const body = validate({ username: v.str(USERNAME), role: v.oneOf(ROLES) }, { ...req.body, username: String(req.body?.username ?? '').toLowerCase() });
    if (svc.repos.users.byUsername(body.username)) throw new AppError('CONFLICT', { message: 'That username is taken.' });
    const id = randomUUID();
    const { code, fields } = issueEnrollment();
    svc.repos.users.create({ id, username: body.username, role: body.role, ...fields });
    req.audit('USER_CREATE', 'success', { targetType: 'user', targetId: id, details: { username: body.username, role: body.role } });
    res.status(201).json({ user: userView(svc.repos.users.byId(id)), enrollmentCode: code });
  });

  // Reset = new enrollment, new key pair. Existing grants to this user become
  // unusable (KEY_MISMATCH) and documents they own become unrecoverable: there is
  // deliberately no key escrow (see T5 / limitations).
  r.post('/users/:id/reset', requirePerm('user.manage'), (req, res) => {
    const u = uid(req);
    validate({ confirm: v.oneOf([true]) }, req.body);
    if (u.id === req.user.id) throw new AppError('CONFLICT', { message: 'You cannot reset your own account while signed in.' });
    const { code, fields } = issueEnrollment();
    svc.repos.users.resetKeys({ id: u.id, ...fields });
    const ended = svc.repos.sessions.deleteForUser(u.id);
    req.audit('USER_RESET', 'success', { targetType: 'user', targetId: u.id, details: { username: u.username, previousKeyVersion: u.key_version, sessionsEnded: ended } });
    res.json({ user: userView(svc.repos.users.byId(u.id)), enrollmentCode: code });
  });

  r.post('/users/:id/status', requirePerm('user.manage'), (req, res) => {
    const u = uid(req);
    const body = validate({ status: v.oneOf(['active', 'disabled']), confirm: v.oneOf([true]) }, req.body);
    if (u.id === req.user.id) throw new AppError('CONFLICT', { message: 'You cannot change your own status.' });
    if (u.status === 'pending') throw new AppError('CONFLICT', { message: 'The user has not enrolled yet.' });
    if (body.status === 'active' && !u.public_key) throw new AppError('CONFLICT', { message: 'The user must enroll before being enabled.' });
    svc.repos.users.setStatus(u.id, body.status);
    const ended = body.status === 'disabled' ? svc.repos.sessions.deleteForUser(u.id) : 0;
    req.audit(body.status === 'disabled' ? 'USER_DISABLE' : 'USER_ENABLE', 'success', { targetType: 'user', targetId: u.id, details: { username: u.username, sessionsEnded: ended } });
    res.json({ user: userView(svc.repos.users.byId(u.id)) });
  });

  r.post('/users/:id/role', requirePerm('user.manage'), (req, res) => {
    const u = uid(req);
    const body = validate({ role: v.oneOf(ROLES), confirm: v.oneOf([true]) }, req.body);
    if (u.id === req.user.id) throw new AppError('CONFLICT', { message: 'You cannot change your own role.' });
    svc.repos.users.setRole(u.id, body.role);
    svc.repos.sessions.deleteForUser(u.id);
    req.audit('USER_ROLE_CHANGE', 'success', { targetType: 'user', targetId: u.id, details: { username: u.username, from: u.role, to: body.role } });
    res.json({ user: userView(svc.repos.users.byId(u.id)) });
  });

  // ---------- settings ----------
  r.get('/settings', requirePerm('config.read'), (req, res) => {
    res.json({ version: svc.settingsVersion(), values: svc.settings(), schema: SETTINGS_SCHEMA, history: svc.repos.settings.history(25) });
  });

  r.put('/settings', requirePerm('config.write'), (req, res) => {
    const body = validate({ changes: v.any(), reason: v.str({ min: 3, max: 200 }), confirm: v.oneOf([true]) }, req.body);
    const before = svc.settings();
    const { ok, errors, next } = validateSettingsChange(before, body.changes, { testMode: svc.testMode });
    if (!ok) throw new AppError('VALIDATION_FAILED', { details: errors });
    const diff = diffSettings(before, next);
    if (!Object.keys(diff).length) throw new AppError('CONFLICT', { message: 'No settings changed.' });
    const version = svc.settingsVersion() + 1;
    svc.repos.settings.insert({ version, values: next, diff, reason: body.reason, changedBy: req.user.id });
    svc.reloadSettings();
    req.audit('CONFIG_CHANGE', 'success', { targetType: 'settings', targetId: String(version), details: { version, reason: body.reason, diff } });
    res.json({ version, values: next, diff });
  });

  // ---------- audit ----------
  const auditFilters = (q) => {
    const f = {};
    if (typeof q.action === 'string' && /^[A-Z_]{3,40}$/.test(q.action)) f.action = q.action;
    if (typeof q.outcome === 'string' && ['success', 'denied', 'error', 'info'].includes(q.outcome)) f.outcome = q.outcome;
    if (typeof q.actor === 'string' && /^[a-z][a-z0-9._-]{2,31}$/.test(q.actor)) f.actor = q.actor;
    if (q.from && !Number.isNaN(Date.parse(q.from))) f.from = new Date(q.from).toISOString();
    if (q.to && !Number.isNaN(Date.parse(q.to))) f.to = new Date(q.to).toISOString();
    if (q.limit && /^\d{1,4}$/.test(q.limit)) f.limit = Number(q.limit);
    if (q.beforeSeq && /^\d{1,10}$/.test(q.beforeSeq)) f.beforeSeq = Number(q.beforeSeq);
    return f;
  };

  r.get('/audit', requirePerm('audit.read'), (req, res) => {
    res.json({ events: svc.repos.audit.query(auditFilters(req.query)), actions: svc.repos.audit.actions(), total: svc.repos.audit.count() });
  });

  r.post('/audit/verify', requirePerm('audit.verify'), (req, res) => {
    const started = performance.now();
    const result = svc.audit.verify();
    const rec = svc.decide(
      req,
      { action: 'audit_verify', subjectType: 'audit', subjectLabel: 'audit chain' },
      { decision: result.ok ? 'allow' : 'deny', rule: result.rule, reason: result.ok ? 'Every event hash and link verified.' : 'The audit chain is broken; see evidence.', evidence: result.evidence, engine: 'vaultshare-audit/1.0.0' },
      started
    );
    req.audit('AUDIT_VERIFY', result.ok ? 'success' : 'error', { details: { rule: result.rule, checked: result.evidence.checked, decisionId: rec.id } });
    res.json({ ...result, severity: rec.severity, recommendedAction: rec.recommendedAction, decisionId: rec.id });
  });

  r.get('/audit/export', requirePerm('audit.export'), (req, res) => {
    const verification = svc.audit.verify({ updateAnchor: false });
    const events = svc.repos.audit.all();
    req.audit('AUDIT_EXPORT', 'success', { details: { events: events.length, chainIntact: verification.ok } });
    const stamp = new Date(svc.now()).toISOString().replace(/[:.]/g, '-');
    res.set('Content-Disposition', `attachment; filename="vaultshare-audit-${stamp}.json"`);
    res.json({
      export: 'VaultShare audit trail',
      exportedAt: new Date(svc.now()).toISOString(),
      exportedBy: req.user.username,
      hashAlgorithm: 'HMAC-SHA256(auditKey, prev_hash || "|" || canonical_json(event))',
      verification,
      head: events.length ? { seq: events[events.length - 1].seq, hash: events[events.length - 1].hash } : null,
      events,
    });
  });

  // ---------- watermark trace ----------
  r.post('/trace', requirePerm('watermark.trace'), (req, res) => {
    const started = performance.now();
    const body = validate({ payload: v.str({ min: 10, max: 120 }) }, req.body);
    const parsed = parsePayload(body.payload);
    const record = parsed ? svc.repos.downloads.byId(parsed.downloadId) : null;
    const result = verifyPayload(svc.secrets.watermarkKey, body.payload, record);
    const evidence = result.valid
      ? {
          downloadId: record.id,
          recipient: record.username,
          recipientRole: record.role,
          document: record.filename,
          documentOwner: record.owner_name,
          grantId: record.grant_id,
          downloadedAt: new Date(record.created_at).toISOString(),
        }
      : { payloadPrefix: body.payload.slice(0, 12) };
    const rec = svc.decide(req, { action: 'watermark_trace', subjectType: 'download', subjectId: parsed?.downloadId ?? null, subjectLabel: 'leak trace' }, { decision: result.valid ? 'allow' : 'deny', rule: result.rule, reason: result.reason, evidence, engine: 'vaultshare-watermark/1.0.0' }, started);
    req.audit('WATERMARK_TRACE', result.valid ? 'success' : 'denied', { targetType: 'download', targetId: parsed?.downloadId ?? null, details: { rule: result.rule, decisionId: rec.id } });
    res.json({ ...result, evidence, severity: rec.severity, recommendedAction: rec.recommendedAction, decisionId: rec.id });
  });

  return r;
}
