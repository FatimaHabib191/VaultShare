// Directory (recipient public keys), grant revocation, decision history and report export.
import { Router } from 'express';
import { AppError } from '../../lib/errors.js';
import { validate, v, UUID_RE } from '../../engine/validation.js';
import { requirePerm } from '../middleware.js';
import { can } from '../../engine/access.js';
import { redact } from '../../engine/redact.js';

export function directoryRoutes(svc) {
  const r = Router();
  r.get('/', requirePerm('directory.read'), (req, res) => {
    res.json({
      users: svc.repos.users
        .directory()
        .filter((u) => u.id !== req.user.id)
        .map((u) => ({ id: u.id, username: u.username, role: u.role, keyFingerprint: u.key_fingerprint, keyVersion: u.key_version })),
    });
  });
  r.get('/:id/public-key', requirePerm('directory.read'), (req, res) => {
    if (!UUID_RE.test(req.params.id)) throw new AppError('NOT_FOUND');
    const u = svc.repos.users.byId(req.params.id);
    if (!u || u.status !== 'active' || !u.public_key || u.role === 'admin') throw new AppError('NOT_FOUND');
    res.json({ id: u.id, username: u.username, publicKey: u.public_key, keyFingerprint: u.key_fingerprint, keyVersion: u.key_version });
  });
  return r;
}

export function grantRoutes(svc) {
  const r = Router();
  // Owner revokes their share; admin may revoke any share for incident response.
  r.post('/:id/revoke', requirePerm('grant.revoke'), (req, res) => {
    if (!UUID_RE.test(req.params.id)) throw new AppError('NOT_FOUND');
    const body = validate({ confirm: v.oneOf([true]), reason: v.optional(v.str({ min: 1, max: 200 })) }, req.body);
    const g = svc.repos.grants.byId(req.params.id);
    const doc = g && svc.repos.documents.byId(g.document_id);
    const isOwner = doc && doc.owner_id === req.user.id;
    if (!g || g.is_owner || !(isOwner || req.user.role === 'admin')) {
      req.audit('ACCESS_DENIED', 'denied', { targetType: 'grant', targetId: req.params.id, details: { permission: 'grant.revoke' } });
      throw new AppError('NOT_FOUND');
    }
    if (g.revoked_at) throw new AppError('CONFLICT', { message: 'This share was already revoked.' });
    svc.repos.grants.revoke(g.id, req.user.id, body.reason ?? null);
    const recipient = svc.repos.users.byId(g.recipient_id);
    req.audit('GRANT_REVOKE', 'success', {
      targetType: 'grant',
      targetId: g.id,
      details: { documentId: g.document_id, filename: doc.filename, recipient: recipient?.username, reason: body.reason ?? null, byAdmin: !isOwner },
    });
    res.json({ ok: true, revokedAt: new Date(svc.now()).toISOString() });
  });
  return r;
}

function decisionView(d) {
  return {
    id: d.id,
    ts: new Date(d.ts).toISOString(),
    actor: d.actor_name,
    action: d.action,
    subjectType: d.subject_type,
    subjectId: d.subject_id,
    subject: d.subject_label,
    decision: d.decision,
    rule: d.rule,
    reason: d.reason,
    severity: d.severity,
    recommendedAction: d.recommended_action,
    evidence: d.evidence,
    engine: d.engine,
    configVersion: d.config_version,
    latencyMs: Math.round(d.latency_ms * 1000) / 1000,
  };
}

function parseFilters(q) {
  const f = {};
  if (q.decision && ['allow', 'deny', 'info'].includes(q.decision)) f.decision = q.decision;
  if (q.rule && /^[A-Z_]{3,40}$/.test(q.rule)) f.rule = q.rule;
  if (q.action && /^[a-z_]{3,30}$/.test(q.action)) f.action = q.action;
  if (q.severity && ['info', 'low', 'medium', 'high'].includes(q.severity)) f.severity = q.severity;
  if (q.from && !Number.isNaN(Date.parse(q.from))) f.from = Date.parse(q.from);
  if (q.to && !Number.isNaN(Date.parse(q.to))) f.to = Date.parse(q.to);
  if (q.limit && /^\d{1,4}$/.test(q.limit)) f.limit = Number(q.limit);
  return f;
}

export function decisionRoutes(svc) {
  const r = Router();
  r.get('/', requirePerm('decision.read_own'), (req, res) => {
    const f = parseFilters(req.query);
    const all = req.query.scope === 'all' && can(req.user.role, 'decision.read_all');
    if (!all) f.actorId = req.user.id;
    else if (typeof req.query.actor === 'string' && /^[a-z][a-z0-9._-]{2,31}$/.test(req.query.actor)) {
      const u = svc.repos.users.byUsername(req.query.actor);
      f.actorId = u ? u.id : '__none__';
    }
    res.json({ decisions: svc.repos.decisions.query(f).map(decisionView) });
  });
  return r;
}

const CSV_COLS = ['ts', 'actor', 'action', 'subject', 'decision', 'severity', 'rule', 'reason', 'recommendedAction', 'configVersion', 'latencyMs', 'id'];
const csvCell = (val) => {
  let s = val == null ? '' : String(val);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // neutralise spreadsheet formula injection
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function reportRoutes(svc) {
  const r = Router();
  r.get('/export', requirePerm('report.export_own'), (req, res) => {
    const all = req.query.scope === 'all' && can(req.user.role, 'report.export_all');
    const f = parseFilters(req.query);
    if (!all) f.actorId = req.user.id;
    f.limit = Math.min(f.limit || 1000, 1000);
    const decisions = svc.repos.decisions.query(f).map(decisionView).map((d) => redact(d));
    const summary = {};
    for (const d of decisions) {
      const k = `${d.action}:${d.decision}:${d.rule}`;
      summary[k] = summary[k] || { action: d.action, decision: d.decision, rule: d.rule, severity: d.severity, count: 0, totalMs: 0 };
      summary[k].count++;
      summary[k].totalMs += d.latencyMs;
    }
    const verification = all ? svc.audit.verify({ updateAnchor: false }) : null;
    req.audit('REPORT_EXPORT', 'success', { details: { scope: all ? 'all' : 'own', format: req.query.format === 'csv' ? 'csv' : 'json', rows: decisions.length } });
    const stamp = new Date(svc.now()).toISOString().replace(/[:.]/g, '-');
    if (req.query.format === 'csv') {
      res.set('Content-Type', 'text/csv; charset=utf-8');
      res.set('Content-Disposition', `attachment; filename="vaultshare-decisions-${stamp}.csv"`);
      return res.send([CSV_COLS.join(','), ...decisions.map((d) => CSV_COLS.map((c) => csvCell(d[c])).join(','))].join('\n'));
    }
    res.set('Content-Disposition', `attachment; filename="vaultshare-report-${stamp}.json"`);
    res.json({
      report: 'VaultShare decision report',
      generatedAt: new Date(svc.now()).toISOString(),
      generatedBy: req.user.username,
      scope: all ? 'all users' : `own decisions (${req.user.username})`,
      configVersion: svc.settingsVersion(),
      sanitization: 'No plaintext, ciphertext, wrapped keys, passwords, session tokens or IP addresses are included.',
      summary: Object.values(summary).map((s) => ({ ...s, avgMs: Math.round((s.totalMs / s.count) * 1000) / 1000, totalMs: undefined })),
      auditVerification: verification,
      decisions,
    });
  });
  return r;
}
