// Composition root: wires the repository layer, security engine and API layer.
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { openDatabase } from './repo/db.js';
import { createRepos } from './repo/repos.js';
import { createAuditLog } from './engine/audit.js';
import { loadSecrets } from './lib/secrets.js';
import { redact } from './engine/redact.js';
import { AppError } from './lib/errors.js';
import { ruleMeta } from './engine/policy.js';
import {
  requestContext,
  securityHeaders,
  loadSession,
  csrfProtection,
  requireAuth,
  rateLimiter,
  errorHandler,
} from './api/middleware.js';
import authRoutes from './api/routes/auth.js';
import documentRoutes from './api/routes/documents.js';
import adminRoutes from './api/routes/admin.js';
import { directoryRoutes, grantRoutes, decisionRoutes, reportRoutes } from './api/routes/sharing.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * @param {object} opts
 * @param {string} opts.dataDir   directory for vaultshare.db, secrets.json, audit-anchor.json
 * @param {() => number} [opts.now] injectable clock (ms) for expiry tests
 * @param {boolean} [opts.testMode] relaxes KDF minimums for fast tests
 */
export function createApp({ dataDir = path.join(ROOT, 'data'), now = () => Date.now(), testMode = false, quiet = false, secureCookies = false } = {}) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const db = openDatabase(path.join(dataDir, 'vaultshare.db'));
  const secrets = loadSecrets(dataDir);
  const repos = createRepos(db, { now });
  repos.settings.ensureDefaults({ testMode });
  const audit = createAuditLog(db, { key: secrets.auditKey, anchorPath: path.join(dataDir, 'audit-anchor.json'), now });

  let cached = repos.settings.current();
  const svc = {
    db,
    repos,
    audit,
    secrets,
    now,
    testMode,
    quiet,
    secureCookies,
    settings: () => cached.values,
    settingsVersion: () => cached.version,
    reloadSettings: () => {
      cached = repos.settings.current();
    },
    /** Persist an explainable decision and return the stored record. */
    decide(req, { action, subjectType = null, subjectId = null, subjectLabel = null }, d, started) {
      const rec = {
        id: randomUUID(),
        ts: now(),
        actor_id: req.user?.id ?? null,
        actor_name: req.user?.username ?? null,
        action,
        subject_type: subjectType,
        subject_id: subjectId,
        subject_label: subjectLabel,
        decision: d.decision,
        rule: d.rule,
        reason: d.reason,
        severity: d.severity || ruleMeta(d.rule).severity,
        recommended_action: d.recommendedAction || ruleMeta(d.rule).recommendedAction,
        evidence: JSON.stringify(redact(d.evidence || {})),
        engine: d.engine,
        config_version: cached.version,
        latency_ms: performance.now() - (started ?? performance.now()),
        request_id: req.id,
      };
      repos.decisions.insert(rec);
      return { id: rec.id, decision: rec.decision, rule: rec.rule, reason: rec.reason, severity: rec.severity, recommendedAction: rec.recommended_action, evidence: JSON.parse(rec.evidence), engine: rec.engine, configVersion: rec.config_version, latencyMs: rec.latency_ms };
    },
  };

  // Recovery after restart: drop expired sessions and abandoned half-uploads.
  const purgedSessions = repos.sessions.purgeExpired(cached.values.session_idle_minutes * 60_000);
  const purgedUploads = repos.documents.purgeStalePending(60 * 60_000);
  const startupCheck = audit.verify({ updateAnchor: false });
  audit.append({ action: 'SYSTEM_START', outcome: startupCheck.ok ? 'success' : 'error', details: { purgedSessions, purgedUploads, auditChain: startupCheck.rule, settingsVersion: cached.version } });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  const limit = rateLimiter(svc);

  app.use(requestContext(svc));
  app.use(securityHeaders);

  // Static client (no server-side templates; CSP forbids inline script)
  const staticOpts = { index: false, fallthrough: true, maxAge: 0, dotfiles: 'deny' };
  app.use('/shared', express.static(path.join(ROOT, 'shared'), staticOpts));
  app.get('/vendor/pdf-lib.esm.min.js', (req, res) => res.sendFile(path.join(ROOT, 'node_modules/pdf-lib/dist/pdf-lib.esm.min.js')));
  const fonts = {
    'atkinson-400.woff2': '@fontsource/atkinson-hyperlegible/files/atkinson-hyperlegible-latin-400-normal.woff2',
    'atkinson-700.woff2': '@fontsource/atkinson-hyperlegible/files/atkinson-hyperlegible-latin-700-normal.woff2',
    'plexmono-400.woff2': '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2',
    'plexmono-500.woff2': '@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2',
    'inter-400.woff2': '@fontsource/inter/files/inter-latin-400-normal.woff2',
    'inter-500.woff2': '@fontsource/inter/files/inter-latin-500-normal.woff2',
    'inter-600.woff2': '@fontsource/inter/files/inter-latin-600-normal.woff2',
    'inter-700.woff2': '@fontsource/inter/files/inter-latin-700-normal.woff2',
  };
  app.get('/fonts/:name', (req, res, next) => {
    const f = fonts[req.params.name];
    if (!f) return next();
    res.set('Cache-Control', 'public, max-age=604800');
    res.sendFile(path.join(ROOT, 'node_modules', f));
  });
  app.use(express.static(path.join(ROOT, 'public'), staticOpts));

  // API
  const api = express.Router();
  api.use(express.json({ limit: '32mb', strict: true }));
  api.use(loadSession(svc));
  api.use(csrfProtection);
  api.get('/health', (req, res) => res.json({ ok: true, settingsVersion: svc.settingsVersion() }));
  api.use('/auth', authRoutes(svc, limit));
  api.use('/documents', requireAuth, documentRoutes(svc, limit));
  api.use('/directory', requireAuth, directoryRoutes(svc));
  api.use('/grants', requireAuth, grantRoutes(svc));
  api.use('/decisions', requireAuth, decisionRoutes(svc));
  api.use('/reports', requireAuth, reportRoutes(svc));
  api.use('/admin', requireAuth, adminRoutes(svc));
  api.use((req, res, next) => next(new AppError('NOT_FOUND')));
  app.use('/api', api);

  // SPA fallback
  app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(ROOT, 'public', 'index.html')));
  app.use(errorHandler(svc));

  return { app, svc, close: () => db.close() };
}
