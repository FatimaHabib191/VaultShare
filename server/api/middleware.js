// API-layer middleware: request ids, security headers, sessions, CSRF, origin
// checks, role permissions, rate limiting and safe error responses.
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { AppError } from '../lib/errors.js';
import { can } from '../engine/access.js';
import { sha256 } from '../lib/passwords.js';
import { hmacHex } from '../lib/secrets.js';

export const SESSION_COOKIE = 'vs_sid';

export function requestContext(svc) {
  return (req, res, next) => {
    req.id = randomUUID();
    req.started = performance.now();
    req.ipHash = hmacHex(svc.secrets.lookupKey, req.socket.remoteAddress || 'unknown', 16);
    res.set('X-Request-Id', req.id);
    req.audit = (action, outcome, extra = {}) =>
      svc.audit.append({
        actor_id: extra.actor?.id ?? req.user?.id ?? null,
        actor_name: extra.actor?.username ?? req.user?.username ?? extra.actorName ?? null,
        actor_role: extra.actor?.role ?? req.user?.role ?? null,
        action,
        target_type: extra.targetType ?? null,
        target_id: extra.targetId ?? null,
        outcome,
        request_id: req.id,
        ip_hash: req.ipHash,
        details: extra.details ?? {},
      });
    next();
  };
}

export function securityHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  });
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

export function cookieOptions(svc, maxAgeMs) {
  return { httpOnly: true, sameSite: 'strict', secure: svc.secureCookies, path: '/', maxAge: maxAgeMs };
}

export function loadSession(svc) {
  return (req, res, next) => {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return next();
    const idHash = sha256(token);
    const s = svc.repos.sessions.get(idHash);
    if (!s) return next();
    const cfg = svc.settings();
    const t = svc.now();
    const idleMs = cfg.session_idle_minutes * 60_000;
    if (t >= s.expires_at || t - s.last_seen_at >= idleMs) {
      svc.repos.sessions.delete(idHash);
      req.sessionExpired = true;
      const u = svc.repos.users.byId(s.user_id);
      req.audit('SESSION_EXPIRED', 'info', { actor: u, details: { reason: t >= s.expires_at ? 'absolute' : 'idle' } });
      res.clearCookie(SESSION_COOKIE, { path: '/' });
      return next();
    }
    const user = svc.repos.users.byId(s.user_id);
    if (!user || user.status !== 'active') {
      svc.repos.sessions.delete(idHash);
      return next();
    }
    svc.repos.sessions.touch(idHash);
    req.session = s;
    req.sessionIdHash = idHash;
    req.user = user;
    next();
  };
}

export function requireAuth(req, res, next) {
  if (!req.user) return next(new AppError(req.sessionExpired ? 'SESSION_EXPIRED' : 'AUTH_REQUIRED'));
  next();
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * CSRF defence in depth:
 *  1. SameSite=Strict session cookie;
 *  2. state-changing requests must be application/json (forces a CORS preflight cross-site);
 *  3. Origin header, when present, must match Host;
 *  4. authenticated requests must echo the per-session synchronizer token in X-CSRF-Token.
 */
export function csrfProtection(req, res, next) {
  if (!UNSAFE.has(req.method)) return next();
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try {
      host = new URL(origin).host;
    } catch {
      host = null;
    }
    if (host !== req.headers.host) {
      req.audit('CSRF_REJECTED', 'denied', { details: { reason: 'origin_mismatch', origin: String(origin).slice(0, 100), path: req.path } });
      return next(new AppError('CSRF_FAILED'));
    }
  }
  if (!req.is('application/json')) {
    return next(new AppError('VALIDATION_FAILED', { details: [{ field: 'Content-Type', rule: 'TYPE', message: 'must be application/json' }] }));
  }
  if (req.user) {
    const got = Buffer.from(String(req.headers['x-csrf-token'] || ''));
    const want = Buffer.from(req.session.csrf_token);
    if (got.length !== want.length || !timingSafeEqual(got, want)) {
      req.audit('CSRF_REJECTED', 'denied', { details: { reason: 'token_mismatch', path: req.path } });
      return next(new AppError('CSRF_FAILED'));
    }
  }
  next();
}

export function requirePerm(action) {
  return (req, res, next) => {
    if (!req.user) return next(new AppError('AUTH_REQUIRED'));
    if (!can(req.user.role, action)) {
      req.audit('ACCESS_DENIED', 'denied', { details: { permission: action, method: req.method, path: req.path } });
      return next(new AppError('FORBIDDEN'));
    }
    next();
  };
}

/** Fixed-window in-memory limiter. limitFn reads the live (admin-configurable) limit. */
export function rateLimiter(svc) {
  const buckets = new Map();
  return function limit(name, { windowMs, limitFn, keyFn }) {
    return (req, res, next) => {
      const key = `${name}:${keyFn(req)}`;
      const t = svc.now();
      let b = buckets.get(key);
      if (!b || t - b.start >= windowMs) {
        b = { start: t, count: 0 };
        buckets.set(key, b);
      }
      b.count++;
      if (buckets.size > 10_000) for (const [k, v] of buckets) if (t - v.start >= windowMs) buckets.delete(k);
      const lim = limitFn();
      if (b.count > lim) {
        const retryAfter = Math.ceil((b.start + windowMs - t) / 1000);
        res.set('Retry-After', String(retryAfter));
        if (b.count === lim + 1) req.audit('RATE_LIMITED', 'denied', { details: { limiter: name, limit: lim, windowSeconds: windowMs / 1000 } });
        return next(new AppError('RATE_LIMITED', { retryAfter }));
      }
      next();
    };
  };
}

export function errorHandler(svc) {
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, next) => {
    let e = err;
    if (!(e instanceof AppError)) {
      if (err?.type === 'entity.parse.failed') e = new AppError('MALFORMED_JSON');
      else if (err?.type === 'entity.too.large') e = new AppError('PAYLOAD_TOO_LARGE');
      else {
        e = new AppError('INTERNAL_ERROR');
        if (!svc.quiet) console.error(`[${req.id}]`, err);
        try {
          req.audit?.('SERVER_ERROR', 'error', { details: { path: req.path, method: req.method, kind: err?.name || 'Error' } });
        } catch {
          /* never let logging failures mask the response */
        }
      }
    }
    if (e.code === 'VALIDATION_FAILED' || e.code === 'MALFORMED_JSON' || e.code === 'PAYLOAD_TOO_LARGE') {
      try {
        req.audit?.('REQUEST_REJECTED', 'denied', { details: { code: e.code, path: req.path, fields: (e.details || []).map((d) => `${d.field}:${d.rule}`).slice(0, 10) } });
      } catch {
        /* ignore */
      }
    }
    const body = { error: { code: e.code, message: e.message, requestId: req.id } };
    if (e.details) body.error.details = e.details;
    if (e.decision) body.error.decision = e.decision;
    if (e.retryAfter) body.error.retryAfter = e.retryAfter;
    res.status(e.status).json(body);
  };
}

export const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
