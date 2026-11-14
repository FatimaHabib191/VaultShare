// FR-1 (accounts and roles): sign-in, enrollment (key creation), sign-out, password change.
import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import { AppError } from '../../lib/errors.js';
import { validate, v, USERNAME } from '../../engine/validation.js';
import { hashAuthKey, verifyAuthKey, hashCode, sha256 } from '../../lib/passwords.js';
import { hmacHex } from '../../lib/secrets.js';
import { SESSION_COOKIE, cookieOptions, requireAuth, asyncH } from '../middleware.js';
import { publicKeyFingerprint, importPublicKey, RSA_MODULUS_BITS, GCM_IV_BYTES } from '../../../shared/crypto-core.js';

const AUTHKEY = v.b64({ exactBytes: 32 });
const WRAPPED_PRIV = v.b64({ minBytes: 1000, maxBytes: 2000 });
const IV = v.b64({ exactBytes: GCM_IV_BYTES });
const SPKI = v.b64({ minBytes: 200, maxBytes: 600 });

export function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, status: u.status, keyFingerprint: u.key_fingerprint, keyVersion: u.key_version };
}

async function checkPublicKey(spkiB64) {
  try {
    const key = await importPublicKey(spkiB64);
    const alg = key.algorithm;
    const exp = Array.from(alg.publicExponent).join(',');
    if (alg.modulusLength !== RSA_MODULUS_BITS || exp !== '1,0,1' || alg.hash.name !== 'SHA-256') return false;
    return true;
  } catch {
    return false;
  }
}

export default function authRoutes(svc, limit) {
  const r = Router();
  const loginLimit = limit('login', {
    windowMs: 15 * 60_000,
    limitFn: () => svc.settings().login_attempts_per_15min,
    keyFn: (req) => `${req.ipHash}:${String(req.body?.username || '').toLowerCase().slice(0, 40)}`,
  });
  const enrollLimit = limit('enroll', {
    windowMs: 15 * 60_000,
    limitFn: () => svc.settings().login_attempts_per_15min,
    keyFn: (req) => `${req.ipHash}:${String(req.body?.username || '').toLowerCase().slice(0, 40)}`,
  });

  function startSession(res, user) {
    const cfg = svc.settings();
    const token = randomBytes(32).toString('base64url');
    const csrf = randomBytes(32).toString('base64url');
    const ttl = cfg.session_absolute_hours * 3_600_000;
    svc.repos.sessions.create({ id_hash: sha256(token), user_id: user.id, csrf_token: csrf, expires_at: svc.now() + ttl });
    res.cookie(SESSION_COOKIE, token, cookieOptions(svc, ttl));
    return csrf;
  }

  // Step 1 of sign-in: fetch KDF parameters. Unknown or pending users receive a
  // deterministic decoy salt so the response does not reveal who has an account.
  // Separate counter so one sign-in (prelogin + login) counts as one attempt.
  const preloginLimit = limit('prelogin', {
    windowMs: 15 * 60_000,
    limitFn: () => svc.settings().login_attempts_per_15min * 3,
    keyFn: (req) => `${req.ipHash}:${String(req.body?.username || '').toLowerCase().slice(0, 40)}`,
  });
  r.post('/prelogin', preloginLimit, (req, res) => {
    const { username } = validate({ username: v.str(USERNAME) }, { username: String(req.body?.username ?? '').toLowerCase() });
    const u = svc.repos.users.byUsername(username);
    if (u && u.status === 'active') return res.json({ kdfSalt: u.kdf_salt, kdfIterations: u.kdf_iterations, userId: u.id });
    const fake = Buffer.from(hmacHex(svc.secrets.lookupKey, `salt:${username}`, 32), 'hex').toString('base64');
    const fakeId = hmacHex(svc.secrets.lookupKey, `id:${username}`, 30).replace(/^(.{8})(.{4})(.{3})(.{3})(.{12})$/, '$1-$2-4$3-a$4-$5');
    res.json({ kdfSalt: fake, kdfIterations: svc.settings().kdf_iterations, userId: fakeId });
  });

  r.post(
    '/login',
    loginLimit,
    asyncH(async (req, res) => {
      const body = validate({ username: v.str(USERNAME), authKey: AUTHKEY }, { ...req.body, username: String(req.body?.username ?? '').toLowerCase() });
      const u = svc.repos.users.byUsername(body.username);
      const ok = await verifyAuthKey(body.authKey, u);
      if (!ok || u.status !== 'active') {
        req.audit('AUTH_LOGIN_FAILURE', 'denied', {
          actorName: body.username,
          details: { reason: !u ? 'unknown_user' : u.status !== 'active' ? `status_${u.status}` : 'bad_credentials' },
        });
        throw new AppError('AUTH_FAILED');
      }
      const csrfToken = startSession(res, u);
      svc.repos.users.touchLogin(u.id);
      req.audit('AUTH_LOGIN_SUCCESS', 'success', { actor: u });
      res.json({ user: publicUser(u), csrfToken, keys: { wrappedPrivateKey: u.wrapped_private_key, wrapIv: u.wrap_iv, publicKey: u.public_key } });
    })
  );

  r.post('/logout', (req, res) => {
    if (req.user) {
      svc.repos.sessions.delete(req.sessionIdHash);
      req.audit('AUTH_LOGOUT', 'success');
    }
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  });

  // Returns 200 with user:null when signed out, so the client can probe without errors.
  r.get('/me', (req, res) => {
    if (!req.user) return res.json({ user: null, sessionExpired: !!req.sessionExpired });
    const u = req.user;
    res.json({
      user: publicUser(u),
      csrfToken: req.session.csrf_token,
      kdf: { kdfSalt: u.kdf_salt, kdfIterations: u.kdf_iterations },
      keys: { wrappedPrivateKey: u.wrapped_private_key, wrapIv: u.wrap_iv, publicKey: u.public_key },
      session: { idleMinutes: svc.settings().session_idle_minutes, expiresAt: new Date(req.session.expires_at).toISOString() },
    });
  });

  function checkCode(username, code) {
    const u = svc.repos.users.byUsername(username);
    const valid = u && u.status === 'pending' && u.enroll_code_hash && u.enroll_code_hash === hashCode(code) && u.enroll_expires_at > svc.now();
    return valid ? u : null;
  }

  const CODE = v.str({ min: 16, max: 24, pattern: /^[A-Za-z0-9-]+$/ });

  r.post('/enroll/start', enrollLimit, (req, res) => {
    const body = validate({ username: v.str(USERNAME), code: CODE }, { ...req.body, username: String(req.body?.username ?? '').toLowerCase() });
    const u = checkCode(body.username, body.code);
    if (!u) {
      req.audit('AUTH_ENROLL_FAILURE', 'denied', { actorName: body.username, details: { stage: 'start' } });
      throw new AppError('ENROLLMENT_INVALID');
    }
    res.json({ userId: u.id, role: u.role, kdfSalt: u.kdf_salt, kdfIterations: u.kdf_iterations });
  });

  r.post(
    '/enroll/complete',
    enrollLimit,
    asyncH(async (req, res) => {
      const body = validate(
        { username: v.str(USERNAME), code: CODE, authKey: AUTHKEY, publicKey: SPKI, wrappedPrivateKey: WRAPPED_PRIV, wrapIv: IV },
        { ...req.body, username: String(req.body?.username ?? '').toLowerCase() }
      );
      const u = checkCode(body.username, body.code);
      if (!u) {
        req.audit('AUTH_ENROLL_FAILURE', 'denied', { actorName: body.username, details: { stage: 'complete' } });
        throw new AppError('ENROLLMENT_INVALID');
      }
      if (!(await checkPublicKey(body.publicKey))) {
        throw new AppError('VALIDATION_FAILED', { details: [{ field: 'publicKey', rule: 'KEY_PARAMS', message: `must be RSA-OAEP ${RSA_MODULUS_BITS}-bit, e=65537, SHA-256` }] });
      }
      const fingerprint = await publicKeyFingerprint(body.publicKey);
      const h = await hashAuthKey(body.authKey);
      const changed = svc.repos.users.completeEnrollment({
        id: u.id,
        ...h,
        public_key: body.publicKey,
        key_fingerprint: fingerprint,
        wrapped_private_key: body.wrappedPrivateKey,
        wrap_iv: body.wrapIv,
      }).changes;
      if (changed !== 1) throw new AppError('ENROLLMENT_INVALID');
      const fresh = svc.repos.users.byId(u.id);
      req.audit('AUTH_ENROLL', 'success', { actor: fresh, targetType: 'user', targetId: u.id, details: { keyVersion: fresh.key_version, fingerprint: fingerprint.slice(0, 16) } });
      const csrfToken = startSession(res, fresh);
      req.audit('AUTH_LOGIN_SUCCESS', 'success', { actor: fresh, details: { via: 'enrollment' } });
      res.status(201).json({ user: publicUser(fresh), csrfToken, keys: { wrappedPrivateKey: fresh.wrapped_private_key, wrapIv: fresh.wrap_iv, publicKey: fresh.public_key } });
    })
  );

  r.post(
    '/password',
    requireAuth,
    loginLimit,
    asyncH(async (req, res) => {
      const body = validate({ currentAuthKey: AUTHKEY, newAuthKey: AUTHKEY, wrappedPrivateKey: WRAPPED_PRIV, wrapIv: IV }, req.body);
      if (!(await verifyAuthKey(body.currentAuthKey, req.user))) {
        req.audit('AUTH_PASSWORD_CHANGE', 'denied', { details: { reason: 'bad_current_password' } });
        throw new AppError('AUTH_FAILED', { message: 'Current password is incorrect.' });
      }
      const h = await hashAuthKey(body.newAuthKey);
      svc.repos.users.changePassword({ id: req.user.id, ...h, wrapped_private_key: body.wrappedPrivateKey, wrap_iv: body.wrapIv });
      // end every other session for this user
      const ended = svc.repos.sessions.deleteForUser(req.user.id);
      const csrfToken = startSession(res, req.user);
      req.audit('AUTH_PASSWORD_CHANGE', 'success', { details: { sessionsEnded: ended } });
      res.json({ ok: true, csrfToken });
    })
  );

  return r;
}
