// Repository functions: the only place SQL lives. Every statement is prepared
// once and bound with named/positional parameters (no string concatenation of input).
import { defaultSettings } from '../engine/settings.js';

export function createRepos(db, { now }) {
  const S = (sql) => db.prepare(sql);

  // ---------- users ----------
  const users = {
    byId: (id) => S('SELECT * FROM users WHERE id = ?').get(id),
    byUsername: (u) => S('SELECT * FROM users WHERE username = ?').get(u),
    count: () => S('SELECT COUNT(*) n FROM users').get().n,
    list: () =>
      S(`SELECT id, username, role, status, key_fingerprint, key_version, created_at, updated_at, last_login_at, enroll_expires_at
         FROM users ORDER BY role, username`).all(),
    directory: () =>
      S(`SELECT id, username, role, key_fingerprint, key_version FROM users
         WHERE status = 'active' AND public_key IS NOT NULL AND role != 'admin' ORDER BY username`).all(),
    create: (u) =>
      S(`INSERT INTO users (id, username, role, status, kdf_salt, kdf_iterations, enroll_code_hash, enroll_expires_at, created_at, updated_at)
         VALUES (@id, @username, @role, 'pending', @kdf_salt, @kdf_iterations, @enroll_code_hash, @enroll_expires_at, @ts, @ts)`).run({ ...u, ts: now() }),
    completeEnrollment: (u) =>
      S(`UPDATE users SET status = 'active', auth_hash = @auth_hash, auth_salt = @auth_salt, public_key = @public_key,
           key_fingerprint = @key_fingerprint, wrapped_private_key = @wrapped_private_key, wrap_iv = @wrap_iv,
           key_version = key_version + 1, enroll_code_hash = NULL, enroll_expires_at = NULL, updated_at = @ts
         WHERE id = @id AND status = 'pending'`).run({ ...u, ts: now() }),
    resetKeys: (u) =>
      S(`UPDATE users SET status = 'pending', auth_hash = NULL, auth_salt = NULL, public_key = NULL, key_fingerprint = NULL,
           wrapped_private_key = NULL, wrap_iv = NULL, kdf_salt = @kdf_salt, kdf_iterations = @kdf_iterations,
           enroll_code_hash = @enroll_code_hash, enroll_expires_at = @enroll_expires_at, updated_at = @ts
         WHERE id = @id`).run({ ...u, ts: now() }),
    setStatus: (id, status) => S('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').run(status, now(), id),
    setRole: (id, role) => S('UPDATE users SET role = ?, updated_at = ? WHERE id = ?').run(role, now(), id),
    touchLogin: (id) => S('UPDATE users SET last_login_at = ? WHERE id = ?').run(now(), id),
    changePassword: (u) =>
      S(`UPDATE users SET auth_hash = @auth_hash, auth_salt = @auth_salt, wrapped_private_key = @wrapped_private_key,
           wrap_iv = @wrap_iv, updated_at = @ts WHERE id = @id AND status = 'active'`).run({ ...u, ts: now() }),
  };

  // ---------- sessions ----------
  const sessions = {
    create: (s) =>
      S(`INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)
         VALUES (@id_hash, @user_id, @csrf_token, @ts, @ts, @expires_at)`).run({ ...s, ts: now() }),
    get: (idHash) => S('SELECT * FROM sessions WHERE id_hash = ?').get(idHash),
    touch: (idHash) => S('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?').run(now(), idHash),
    delete: (idHash) => S('DELETE FROM sessions WHERE id_hash = ?').run(idHash),
    deleteForUser: (userId) => S('DELETE FROM sessions WHERE user_id = ?').run(userId).changes,
    purgeExpired: (idleMs) => S('DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?').run(now(), now() - idleMs).changes,
  };

  // ---------- settings ----------
  const settings = {
    current: () => {
      const row = S('SELECT * FROM settings_versions ORDER BY version DESC LIMIT 1').get();
      return row ? { version: row.version, values: JSON.parse(row.settings) } : null;
    },
    history: (limit = 50) =>
      S(`SELECT v.version, v.diff, v.reason, v.changed_at, u.username AS changed_by
         FROM settings_versions v LEFT JOIN users u ON u.id = v.changed_by ORDER BY v.version DESC LIMIT ?`)
        .all(limit)
        .map((r) => ({ ...r, diff: JSON.parse(r.diff) })),
    insert: ({ version, values, diff, reason, changedBy }) =>
      S('INSERT INTO settings_versions (version, settings, diff, reason, changed_by, changed_at) VALUES (?, ?, ?, ?, ?, ?)').run(
        version,
        JSON.stringify(values),
        JSON.stringify(diff),
        reason ?? null,
        changedBy ?? null,
        now()
      ),
    ensureDefaults: (env) => {
      if (!settings.current()) settings.insert({ version: 1, values: defaultSettings(env), diff: {}, reason: 'initial defaults', changedBy: null });
    },
  };

  // ---------- documents ----------
  const DOC_COLS = 'd.id, d.owner_id, d.filename, d.extension, d.mime_type, d.size_plain, d.size_cipher, d.cipher_sha256, d.binding, d.status, d.created_at, d.uploaded_at, d.deleted_at';
  const documents = {
    create: (d) =>
      S(`INSERT INTO documents (id, owner_id, filename, extension, mime_type, size_plain, binding, status, config_version, created_at)
         VALUES (@id, @owner_id, @filename, @extension, @mime_type, @size_plain, @binding, 'pending', @config_version, @ts)`).run({ ...d, ts: now() }),
    byId: (id) => S(`SELECT ${DOC_COLS}, u.username AS owner_name FROM documents d JOIN users u ON u.id = d.owner_id WHERE d.id = ?`).get(id),
    content: (id) => {
      const c = S("SELECT content FROM documents WHERE id = ? AND status = 'active'").get(id)?.content;
      return c ? Buffer.from(c) : null;
    },
    activate: (d) =>
      S(`UPDATE documents SET status = 'active', content = @content, size_cipher = @size_cipher, cipher_sha256 = @cipher_sha256, uploaded_at = @ts
         WHERE id = @id AND status = 'pending'`).run({ ...d, ts: now() }),
    softDelete: (id) =>
      S(`UPDATE documents SET status = 'deleted', content = NULL, deleted_at = ? WHERE id = ? AND status != 'deleted'`).run(now(), id),
    purgeStalePending: (olderThanMs) =>
      S("DELETE FROM documents WHERE status = 'pending' AND created_at < ? AND id NOT IN (SELECT document_id FROM grants)").run(now() - olderThanMs).changes,
    owned: (ownerId) =>
      S(`SELECT ${DOC_COLS},
           (SELECT COUNT(*) FROM grants g WHERE g.document_id = d.id AND g.is_owner = 0 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > @now) AND g.download_count < g.max_downloads) AS active_shares
         FROM documents d WHERE d.owner_id = @ownerId AND d.status = 'active' ORDER BY d.created_at DESC`).all({ ownerId, now: now() }),
    sharedWith: (userId) =>
      S(`SELECT ${DOC_COLS}, u.username AS owner_name, g.id AS grant_id, g.expires_at, g.max_downloads, g.download_count, g.revoked_at,
           g.recipient_key_version, g.recipient_key_fingerprint, g.created_at AS shared_at
         FROM grants g JOIN documents d ON d.id = g.document_id JOIN users u ON u.id = d.owner_id
         WHERE g.recipient_id = ? AND g.is_owner = 0 AND d.status != 'pending'
           AND g.created_at = (SELECT MAX(g2.created_at) FROM grants g2 WHERE g2.document_id = g.document_id AND g2.recipient_id = g.recipient_id AND g2.is_owner = 0)
         ORDER BY g.created_at DESC`).all(userId),
  };

  // ---------- grants ----------
  const grants = {
    create: (g) =>
      S(`INSERT INTO grants (id, document_id, recipient_id, granted_by, is_owner, wrapped_key, recipient_key_fingerprint, recipient_key_version,
           expires_at, max_downloads, decision_id, created_at)
         VALUES (@id, @document_id, @recipient_id, @granted_by, @is_owner, @wrapped_key, @recipient_key_fingerprint, @recipient_key_version,
           @expires_at, @max_downloads, @decision_id, @ts)`).run({ decision_id: null, ...g, ts: now() }),
    byId: (id) => S('SELECT * FROM grants WHERE id = ?').get(id),
    latestFor: (documentId, userId) =>
      S('SELECT * FROM grants WHERE document_id = ? AND recipient_id = ? ORDER BY is_owner DESC, created_at DESC, rowid DESC LIMIT 1').get(documentId, userId),
    activeFor: (documentId, userId, t) =>
      S(`SELECT * FROM grants WHERE document_id = ? AND recipient_id = ? AND is_owner = 0 AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?) AND download_count < max_downloads ORDER BY created_at DESC LIMIT 1`).get(documentId, userId, t),
    forDocument: (documentId) =>
      S(`SELECT g.id, g.recipient_id, u.username AS recipient_name, u.role AS recipient_role, g.is_owner, g.expires_at, g.max_downloads,
           g.download_count, g.revoked_at, g.revoke_reason, g.recipient_key_version, g.recipient_key_fingerprint, g.created_at,
           u.key_version AS current_key_version, rb.username AS revoked_by_name
         FROM grants g JOIN users u ON u.id = g.recipient_id LEFT JOIN users rb ON rb.id = g.revoked_by
         WHERE g.document_id = ? ORDER BY g.is_owner DESC, g.created_at DESC`).all(documentId),
    revoke: (id, by, reason) =>
      S('UPDATE grants SET revoked_at = ?, revoked_by = ?, revoke_reason = ?, wrapped_key = NULL WHERE id = ? AND revoked_at IS NULL').run(now(), by, reason ?? null, id),
    revokeAllForDocument: (documentId, by, reason) =>
      S('UPDATE grants SET revoked_at = ?, revoked_by = ?, revoke_reason = ?, wrapped_key = NULL WHERE document_id = ? AND revoked_at IS NULL').run(now(), by, reason, documentId).changes,
    /** Atomic: only increments when the limit still allows it (protects against concurrent double-spend). */
    consumeDownload: (id) =>
      S('UPDATE grants SET download_count = download_count + 1 WHERE id = ? AND revoked_at IS NULL AND (max_downloads IS NULL OR download_count < max_downloads)').run(id).changes === 1,
  };

  // ---------- downloads ----------
  const downloads = {
    create: (d) => S('INSERT INTO downloads (id, grant_id, document_id, user_id, decision_id, created_at) VALUES (@id, @grant_id, @document_id, @user_id, @decision_id, @ts)').run({ ...d, ts: now() }),
    byId: (id) =>
      S(`SELECT dl.*, u.username, u.role, d.filename, o.username AS owner_name FROM downloads dl
         JOIN users u ON u.id = dl.user_id JOIN documents d ON d.id = dl.document_id JOIN users o ON o.id = d.owner_id WHERE dl.id = ?`).get(id),
  };

  // ---------- decisions ----------
  const decisions = {
    insert: (d) =>
      S(`INSERT INTO decisions (id, ts, actor_id, actor_name, action, subject_type, subject_id, subject_label, decision, rule, reason, severity, recommended_action, evidence, engine, config_version, latency_ms, request_id)
         VALUES (@id, @ts, @actor_id, @actor_name, @action, @subject_type, @subject_id, @subject_label, @decision, @rule, @reason, @severity, @recommended_action, @evidence, @engine, @config_version, @latency_ms, @request_id)`).run(d),
    query: ({ actorId, decision, rule, action, severity, from, to, limit = 200 }) => {
      const where = [];
      const p = { limit: Math.min(limit, 1000) };
      if (severity) (where.push('severity = @severity'), (p.severity = severity));
      if (actorId) (where.push('actor_id = @actorId'), (p.actorId = actorId));
      if (decision) (where.push('decision = @decision'), (p.decision = decision));
      if (rule) (where.push('rule = @rule'), (p.rule = rule));
      if (action) (where.push('action = @action'), (p.action = action));
      if (from) (where.push('ts >= @from'), (p.from = from));
      if (to) (where.push('ts <= @to'), (p.to = to));
      const sql = `SELECT * FROM decisions ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY ts DESC, rowid DESC LIMIT @limit`;
      return S(sql).all(p).map((r) => ({ ...r, evidence: JSON.parse(r.evidence) }));
    },
    stats: () => S('SELECT action, decision, rule, severity, COUNT(*) n, AVG(latency_ms) avg_ms, MAX(latency_ms) max_ms FROM decisions GROUP BY action, decision, rule, severity ORDER BY action, decision').all(),
  };

  // ---------- audit (read side; writes go through engine/audit.js) ----------
  const audit = {
    query: ({ action, outcome, actor, from, to, limit = 200, beforeSeq }) => {
      const where = [];
      const p = { limit: Math.min(limit, 1000) };
      if (action) (where.push('action = @action'), (p.action = action));
      if (outcome) (where.push('outcome = @outcome'), (p.outcome = outcome));
      if (actor) (where.push('actor_name = @actor'), (p.actor = actor));
      if (from) (where.push('ts >= @from'), (p.from = from));
      if (to) (where.push('ts <= @to'), (p.to = to));
      if (beforeSeq) (where.push('seq < @beforeSeq'), (p.beforeSeq = beforeSeq));
      const sql = `SELECT * FROM audit_events ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY seq DESC LIMIT @limit`;
      return S(sql).all(p).map((r) => ({ ...r, details: JSON.parse(r.details) }));
    },
    all: () => S('SELECT * FROM audit_events ORDER BY seq ASC').all().map((r) => ({ ...r, details: JSON.parse(r.details) })),
    actions: () => S('SELECT DISTINCT action FROM audit_events ORDER BY action').all().map((r) => r.action),
    count: () => S('SELECT COUNT(*) n FROM audit_events').get().n,
  };

  return { users, sessions, settings, documents, grants, downloads, decisions, audit, tx: (fn) => db.transaction(fn)() };
}
