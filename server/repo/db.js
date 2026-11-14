// Repository layer: SQLite connection and schema.
// Uses Node's built-in SQLite (node:sqlite, Node >= 22.13), so there is no native
// module to compile on student laptops. All queries elsewhere use prepared
// statements with bound parameters.
import { createRequire } from 'node:module';

// node:sqlite prints an "experimental" warning once; silence only that warning.
const emitWarning = process.emitWarning;
process.emitWarning = function (warning, ...rest) {
  if (String(warning?.message ?? warning).includes('SQLite is an experimental feature')) return;
  return emitWarning.call(this, warning, ...rest);
};
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite');

export const SCHEMA_VERSION = 1;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
  status TEXT NOT NULL CHECK (status IN ('pending','active','disabled')),
  kdf_salt TEXT NOT NULL,
  kdf_iterations INTEGER NOT NULL,
  auth_hash TEXT,
  auth_salt TEXT,
  public_key TEXT,
  key_fingerprint TEXT,
  wrapped_private_key TEXT,
  wrap_iv TEXT,
  key_version INTEGER NOT NULL DEFAULT 0,
  enroll_code_hash TEXT,
  enroll_expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS settings_versions (
  version INTEGER PRIMARY KEY,
  settings TEXT NOT NULL,
  diff TEXT NOT NULL,
  reason TEXT,
  changed_by TEXT,
  changed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  filename TEXT NOT NULL,
  extension TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_plain INTEGER NOT NULL,
  size_cipher INTEGER,
  cipher_sha256 TEXT,
  binding TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','active','deleted')),
  content BLOB,
  config_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  uploaded_at INTEGER,
  deleted_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  recipient_id TEXT NOT NULL REFERENCES users(id),
  granted_by TEXT NOT NULL REFERENCES users(id),
  is_owner INTEGER NOT NULL DEFAULT 0,
  wrapped_key TEXT,
  recipient_key_fingerprint TEXT NOT NULL,
  recipient_key_version INTEGER NOT NULL,
  expires_at INTEGER,
  max_downloads INTEGER,
  download_count INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER,
  revoked_by TEXT,
  revoke_reason TEXT,
  decision_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_grants_doc ON grants(document_id);
CREATE INDEX IF NOT EXISTS idx_grants_recipient ON grants(recipient_id);

CREATE TABLE IF NOT EXISTS downloads (
  id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES grants(id),
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  decision_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  action TEXT NOT NULL,
  subject_type TEXT,
  subject_id TEXT,
  subject_label TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','info')),
  rule TEXT NOT NULL,
  reason TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  recommended_action TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL,
  engine TEXT NOT NULL,
  config_version INTEGER NOT NULL,
  latency_ms REAL NOT NULL,
  request_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_actor ON decisions(actor_id, ts);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);

CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  outcome TEXT NOT NULL,
  request_id TEXT,
  ip_hash TEXT,
  details TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

/** Thin wrapper: statement cache and nest-safe transactions (SAVEPOINT). */
class Db {
  constructor(file) {
    this.raw = new DatabaseSync(file);
    this.cache = new Map();
    this.depth = 0;
    this.seq = 0;
  }
  exec(sql) {
    this.raw.exec(sql);
  }
  prepare(sql) {
    let st = this.cache.get(sql);
    if (!st) {
      st = this.raw.prepare(sql);
      this.cache.set(sql, st);
    }
    return st;
  }
  pragma(p) {
    this.raw.exec(`PRAGMA ${p}`);
  }
  /** Returns a function that runs fn atomically; all-or-nothing on exceptions. */
  transaction(fn) {
    return (...args) => {
      const name = `sp${++this.seq}`;
      const outer = this.depth === 0;
      this.raw.exec(outer ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${name}`);
      this.depth++;
      try {
        const out = fn(...args);
        this.depth--;
        this.raw.exec(outer ? 'COMMIT' : `RELEASE ${name}`);
        return out;
      } catch (e) {
        this.depth--;
        this.raw.exec(outer ? 'ROLLBACK' : `ROLLBACK TO ${name}; RELEASE ${name}`);
        throw e;
      }
    };
  }
  close() {
    this.cache.clear();
    this.raw.close();
  }
}

export function openDatabase(path) {
  const db = new Db(path);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = FULL');
  db.pragma('foreign_keys = ON');
  db.pragma('secure_delete = ON'); // overwrite freed pages, so deleted ciphertext is not left in the file
  db.pragma('busy_timeout = 5000');
  db.exec(SCHEMA);
  // Migration for databases created before severity/recommended action existed.
  const cols = db.raw.prepare('PRAGMA table_info(decisions)').all().map((c) => c.name);
  if (!cols.includes('severity')) db.exec("ALTER TABLE decisions ADD COLUMN severity TEXT NOT NULL DEFAULT 'info'");
  if (!cols.includes('recommended_action')) db.exec("ALTER TABLE decisions ADD COLUMN recommended_action TEXT NOT NULL DEFAULT ''");
  db.prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)").run(String(SCHEMA_VERSION));
  return db;
}
