// Tamper-evident audit trail.
// Each event's hash = HMAC-SHA256(auditKey, prev_hash || "|" || canonical(event)).
// Because every hash covers the previous one, editing, inserting or deleting any
// row breaks every later link. The HMAC key (kept outside the database) stops an
// attacker who can write the database from simply recomputing the chain.
// SQLite triggers additionally reject UPDATE/DELETE on audit_events, and an
// external anchor file records the last verified head so tail truncation is caught.

import { createHmac, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { redact } from './redact.js';

export const GENESIS = '0'.repeat(64);

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
    .join(',')}}`;
}

export function eventBody(row) {
  return {
    seq: row.seq,
    ts: row.ts,
    actor_id: row.actor_id ?? null,
    actor_name: row.actor_name ?? null,
    actor_role: row.actor_role ?? null,
    action: row.action,
    target_type: row.target_type ?? null,
    target_id: row.target_id ?? null,
    outcome: row.outcome,
    request_id: row.request_id ?? null,
    ip_hash: row.ip_hash ?? null,
    details: typeof row.details === 'string' ? JSON.parse(row.details) : row.details ?? {},
  };
}

export function computeHash(key, prevHash, body) {
  return createHmac('sha256', key).update(`${prevHash}|${canonical(body)}`).digest('hex');
}

export function createAuditLog(db, { key, anchorPath, now }) {
  const lastStmt = db.prepare('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1');
  const insertStmt = db.prepare(`INSERT INTO audit_events
    (seq, ts, actor_id, actor_name, actor_role, action, target_type, target_id, outcome, request_id, ip_hash, details, prev_hash, hash)
    VALUES (@seq, @ts, @actor_id, @actor_name, @actor_role, @action, @target_type, @target_id, @outcome, @request_id, @ip_hash, @details, @prev_hash, @hash)`);

  const appendTx = db.transaction((evt) => {
    const last = lastStmt.get();
    const seq = last ? last.seq + 1 : 1;
    const prev = last ? last.hash : GENESIS;
    // Round-trip through JSON first so the hashed form is exactly the stored form
    // (e.g. keys whose value is undefined are dropped before hashing, not after).
    const details = JSON.parse(JSON.stringify(redact(evt.details || {})));
    const body = eventBody({ ...evt, seq, ts: new Date(now()).toISOString(), details });
    const hash = computeHash(key, prev, body);
    insertStmt.run({ ...body, details: JSON.stringify(body.details), prev_hash: prev, hash });
    return { seq, hash };
  });

  function append(evt) {
    return appendTx(evt);
  }

  function readAnchor() {
    try {
      return JSON.parse(fs.readFileSync(anchorPath, 'utf8'));
    } catch {
      return null;
    }
  }

  function writeAnchor(head) {
    if (!anchorPath) return;
    fs.writeFileSync(anchorPath, JSON.stringify({ ...head, anchoredAt: new Date(now()).toISOString() }, null, 2), { mode: 0o600 });
  }

  /** Walk the whole chain. Returns an explainable verification result. */
  function verify({ updateAnchor = true } = {}) {
    const started = Date.now();
    const rows = db.prepare('SELECT * FROM audit_events ORDER BY seq ASC').iterate();
    let prev = GENESIS;
    let expectedSeq = 1;
    let checked = 0;
    let head = null;
    for (const row of rows) {
      if (row.seq !== expectedSeq) {
        return result(false, 'SEQUENCE_GAP', { atSeq: expectedSeq, foundSeq: row.seq, checked });
      }
      if (row.prev_hash !== prev) {
        return result(false, 'PREV_HASH_MISMATCH', { atSeq: row.seq, checked });
      }
      const expect = computeHash(key, prev, eventBody(row));
      const a = Buffer.from(expect, 'hex');
      const b = Buffer.from(String(row.hash), 'hex');
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        return result(false, 'HASH_MISMATCH', { atSeq: row.seq, action: row.action, checked });
      }
      prev = row.hash;
      head = { seq: row.seq, hash: row.hash };
      expectedSeq++;
      checked++;
    }
    const anchor = readAnchor();
    if (anchor) {
      if (!head || head.seq < anchor.seq) {
        return result(false, 'TRUNCATED_BELOW_ANCHOR', { anchoredSeq: anchor.seq, currentHeadSeq: head?.seq ?? 0, checked });
      }
      const atAnchor = db.prepare('SELECT hash FROM audit_events WHERE seq = ?').get(anchor.seq);
      if (!atAnchor || atAnchor.hash !== anchor.hash) {
        return result(false, 'ANCHOR_MISMATCH', { anchoredSeq: anchor.seq, checked });
      }
    }
    if (updateAnchor && head) writeAnchor(head);
    return result(true, 'CHAIN_INTACT', { checked, head, anchor: anchor ? { seq: anchor.seq } : null });

    function result(ok, rule, evidence) {
      return { ok, rule, evidence, verifiedAt: new Date(now()).toISOString(), latencyMs: Date.now() - started };
    }
  }

  return { append, verify, readAnchor };
}
