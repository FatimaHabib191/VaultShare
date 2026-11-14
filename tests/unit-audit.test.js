import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDatabase } from '../server/repo/db.js';
import { createAuditLog, canonical } from '../server/engine/audit.js';

function fresh() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vs-audit-'));
  const db = openDatabase(path.join(dir, 'a.db'));
  const log = createAuditLog(db, { key: Buffer.alloc(32, 3), anchorPath: path.join(dir, 'anchor.json'), now: () => Date.now() });
  for (let i = 0; i < 10; i++) log.append({ action: 'TEST_EVENT', outcome: 'success', actor_name: 'alice', details: { i, password: 'never-stored' } });
  return { dir, db, log, cleanup: () => (db.close(), fs.rmSync(dir, { recursive: true, force: true })) };
}

test('canonical JSON is key-order independent', () => {
  assert.equal(canonical({ b: 1, a: [2, { d: 1, c: 2 }] }), canonical({ a: [2, { c: 2, d: 1 }], b: 1 }));
});

test('intact chain verifies and secrets are redacted before hashing', () => {
  const t = fresh();
  const r = t.log.verify();
  assert.equal(r.ok, true);
  assert.equal(r.rule, 'CHAIN_INTACT');
  assert.equal(r.evidence.checked, 10);
  const row = t.db.prepare('SELECT details FROM audit_events WHERE seq = 1').get();
  assert.ok(!row.details.includes('never-stored'));
  t.cleanup();
});

test('UPDATE and DELETE are blocked by triggers', () => {
  const t = fresh();
  assert.throws(() => t.db.prepare("UPDATE audit_events SET outcome = 'denied' WHERE seq = 3").run(), /append-only/);
  assert.throws(() => t.db.prepare('DELETE FROM audit_events WHERE seq = 3').run(), /append-only/);
  t.cleanup();
});

test('editing an event (after bypassing triggers) is detected at that event', () => {
  const t = fresh();
  t.db.exec('DROP TRIGGER audit_no_update');
  t.db.prepare(`UPDATE audit_events SET details = '{"i":4,"edited":true}' WHERE seq = 5`).run();
  const r = t.log.verify();
  assert.equal(r.ok, false);
  assert.equal(r.rule, 'HASH_MISMATCH');
  assert.equal(r.evidence.atSeq, 5);
  t.cleanup();
});

test('recomputing a hash without the HMAC key does not help an attacker', () => {
  const t = fresh();
  t.db.exec('DROP TRIGGER audit_no_update');
  // attacker edits and rewrites hash with plain SHA-256 — next link and HMAC both fail
  t.db.prepare(`UPDATE audit_events SET outcome = 'denied', hash = '${'ab'.repeat(32)}' WHERE seq = 2`).run();
  const r = t.log.verify();
  assert.equal(r.ok, false);
  assert.equal(r.evidence.atSeq, 2);
  t.cleanup();
});

test('deleting a middle event is detected as a sequence gap', () => {
  const t = fresh();
  t.db.exec('DROP TRIGGER audit_no_delete');
  t.db.prepare('DELETE FROM audit_events WHERE seq = 6').run();
  const r = t.log.verify();
  assert.equal(r.rule, 'SEQUENCE_GAP');
  assert.equal(r.evidence.atSeq, 6);
  t.cleanup();
});

test('truncating the tail below the last anchor is detected', () => {
  const t = fresh();
  assert.equal(t.log.verify().ok, true); // writes anchor at seq 10
  t.db.exec('DROP TRIGGER audit_no_delete');
  t.db.prepare('DELETE FROM audit_events WHERE seq > 7').run();
  const r = t.log.verify();
  assert.equal(r.rule, 'TRUNCATED_BELOW_ANCHOR');
  t.cleanup();
});

test('details with undefined values still verify (hash covers the stored form)', () => {
  const t = fresh();
  t.log.append({ action: 'TEST_EVENT', outcome: 'denied', details: { a: undefined, b: 1, nested: { c: undefined } } });
  assert.equal(t.log.verify().ok, true);
  t.cleanup();
});
