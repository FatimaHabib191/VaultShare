// Spins up an isolated VaultShare instance (temporary data directory, injectable
// clock, fast KDF) and creates users through the real API. Used by the automated
// tests and the evaluation harness.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, randomBytes } from 'node:crypto';
import { createApp } from '../../server/app.js';
import { newEnrollmentCode, hashCode } from '../../server/lib/passwords.js';
import { VSClient } from './vs-client.js';

export const PASSWORDS = {
  admin: 'Admin#Test-pass1',
  alice: 'Alice#Test-pass1',
  bob: 'Bob#Test-pass12',
  victor: 'Victor#Test-pass1',
  mallory: 'Mallory#Test-pass1',
};

export async function startInstance({ dataDir, keepDir = false } = {}) {
  const dir = dataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'vaultshare-'));
  let offset = 0;
  const now = () => Date.now() + offset;
  const inst = { dir, now, advance: (ms) => (offset += ms) };

  async function boot() {
    const { app, svc, close } = createApp({ dataDir: dir, now, testMode: true, quiet: true });
    const server = app.listen(0, '127.0.0.1');
    await new Promise((r) => server.once('listening', r));
    Object.assign(inst, { app, svc, server, closeDb: close, base: `http://127.0.0.1:${server.address().port}` });
  }
  await boot();

  inst.client = () => new VSClient(inst.base);
  inst.stop = async () => {
    await new Promise((r) => inst.server.close(r));
    inst.closeDb();
  };
  /** Simulates a process restart against the same data directory. */
  inst.restart = async () => {
    await inst.stop();
    await boot();
  };
  inst.destroy = async () => {
    await inst.stop().catch(() => {});
    if (!keepDir) fs.rmSync(dir, { recursive: true, force: true });
  };

  inst.bootstrapAdmin = async (username = 'admin', password = PASSWORDS.admin) => {
    const code = newEnrollmentCode();
    inst.svc.repos.users.create({
      id: randomUUID(),
      username,
      role: 'admin',
      kdf_salt: randomBytes(16).toString('base64'),
      kdf_iterations: inst.svc.settings().kdf_iterations,
      enroll_code_hash: hashCode(code),
      enroll_expires_at: now() + 3_600_000,
    });
    const c = inst.client();
    const r = await c.enroll(username, code, password);
    if (r.status !== 201) throw new Error(`bootstrap failed ${JSON.stringify(r.body)}`);
    return c;
  };

  /** admin + alice/bob/mallory (operators) + victor (viewer), all enrolled and signed in. */
  inst.standardUsers = async () => {
    const admin = await inst.bootstrapAdmin();
    const out = { admin };
    for (const [u, role] of [
      ['alice', 'operator'],
      ['bob', 'operator'],
      ['victor', 'viewer'],
      ['mallory', 'operator'],
    ]) {
      const r = await admin.req('POST', '/api/admin/users', { username: u, role });
      const c = inst.client();
      const e = await c.enroll(u, r.body.enrollmentCode, PASSWORDS[u]);
      if (e.status !== 201) throw new Error(`enroll ${u} failed`);
      out[u] = c;
    }
    return out;
  };

  return inst;
}
