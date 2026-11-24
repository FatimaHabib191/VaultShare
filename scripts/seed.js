// Creates the demo accounts through the real API (enrollment generates real key
// pairs) and one shared sample document.
//   npm run seed            create demo data if the database is empty
//   npm run reset           wipe data/ and re-seed
//   node scripts/seed.js --admin-only   create only an admin enrollment code (no demo passwords)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, randomBytes } from 'node:crypto';
import { createApp } from '../server/app.js';
import { newEnrollmentCode, hashCode } from '../server/lib/passwords.js';
import { VSClient } from './lib/vs-client.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = process.env.VS_DATA_DIR || path.join(ROOT, 'data');
const args = new Set(process.argv.slice(2));

export const DEMO_USERS = [
  { username: 'admin', role: 'admin', password: 'Admin#Vault2026' },
  { username: 'alice', role: 'operator', password: 'Alice#Vault2026' },
  { username: 'bob', role: 'operator', password: 'Bob#Vault2026!' },
  { username: 'victor', role: 'viewer', password: 'Victor#Vault2026' },
  { username: 'mallory', role: 'operator', password: 'Mallory#Vault2026' },
];

if (args.has('--reset') && fs.existsSync(dataDir)) {
  for (const f of fs.readdirSync(dataDir)) fs.rmSync(path.join(dataDir, f), { recursive: true, force: true });
  console.log('  Cleared', dataDir);
}

const { app, svc, close } = createApp({ dataDir, quiet: true });
if (svc.repos.users.count() > 0) {
  console.log('  Database already has users. Use "npm run reset" to start over.');
  close();
  process.exit(0);
}

function bootstrapAdmin(username) {
  const code = newEnrollmentCode();
  svc.repos.users.create({
    id: randomUUID(),
    username,
    role: 'admin',
    kdf_salt: randomBytes(16).toString('base64'),
    kdf_iterations: svc.settings().kdf_iterations,
    enroll_code_hash: hashCode(code),
    enroll_expires_at: svc.now() + 24 * 3_600_000,
  });
  svc.audit.append({ action: 'USER_CREATE', outcome: 'success', actor_name: 'seed-script', details: { username, role: 'admin', bootstrap: true } });
  return code;
}

if (args.has('--admin-only')) {
  const code = bootstrapAdmin('admin');
  console.log(`\n  Admin account "admin" created. Enrollment code (valid 24h):\n\n      ${code}\n\n  Start the server and choose "Set up account" on the sign-in screen.\n`);
  close();
  process.exit(0);
}

const server = app.listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}`;

try {
  const [adminDef, ...others] = DEMO_USERS;
  const admin = new VSClient(base);
  let r = await admin.enroll(adminDef.username, bootstrapAdmin(adminDef.username), adminDef.password);
  if (r.status !== 201) throw new Error(`admin enroll failed: ${JSON.stringify(r.body)}`);

  const clients = { admin };
  for (const u of others) {
    r = await admin.req('POST', '/api/admin/users', { username: u.username, role: u.role });
    if (r.status !== 201) throw new Error(`create ${u.username}: ${JSON.stringify(r.body)}`);
    const c = new VSClient(base);
    const e = await c.enroll(u.username, r.body.enrollmentCode, u.password);
    if (e.status !== 201) throw new Error(`enroll ${u.username}: ${JSON.stringify(e.body)}`);
    clients[u.username] = c;
  }

  const sample = fs.readFileSync(path.join(ROOT, 'fixtures/samples/quarterly-briefing.txt'));
  const up = await clients.alice.upload('quarterly-briefing.txt', 'text/plain', new Uint8Array(sample));
  if (up.status !== 200) throw new Error(`upload: ${JSON.stringify(up.body)}`);
  const sh = await clients.alice.share(up.docId, 'bob', { minutes: 7 * 24 * 60, maxDownloads: 5 });
  if (sh.status !== 201) throw new Error(`share: ${JSON.stringify(sh.body)}`);

  console.log('\n  Demo data created. Local demo accounts (do not reuse these passwords anywhere):\n');
  for (const u of DEMO_USERS) console.log(`    ${u.role.padEnd(9)} ${u.username.padEnd(8)} ${u.password}`);
  console.log('\n  alice has shared "quarterly-briefing.txt" with bob (7 days, 5 downloads).');
  console.log('  Start the server with "npm start" and open http://localhost:3000\n');
} finally {
  server.close();
  close();
}
