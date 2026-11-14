// Server secrets live outside the database (data/secrets.json, mode 0600) or in
// environment variables, so a stolen database file alone cannot forge audit
// hashes or watermark signatures.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';

const NAMES = { auditKey: 'VS_AUDIT_KEY', watermarkKey: 'VS_WATERMARK_KEY', lookupKey: 'VS_LOOKUP_KEY' };

export function loadSecrets(dataDir) {
  const file = path.join(dataDir, 'secrets.json');
  let stored = {};
  if (fs.existsSync(file)) stored = JSON.parse(fs.readFileSync(file, 'utf8'));
  let changed = false;
  const out = {};
  for (const [name, envName] of Object.entries(NAMES)) {
    const fromEnv = process.env[envName];
    if (fromEnv && /^[0-9a-f]{64}$/.test(fromEnv)) out[name] = Buffer.from(fromEnv, 'hex');
    else {
      if (!stored[name]) {
        stored[name] = randomBytes(32).toString('hex');
        changed = true;
      }
      out[name] = Buffer.from(stored[name], 'hex');
    }
  }
  if (changed) fs.writeFileSync(file, JSON.stringify(stored, null, 2), { mode: 0o600 });
  return out;
}

export function hmacHex(key, value, len = 64) {
  return createHmac('sha256', key).update(String(value)).digest('hex').slice(0, len);
}
