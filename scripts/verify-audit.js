// Offline audit verification: node scripts/verify-audit.js [dataDir]
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { openDatabase } from '../server/repo/db.js';
import { loadSecrets } from '../server/lib/secrets.js';
import { createAuditLog } from '../server/engine/audit.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dataDir = process.argv[2] || process.env.VS_DATA_DIR || path.join(ROOT, 'data');
const db = openDatabase(path.join(dataDir, 'vaultshare.db'));
const log = createAuditLog(db, { key: loadSecrets(dataDir).auditKey, anchorPath: path.join(dataDir, 'audit-anchor.json'), now: () => Date.now() });
const r = log.verify({ updateAnchor: false });
db.close();
console.log(JSON.stringify(r, null, 2));
process.exit(r.ok ? 0 : 2);
