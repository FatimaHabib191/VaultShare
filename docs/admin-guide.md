# Administrator guide

Administrators manage people, policy and evidence. By design they **cannot read documents**: they hold no document keys, cannot upload, cannot be chosen as a share recipient, and the server refuses their download requests.

## Installation and operation

See the [README](../README.md) for `npm install`, `npm run seed` and `npm start`. Without demo data, run `node scripts/seed.js --admin-only` to receive the first admin enrollment code.

| Environment variable | Default | Purpose |
|---|---|---|
| `PORT` | 3000 | Listening port |
| `HOST` | 127.0.0.1 | Bind address (keep local unless TLS is in front) |
| `VS_DATA_DIR` | `./data` | Database, secrets and audit anchor |
| `VS_SECURE_COOKIES` | off | Set to `1` behind HTTPS |
| `VS_AUDIT_KEY`, `VS_WATERMARK_KEY`, `VS_LOOKUP_KEY` | generated in `secrets.json` | 64-hex-character keys, if you prefer to inject them |

## People

**People → Add a person**: choose a username and role. The one-time enrollment code is shown once; give it to the person through a separate channel (in person, phone). Codes expire after 24 hours by default.

| Action | Effect | Audit event |
|---|---|---|
| Change role | Takes effect at the person's next sign-in; their sessions end now | `USER_ROLE_CHANGE` |
| Disable / Enable | Disabled people are signed out and cannot sign in | `USER_DISABLE` / `USER_ENABLE` |
| Reset key | New code and new key pair at re-enrollment. Shares to the old key show `KEY_MISMATCH`; files the person owned become unrecoverable | `USER_RESET` |

Every high-impact action asks for confirmation. You cannot change, disable or reset your own account.

## Permission matrix

| Permission | Admin | Operator | Viewer |
|---|---|---|---|
| Upload, delete, share own documents | — | Yes | — |
| List and open documents shared with you | — | Yes | Yes |
| Browse recipient directory | — | Yes | — |
| Revoke a share | Yes (incident response) | Own documents | — |
| Own decision history and report | Yes | Yes | Yes |
| All decisions, all-user report | Yes | — | — |
| People, policy settings | Yes | — | — |
| Audit read, verify, export | Yes | — | — |
| Trace a leaked copy | Yes | — | — |

The live matrix is on the **Overview** page and is generated from `server/engine/access.js`.

## Policy settings

**Policy settings** lists every rule and threshold with its allowed range. To change one, edit it, give a reason, choose **Review and apply** and confirm. The server validates the change, stores it as a new **settings version** with the before/after diff and reason, writes a `CONFIG_CHANGE` audit event, and every later decision records the new version — so you can show exactly which version produced which result.

| Setting | Default | Range |
|---|---|---|
| Maximum file size (MB) | 10 | 1–20 |
| Allowed file types | txt, md, csv, pdf, png, jpg, jpeg | subset |
| Longest allowed share (hours) | 168 | 1–720 |
| Default share length (hours) | 24 | ≤ longest |
| Most downloads per share | 10 | 1–100 |
| Sign out after inactivity (minutes) | 30 | 5–240 |
| Longest session (hours) | 8 | 1–24 |
| Sign-in attempts per 15 minutes | 10 | 3–50 |
| Uploads, shares and downloads per minute | 30 | 5–300 |
| Password key-derivation rounds | 600 000 | 100 000–2 000 000 (new enrollments) |
| Enrollment code lifetime (hours) | 24 | 1–168 |

## Audit trail

**Audit trail** shows every event newest first with filters by event, outcome and user. Each event stores an HMAC over its content and the previous event's hash.

- **Verify chain** recomputes every link. *Chain intact* means nothing was edited, inserted or removed. *Tampering detected* names the first broken event (`HASH_MISMATCH`, `SEQUENCE_GAP`, `PREV_HASH_MISMATCH`, `TRUNCATED_BELOW_ANCHOR`, `ANCHOR_MISMATCH`).
- Each successful verification writes the head (sequence and hash) to `data/audit-anchor.json`, so later truncation is detectable. Keep a copy of exported head hashes outside the machine for stronger evidence.
- **Export (JSON)** downloads all events, the verification result and the head hash.
- `npm run verify-audit` verifies from the command line, also while the server is stopped.

Events recorded include sign-in success and failure, enrollment, session expiry, CSRF rejections, access denials, rate limiting, rejected requests, user and settings changes, uploads (accepted and rejected), shares (created and denied), revocations, deletions, downloads (allowed and denied), exports, verifications, traces, server errors and server start. Secrets, keys, ciphertext and IP addresses are never written (IPs appear as keyed hashes).

### If verification fails

1. Stop using the instance for new work. Do not run reset or seed.
2. Copy the whole `data/` folder (including `secrets.json` and `audit-anchor.json`) to read-only storage.
3. Export the audit trail and note the broken sequence number.
4. Compare with the last head hash you exported earlier.

## Tracing a leaked copy

**Trace a leak** → choose the file. Your browser extracts the watermark locally (text: invisible characters and banner; PDF: document properties; PNG: metadata) and sends only the reference to the server, which checks its HMAC signature and shows the recipient, document, owner, grant and download time. A reference that has been altered is reported as `WATERMARK_FORGED`. You can also paste a reference by hand.

## Incident response: revoke access quickly

In **Audit trail**, filter *Event = GRANT_CREATE*; each share has a **Revoke** button. After confirmation the share is revoked immediately, the owner sees it attributed to you, and a `GRANT_REVOKE` event records `byAdmin: true`. Disable an account to end all of its sessions at once.

Filter *Severity = High* in **All decisions** to find events that need review: content mismatches on upload, integrity failures, stale-fingerprint shares and traced leaks.

## Backup and restore

Stop the server, copy `data/`, start it again. To restore, stop the server, replace `data/` and start. `secrets.json` must stay with the database it was created with.
