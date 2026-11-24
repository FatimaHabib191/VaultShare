# Demonstration script (about 12 minutes)

**Before you start (2 minutes, off the clock):** `npm run reset` then `npm start`. Open three browser windows side by side — a normal window (alice), a private window (victor / mallory) and a second private window or another browser (admin) — at <http://localhost:3000>. Have `fixtures/` open in a file explorer.

| Time | Presenter | Show | Say |
|---|---|---|---|
| 0:00 | A | Title slide or README | Problem: hand confidential files to specific people for a limited time and prove who had access. Three roles; five layers; server only ever sees ciphertext. |
| 1:00 | A | Sign in as **alice** | Password stays in the browser: PBKDF2 → HKDF gives an authKey for the server and a key that unlocks alice's private key locally. |
| 2:00 | B | **Upload** `fixtures/samples/access-policy.pdf` | Steps tick through: content check, AES-256-GCM encryption with a fresh key, key wrapped to alice's public key, upload. Point at the verdict slip: rule `ALLOW_UPLOAD`, evidence (declared size, ciphertext = size + 34 bytes), engine and settings version. |
| 3:00 | B | **Upload** `fixtures/adverse/not-really.pdf` | Seeded adverse sample. Rejected by the server: `CONTENT_TYPE_MISMATCH`, high severity — "named .pdf but its contents are plain text, not a PDF" — plus the detected type, first bytes and what to do. Not just "unsafe". |
| 3:45 | C | **Share** the PDF with **victor**, *1 minute*, 3 downloads | Show victor's key fingerprint and compare it with victor's Account page. The browser re-wraps the file key for victor; `ALLOW_SHARE`. |
| 4:45 | C | As **victor**: open the PDF | `ALLOW_GRANT`. Preview shows the footer and diagonal stamp "Issued to victor … ref …". Save the file (keep it for the trace). |
| 5:45 | C | As **mallory** (sign out victor, sign in mallory): paste victor's document URL (`#/doc/<id>`) | Generic "not found". Nothing about the file is revealed. |
| 6:15 | D | Admin → **Audit trail**, filter *User = mallory* | mallory's attempt is recorded as `ACCESS_DENIED` (reason `no_grant`) without the file name; IP only as a hash. |
| 6:45 | C | As **victor** after the minute has passed: open again | `GRANT_EXPIRED` with expiry and evaluation times in the evidence. |
| 7:15 | C | victor → **My decisions**, select both rows; **Export CSV**. (Optionally alice's history: the PDF allowed and not-really.pdf rejected) | The allowed and denied results side by side with severity; export contains no keys or contents. |
| 8:00 | D | Admin → **Policy settings**: *Longest allowed share* 168 → 2 and *Default share length* 24 → 1, reason "demo: tighten", apply | Confirmation dialog; becomes settings v2. (Leaving the default at 24 shows the consistency check: `DEFAULT_EXCEEDS_MAX`.) |
| 8:30 | B | alice shares `quarterly-briefing.txt` with **victor** using *Custom… 180 minutes* | Denied `GRANT_TTL_OUT_OF_RANGE`, evidence shows 180 vs 120 minutes, slip footer shows `settings v2`. Then share for 1 hour → allowed. |
| 9:15 | D | Admin → **Audit trail** → *CONFIG_CHANGE* row; **Verify chain** | Diff and reason are logged. Verification: *Chain intact*, events checked, head hash. |
| 10:00 | D | Terminal: `npm run evaluate` (already run) — open `reports/evaluation.md` | Tampering evidence: T2 (500/500 bit flips rejected) and T-final.15 (audit edit detected at the exact event). |
| 10:45 | B | Admin → **Trace a leak**, choose the PDF victor saved | `WATERMARK_VERIFIED` → victor, the document, the grant and the time. Explain that the reference is HMAC-signed. |
| 11:30 | A | Admin → **People** → Reset key for bob (optional) and summary | Key loss is permanent by design (T5); limitations: browser trusts server code, watermark deters rather than prevents. 86/86 tests, 59/59 evaluation cases. |
| 12:00 | — | Questions | |

## Backup lines

- If the 1-minute share has not expired yet when you reach 6:45, continue with the settings change and return to it.
- If a rate limit triggers during rehearsal, wait a minute or raise *Uploads, shares and downloads per minute* in Policy settings.
- Restart recovery: stop the server (Ctrl+C), `npm start`, sign in as bob and open the seeded file; the audit trail shows a `SYSTEM_START` event with `auditChain: CHAIN_INTACT`.
