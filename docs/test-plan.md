# Test plan and results

## Strategy

| Level | What | Where | Run |
|---|---|---|---|
| Unit | Crypto core, policy rules, permission matrix, validator, settings, watermark codec and signing, redaction, audit chain | `tests/unit-*.test.js` | `npm test` |
| Integration | Real HTTP server per file, real clients using the shared crypto core, isolated temp data dir, injectable clock | `tests/api-*.test.js` | `npm test` |
| Evaluation | The mandatory cases T1–T5 and T-final with input / expected / actual / evidence / pass-fail, plus measurements | `scripts/evaluate.js` → `reports/evaluation.md` | `npm run evaluate` |
| Manual / UI | The demonstration path in Chrome, keyboard navigation, 390 px mobile width, light and dark themes | `docs/demo-script.md` | by hand |

Positive, negative, edge-case and misuse tests are present at every level: e.g. grant valid at expiry − 1 s and denied at exactly expiry (edge), 500 random bit flips (negative), concurrent download race and injection-shaped usernames (misuse).

**Exit criteria (from the specification):** ≥ 80% of automated tests pass; zero unresolved critical authorization, injection, secret-exposure or unsafe-file-handling defects.

## Results

The latest generated results are in [`reports/evaluation.md`](../reports/evaluation.md) (`reports/evaluation.json` for machines). At the time of submission:

- **Automated tests: 86 / 86 pass (100%).**
- **Browser end-to-end checks of the interface: 35 / 35 pass** (sign-in errors, enrollment, unlock, upload, search and filters, sharing, opening, revocation, the decision drawer, export, settings, policy denial, audit pagination and verification, leak tracing, delete, keyboard, mobile drawer), with no unexpected console errors.
- **Responsive check:** every page at 375, 430, 768, 1024, 1440 and 1920 px with no horizontal page scroll.
- **Evaluation cases: 59 / 59 pass.**
- Access-control matrix: **19 / 19 permissions × 3 roles = 57 server requests, 0 false permits, 0 false denies**.
- Tamper detection: **500 / 500** random single-bit corruptions rejected.
- Decision latency (server, p95): download 0.5 ms, share 1.0 ms, upload checks < 1 ms; download round trip p95 ≈ 11 ms on a laptop.

Numbers vary slightly per machine and run; re-run `npm run evaluate` to regenerate them.

## Mandatory case mapping

| Case | Required by spec | Evaluation IDs | Automated tests |
|---|---|---|---|
| T1 | Confidentiality | T1.1–T1.6 | `unit-crypto` round trip / no plaintext / unwrap; `api-documents` "T1: …" |
| T2 | Altered-ciphertext rejection | T2.1–T2.9 | `unit-crypto` "altering the …"; `api-documents` "T2: …" |
| T3 | Access-control matrices | T3.1–T3.6, T-final.9 | `unit-engine` permission matrix; `api-documents` "T3: …"; `api-auth` CSRF, role change |
| T4 | Expiry tests | T4.1–T4.8 | `unit-engine` download policy; `api-documents` "T4: …" |
| T5 | Key-loss behaviour | T5.1–T5.6 | `unit-crypto` wrong password; `api-documents` "T5: …" |
| Page-3 example | Normal vs adverse sample, history, sanitised export, unauthorised viewer | EX.1–EX.7 | `api-documents` "upload rejects…" (adverse samples recorded in history and audit) |
| T-final | Malformed/oversized input, unauthorised request, repeated submission, safe failure, restart recovery | T-final.1–T-final.15 | `api-documents` "T-final: …", "repeated submission…" |

## Functional requirement coverage

| FR | Validates input | Clear result | Records security-relevant action | Tests |
|---|---|---|---|---|
| FR-1 Accounts and roles | username pattern, base64 lengths, RSA key parameters | generic auth errors, enrollment steps | `AUTH_*`, `USER_*`, `SESSION_EXPIRED`, `ACCESS_DENIED` | `api-auth` (16) |
| FR-2 AES-GCM encryption | extension/MIME/size, magic bytes (client), container structure and length (server) | upload verdict slip | `DOC_INIT`, `DOC_UPLOAD`, `DOC_UPLOAD_REJECTED` | `unit-crypto`, T1, T2 |
| FR-3 Key wrapping | wrapped-key length, recipient fingerprint | share verdict slip | `GRANT_CREATE`, `GRANT_DENIED`, `DOC_KEY_ACCESS` | T1.3–T1.4, T5 |
| FR-4 Expiry / revocation | TTL and limit bounds, confirmation | download verdict slip with rule | `DOWNLOAD_ALLOW`, `DOWNLOAD_DENY`, `GRANT_REVOKE`, `DOC_DELETE` | T4 |
| FR-5 Watermarking | payload format and HMAC | trace verdict slip | `WATERMARK_TRACE` | FR-5.1–5.2, `unit-engine` codec tests |
| FR-6 Audit trail | filter allow-lists | verification slip, export | `AUDIT_VERIFY`, `AUDIT_EXPORT`, `REPORT_EXPORT`, `CONFIG_CHANGE`, `SYSTEM_START` | `unit-audit`, T-final.13–15 |

## Fixtures

`fixtures/samples/` — sanitised, fictional sample files (TXT, MD, CSV, PDF, PNG).
`fixtures/adverse/` — `not-really.pdf` (text with a PDF name), `report.pdf.exe` (double extension), `empty.txt`, `formula-injection.csv` (spreadsheet formula).

## Defects found and fixed during testing

| Found by | Defect | Fix |
|---|---|---|
| UI review | Inline `style` attributes were blocked by the strict CSP | Styles applied via CSSOM; CSP left strict |
| Evaluation | Redaction matched `ciphertextBytes`, hiding useful evidence | Redaction uses exact secret field names |
| API tests | Enrollment limiter keyed only by IP blocked an admin onboarding several people | Keyed by IP + username |
| UI review | Sign-in probe produced a console 401 on every page load | `/auth/me` returns `{ user: null }` when signed out |
| Requirements review | Adverse samples were rejected only in the browser, so they were missing from history and the audit trail (page-3 example) | Server-side `CONTENT_TYPE_MISMATCH` rule; browser sends first bytes; evaluation EX.2–EX.4 |
| Requirements review | Client-detected tampering was not recorded server-side | `/integrity-failure` report endpoint; evaluation EX.7 |
| Requirements review | Dashboard lacked severity and recommended action | `RULE_META` for every rule, shown in slips, history, filters and exports |
| Requirements review | Access-control evaluation covered 12 of 19 permissions | All 19 probed (57 requests) |
| Interface redesign | The `hidden` attribute was overridden by component `display` rules, so hidden fields still showed | Global `[hidden] { display: none !important }` |
| Interface redesign | Visually-hidden table labels escaped the scroll container and widened the page at 768–1024 px | Table container is the positioning context |
| Interface redesign | One sign-in counted twice against the sign-in limit (prelogin + login), halving the configured attempts | Prelogin has its own counter; test added in `api-auth` |
| Interface redesign | The document header kept showing *Active* after an expired share was denied | Header status refreshes with the access panel |
| New test | Audit events with an `undefined` detail field broke the hash chain (hashed before, dropped after storage) | Details are normalised through JSON before hashing; regression test in `unit-audit` |
