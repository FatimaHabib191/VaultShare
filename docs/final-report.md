# VaultShare: Encrypted Document Exchange — Final Report

Domain: Cryptography and Digital Rights Management

Every claim in this report links to a test, an evaluation case in [`reports/evaluation.md`](../reports/evaluation.md) (IDs such as **T4.3**), a screenshot, or a source file.

## 1. Problem and outcome

Teams need to hand confidential documents to specific people for a limited time and later prove who had access. VaultShare is a locally runnable web system that:

- encrypts each file in the browser with its own AES-256-GCM key, so the server stores only ciphertext (**T1.1**);
- wraps that key separately for each recipient with RSA-OAEP, so each share is cryptographically individual (**T1.3, T1.4**);
- enforces expiry, revocation and download limits on the server before any key is released (**T4.1–T4.7**);
- watermarks every opened copy with a signed, per-download reference that an administrator can trace (**FR-5.1, FR-5.2**);
- records every security-relevant action in an HMAC hash chain that detects editing, deletion and truncation (**T-final.13–15**, [`unit-audit.test.js`](../tests/unit-audit.test.js));
- explains every allow/deny with a rule, reason, evidence, engine version and settings version (**T4.3, T4.8**).

**Acceptance status:** all six functional requirements are demonstrable; **86/86 automated tests pass (100%, threshold 80%)**; **59/59 evaluation cases pass**; no open critical authorization, injection, secret-exposure or unsafe-file-handling defects (see §6).

## 2. Users and roles

| Role | Can | Cannot |
|---|---|---|
| Administrator | manage people and roles, change policy, read/verify/export the audit trail, trace leaks, revoke any share | upload, receive or open documents (**T1.5**) |
| Operator | upload, share, revoke, delete, open shared files | administration |
| Viewer (restricted) | open files shared with them | upload, share, browse directory (**T3.4**) |

Authorization is enforced only on the server ([`access.js`](../server/engine/access.js), `requirePerm` in [`middleware.js`](../server/api/middleware.js)); the role × permission matrix (all 19 permissions × 3 roles = 57 requests) produced **0 false permits and 0 false denies (T3.1)**.

## 3. Architecture

Five layers — browser UI, API, security engine, repository, fixtures — described with the data-flow diagram (`img/dataflow.png`), trust boundaries, key hierarchy, data model and schemas in [architecture.md](architecture.md). Security logic is in `server/engine/` and `shared/`, both unit-tested without the UI (35 unit tests).

### Cryptographic design and justification

| Decision | Choice | Why |
|---|---|---|
| File cipher | AES-256-GCM, random 96-bit IV, 128-bit tag | Authenticated encryption detects any change (**T2.6: 500/500**); native in Web Crypto; IV uniqueness verified (**T1.6**) |
| AAD | container header ‖ docId ‖ ownerId | Stops header edits and ciphertext swapping between documents (**T2.1, T2.8**) |
| Key wrapping | RSA-OAEP-2048, SHA-256 | Lets the owner wrap a key for a recipient using only their public key; universally available in Web Crypto |
| Password handling | PBKDF2-SHA256 (600 000 rounds, OWASP 2023 guidance) → HKDF split into authKey and KEK | The password never leaves the browser; the server sees only authKey and stores scrypt(authKey) ([`passwords.js`](../server/lib/passwords.js)) |
| Private key at rest | AES-GCM-wrapped with the KEK, AAD = userId | Server-side storage without server-side access; wrong password fails (**T5.1**) |
| Audit integrity | HMAC-SHA256 chain, key outside the DB, append-only triggers, external anchor | A database writer cannot recompute hashes without the key ([`audit.js`](../server/engine/audit.js)) |
| Watermark | HMAC-signed `VS1.<downloadId>.<tag>`, visible + invisible | Traces a leak to one download; forgeries rejected (**FR-5.2**) |
| No key escrow | Deliberate | True end-to-end confidentiality; trade-off documented (**T5.2–T5.5**, [limitations](limitations-ethics.md)) |

## 4. Functional requirements

| FR | Implementation | Evidence |
|---|---|---|
| FR-1 Accounts and roles | Admin-issued one-time enrollment codes; key pair generated in the user's browser; decoy salts against enumeration; idle/absolute session expiry; CSRF tokens; rate limits | [`auth.js`](../server/api/routes/auth.js); `api-auth.test.js` (16 tests); **T3.6, T-final.11**; screenshot `img/signin.png` |
| FR-2 AES-GCM encryption | Client magic-byte check → encrypt → server type/size policy and container validation | **T1.1, T2.1–T2.9, T-final.3–6**; `img/upload.png` |
| FR-3 Key wrapping | Owner key wrapped at upload, re-wrapped per recipient; fingerprint must match recipient's current key | **T1.3–T1.4**, `api-documents` "sharing to a stale fingerprint"; `img/share.png` |
| FR-4 Expiry / revocation | `evaluateDownload` rule order; atomic consumption; revocation erases wrapped key; delete crypto-shreds | **T4.1–T4.8, T-final.12**; `img/denied.png` |
| FR-5 Watermarking | Server-signed payload, client embedding for text/PDF/PNG/JPEG, browser-side extraction for tracing | **FR-5.1–5.2**; `unit-engine` PDF/PNG/text codec tests; `img/open.png`, `img/trace.png` |
| FR-6 Tamper-evident audit trail | HMAC chain, triggers, anchor, verification UI and CLI, export | **T-final.13–15**; `unit-audit.test.js`; `img/audit.png` |

Each FR validates input, reports a clear result (the verdict slip), and records security-relevant actions with secrets redacted ([`redact.js`](../server/engine/redact.js)).

## 5. Illustrative working example (spec page 3)

Reproduced exactly in the [demo script](demo-script.md) and in the evaluation:

1. alice signs in and uploads `quarterly-briefing.txt` → *Allowed, ALLOW_UPLOAD* (`img/upload.png`).
2. alice uploads `fixtures/adverse/not-really.pdf` → *Rejected, CONTENT_TYPE_MISMATCH, high severity*: "The file is named .pdf but its contents are plain text, not a PDF", with the detected type and first bytes as evidence and a recommended action — the specific indicator, not just "unsafe". The server makes and records this decision (**EX.2, EX.4**, `img/upload-reject.png`).
3. alice shares with victor for 1 minute; victor opens it → *Allowed, ALLOW_GRANT*, watermarked copy; after a minute → *Denied, GRANT_EXPIRED* with expiry and evaluation times (**T4.3**).
4. mallory (no grant) tries the same file → generic "not found", and `DOWNLOAD_DENY / NO_GRANT` is logged without revealing the file (**T3.2**).
5. Both outcomes appear side by side in **My decisions** (`img/history-compare.png`) and are exported as JSON/CSV with no keys or contents (**EX.5**).
6. admin lowers *Longest allowed share* to 2 hours (and the default to 1 hour) with a reason; alice's 3-hour share is now refused with `GRANT_TTL_OUT_OF_RANGE` under settings v2, while the `CONFIG_CHANGE` audit event shows the diff and reason (**T4.8**, `img/settings.png`).

## 6. Security evaluation

The threat model ([threat-model.md](threat-model.md)) lists **16 threats** mapped to mitigations and to the tests that show them working (the specification asks for at least eight).

| Defect class (acceptance criterion) | Status | Evidence |
|---|---|---|
| Authorization | None open | **T3.1** (0 false permits), **T3.2–T3.6**, **T-final.9**, `api-auth` role-change test |
| Injection | None open | Prepared statements only; **T-final.7–8**; DOM built with `textContent`; strict CSP; CSV formula neutralisation test |
| Secret exposure | None open | Password never sent; secrets outside DB; redaction tests; sanitised export test; no stack traces (**T-final.1**) |
| Unsafe file handling | None open | Allow-list + sanitiser + size limit + magic bytes; files never written to disk; **T-final.2–6** |

## 7. Measurements

From [`reports/evaluation.md`](../reports/evaluation.md) (laptop, Node 22; re-run with `npm run evaluate`):

| Measure | Result |
|---|---|
| Automated tests | 86 / 86 pass (100%) |
| Evaluation cases | 59 / 59 pass |
| Access control (rule-based) | 19/19 permissions, 57 requests: 27 correct allows, 30 correct denies, 0 false positives, 0 false negatives |
| Tamper detection | 500 / 500 random single-bit corruptions rejected (false-negative rate 0%) |
| Policy decision latency p95 | download ≈ 0.5 ms; share ≈ 1.0 ms; upload checks < 1 ms |
| Download round trip p95 | ≈ 11 ms (includes ciphertext transfer) |
| Audit verification | ≈ 170 events in < 10 ms |
| AES-256-GCM (Node Web Crypto) | 10 MB encrypt ≈ 23 ms, decrypt ≈ 17 ms |

## 8. Team allocation

| Member | Ownership | Main files |
|---|---|---|
| **Fatima Habib** — backend / data / authentication | repository layer, sessions, enrollment, API | `server/repo/`, `server/api/routes/auth.js`, `server/api/middleware.js` |
| **Khadija Bilal** — security engine / evaluation fixtures | policy, audit chain, watermark signing, crypto core, fixtures | `server/engine/`, `shared/`, `fixtures/` |
| **Sanniya Aslam** — frontend / reporting / integration | browser client, verdict slips, exports, admin screens | `public/`, `server/api/routes/sharing.js` |
| **Umer Farooq** — automation / security testing / packaging / QA | tests, evaluation harness, seed, docs | `tests/`, `scripts/`, `docs/` |

## 9. Limitations

Summarised from [limitations-ethics.md](limitations-ethics.md): the browser trusts the server-delivered code; no key escrow by design; watermarking deters and traces but cannot prevent leaks; revocation cannot recall saved copies; the server cannot scan encrypted content; metadata is visible; deployment beyond localhost needs TLS and managed keys.

## 10. Deliverables checklist

| Deliverable | Location in the submission package |
|---|---|
| Source and setup guide | `01-Source-and-Setup/` (source zip, Setup-Guide.pdf) |
| Sanitised sample data | `02-Sanitized-Sample-Data/` |
| Architecture / data-flow diagrams | `03-Architecture-and-Diagrams/` |
| Threat model | `04-Threat-Model/` |
| Test plan / results | `05-Test-Plan-and-Results/` |
| User and administrator guide | `06-User-and-Admin-Guide/` |
| Limitations and ethics | `07-Limitations-and-Ethics/` |
| Final report | `08-Final-Report/` (this document) |
| 10–15 minute demonstration | `09-Demo-Script/` |

## Appendix: screenshots

Captured from the running system with the demo accounts (Chromium, 1360 × 900).

| | |
|---|---|
| ![Sign in](img/signin.png) Sign-in: the password only unlocks the key locally | ![Enrollment](img/enroll.png) Enrollment: key pair created in the browser, fingerprint shown |
| ![Upload allowed](img/upload.png) FR-2 upload with `ALLOW_UPLOAD` evidence | ![Upload rejected](img/upload-reject.png) Adverse sample rejected with the specific indicator |
| ![Share](img/share.png) FR-3 share: re-wrapped key, recipient fingerprint | ![Open](img/open.png) FR-4/FR-5 open: `ALLOW_GRANT`, watermarked copy |
| ![Expired](img/denied.png) FR-4 `GRANT_EXPIRED` with times as evidence | ![Unauthorised](img/unauthorized.png) Unauthorised user: generic denial |
| ![Policy denial](img/policy-deny.png) Rule change applied: `GRANT_TTL_OUT_OF_RANGE` under settings v2 | ![Settings](img/settings.png) Versioned policy settings with history |
| ![Decisions](img/decisions.png) Decision history with explainable detail | ![Audit](img/audit.png) FR-6 audit trail, chain verified |
| ![Trace](img/trace.png) FR-5 leaked PDF traced to the download | ![People](img/people.png) One-time enrollment code issued |
| ![History](img/history-compare.png) Normal and adverse results compared in history | ![Data flow](img/dataflow.png) Data-flow diagram with trust boundaries |
| ![Dashboard](img/dashboard.png) Operator dashboard built from real data | ![Documents](img/documents.png) Document browser with search, filters and views |
| ![Mobile](img/mobile-dashboard.png) Phone layout (390px) | |
