# VaultShare evaluation results

Generated 2026-11-10T16:13:36.453Z on Node v22.22.0 by `npm run evaluate`.

**59 of 59 evaluation cases passed.** Automated test suite: **86/86 passed (100%)**.

## T1 — Confidentiality

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T1.1 | Stored ciphertext and database files contain no plaintext | upload "CONFIDENTIAL-SAMPLE: merger code…" as alice | marker string absent from DB, WAL and blob | marker absent | blob 94 B = 60 + 34 overhead; sha256 bb97b84d37209ddb… | PASS |
| T1.2 | Owner decrypts own document | alice opens t1-secret.txt | ALLOW_OWNER, plaintext identical | ALLOW_OWNER, identical=true | decision 5cc5db11 | PASS |
| T1.3 | Recipient decrypts with own key after share | alice → bob, 60 min, 3 downloads; bob opens | ALLOW_SHARE then ALLOW_GRANT, plaintext identical | ALLOW_SHARE / ALLOW_GRANT, identical=true | grant 7abf5489; wrapped DEK 256 B (RSA-OAEP-2048) | PASS |
| T1.4 | Stolen wrapped key is useless without the recipient's private key | mallory tries to unwrap bob's wrapped DEK taken from the database | DEK_UNWRAP_FAILED | DEK_UNWRAP_FAILED | RSA-OAEP decryption error | PASS |
| T1.5 | Administrator cannot obtain document keys | admin requests download | 403 FORBIDDEN (no doc.download permission) | 403 FORBIDDEN | ACCESS_DENIED audited | PASS |
| T1.6 | Fresh random 96-bit IV on every encryption | 20 encryptions of the same file with one key | 20 distinct IVs | 20 distinct | IV from crypto.getRandomValues | PASS |

## T2 — Altered-ciphertext rejection

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T2.1 | Single-bit flip in header magic is rejected | flip 1 bit at header magic (in transit) | decryption refused, no plaintext | CONTAINER_BAD_MAGIC | AES-GCM tag / container check | PASS |
| T2.2 | Single-bit flip in version byte is rejected | flip 1 bit at version byte (in transit) | decryption refused, no plaintext | CONTAINER_UNSUPPORTED_VERSION | AES-GCM tag / container check | PASS |
| T2.3 | Single-bit flip in IV is rejected | flip 1 bit at IV (in transit) | decryption refused, no plaintext | INTEGRITY_CHECK_FAILED | AES-GCM tag / container check | PASS |
| T2.4 | Single-bit flip in ciphertext body is rejected | flip 1 bit at ciphertext body (in transit) | decryption refused, no plaintext | INTEGRITY_CHECK_FAILED | AES-GCM tag / container check | PASS |
| T2.5 | Single-bit flip in GCM tag is rejected | flip 1 bit at GCM tag (in transit) | decryption refused, no plaintext | INTEGRITY_CHECK_FAILED | AES-GCM tag / container check | PASS |
| T2.6 | Random single-bit corruption of stored ciphertext | 500 random bit flips across the 713-byte container | 100% rejected | 500/500 rejected | false-negative rate 0 required | PASS |
| T2.7 | Ciphertext altered at rest is rejected end-to-end | flip 1 bit in SQLite blob, bob opens | INTEGRITY_CHECK_FAILED | INTEGRITY_CHECK_FAILED | server still released ciphertext (it cannot detect); client refused | PASS |
| T2.8 | Ciphertext swapped between documents is rejected | decrypt document B ciphertext with document A key/binding | INTEGRITY_CHECK_FAILED | INTEGRITY_CHECK_FAILED | AAD binds docId + ownerId | PASS |
| T2.9 | Server rejects a non-VaultShare container | 134 zero bytes declared as 100-byte file | CIPHERTEXT_MALFORMED | CIPHERTEXT_MALFORMED | {"declaredSize":100,"ciphertextBytes":134,"expectedBytes":134,"check":"CONTAINER_BAD_MAGIC"} | PASS |

## T3 — Access-control matrix

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T3.1 | Role × permission matrix enforced by the server | 57 requests (19/19 permissions × 3 roles) | 0 false permits, 0 false denies | 0 false permits, 0 false denies | 27 correct allows, 30 correct denies | PASS |
| T3.2 | Unauthorised operator gets a generic denial and the attempt is logged | mallory (no grant) requests download | 404 NOT_FOUND, no filename in response, audit NO_GRANT | 404 NOT_FOUND; leaks name=false | audit seq 92 rule NO_GRANT | PASS |
| T3.3 | Unauthenticated request refused | GET document without a session | 401 AUTH_REQUIRED | 401 AUTH_REQUIRED |  | PASS |
| T3.4 | Viewer cannot re-share a document shared with them | victor POST /grants | 403 FORBIDDEN | 403 FORBIDDEN | grant.create = operator only | PASS |
| T3.5 | Recipient operator cannot share a document they do not own | bob (recipient) tries to share to mallory | 404 (owner key not released) | 404 | owner-key endpoint is owner-only | PASS |
| T3.6 | Request with forged CSRF token refused | bob session, wrong X-CSRF-Token | 403 CSRF_FAILED | 403 CSRF_FAILED | synchronizer token + SameSite=Strict | PASS |

## T4 — Expiry, revocation and limits

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T4.1 | Grant valid before expiry | share 5 min; open at t+0 | ALLOW_GRANT | ALLOW_GRANT | expiresAt 2026-11-10T16:21:28.259Z | PASS |
| T4.2 | Grant valid 1 s before expiry (edge) | open at t+4m59s | ALLOW_GRANT | ALLOW_GRANT |  | PASS |
| T4.3 | Grant denied exactly at expiry | open at t+5m00s | GRANT_EXPIRED | GRANT_EXPIRED | {"expiresAt":"2026-11-10T16:21:28.259Z","evaluatedAt":"2026-11-10T16:21:28.272Z"} | PASS |
| T4.4 | Revocation is immediate and destroys the wrapped key | owner revokes, recipient retries | GRANT_REVOKED, wrapped key erased | GRANT_REVOKED, wrapped key erased=true | revoke→deny round trip 6.859 ms | PASS |
| T4.5 | Download limit enforced | limit 2, three attempts | allow, allow, DOWNLOAD_LIMIT_REACHED | ALLOW_GRANT, ALLOW_GRANT, DOWNLOAD_LIMIT_REACHED |  | PASS |
| T4.6 | Limit holds under 10 concurrent requests | limit 1, 10 parallel downloads | exactly 1 success | 1 success | atomic conditional UPDATE in a transaction | PASS |
| T4.7 | Expiry beyond policy maximum refused | share for 10081 min (max 10080) | GRANT_TTL_OUT_OF_RANGE | GRANT_TTL_OUT_OF_RANGE | {"recipient":"victor","requestedMinutes":10081,"maxMinutes":10080,"requestedDownloads":3,"maxDownloads":10} | PASS |
| T4.8 | Administrator rule change is applied and traceable | max_grant_ttl_hours 168 → 2 (default 24 → 1), then share 180 min and 120 min | deny under new version, allow within limit, CONFIG_CHANGE audited | GRANT_TTL_OUT_OF_RANGE (settings v2), ALLOW_SHARE | audit seq 133: {"max_grant_ttl_hours":{"from":168,"to":2},"default_grant_ttl_hours":{"from":24,"to":1}} | PASS |

## T5 — Key-loss behaviour

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T5.1 | Wrong password cannot open the key | sign in as kim with wrong password | AUTH_FAILED (generic) | 401 AUTH_FAILED | scrypt(authKey) mismatch; private key never unwrapped | PASS |
| T5.2 | After key reset, documents kim owned are unrecoverable | admin reset → kim re-enrolls (key v2) → opens own file | KEY_MISMATCH (no escrow by design) | KEY_MISMATCH | {"grantId":"58b25e93-2940-4427-84c6-565c3476d796","isOwnerGrant":true,"expiresAt":null,"evaluatedAt":"2026-11-10T16:22:29.815Z","downloadsUsed":0,"downloadLimit":null,"grantKeyVersion":1,"currentKeyVersion":2,"grantFingerprint":"bef01a86ff7cfa15","currentFingerprint":"61b2b73dd4563e9d"} | PASS |
| T5.3 | After key reset, grants to the old key are refused with an explanation | kim (v2) opens file shared to key v1 | KEY_MISMATCH | KEY_MISMATCH | grant key v1 vs current v2 | PASS |
| T5.4 | New private key cannot unwrap a DEK wrapped for the old key | force-unwrap stale wrapped DEK with key v2 | DEK_UNWRAP_FAILED | DEK_UNWRAP_FAILED | cryptographic, not just policy | PASS |
| T5.5 | Recovery path: owner re-shares to the new key | alice revokes stale grant and shares again | ALLOW_SHARE then plaintext restored | ALLOW_SHARE, plaintext=shared with kim |  | PASS |
| T5.6 | Key reset is audited | inspect audit trail | USER_RESET with previous key version | {"username":"kim","previousKeyVersion":1,"sessionsEnded":1} | seq 151 | PASS |

## Illustrative working example (spec page 3) — normal vs adverse sample, history, export, unauthorised viewer

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| EX.1 | Normal sample completes with evidence and no warning | alice uploads fixtures/samples/access-policy.pdf | ALLOW_UPLOAD, severity info | ALLOW_UPLOAD, severity info | {"declaredSize":4751,"ciphertextBytes":4785,"expectedBytes":4785,"containerVersion":1} | PASS |
| EX.2 | Seeded adverse sample names the specific indicator | alice uploads fixtures/adverse/not-really.pdf (text named .pdf) | CONTENT_TYPE_MISMATCH with the detected type, severity high | CONTENT_TYPE_MISMATCH: "The file is named .pdf but its contents are plain text, not a PDF." (high) | detected text, first bytes 5468697320697320; action: Do not upload this file. Its contents are not what its name says; check where it came from. | PASS |
| EX.3 | Disguised executable rejected | fixtures/adverse/report.pdf.exe | TYPE_NOT_ALLOWED | TYPE_NOT_ALLOWED |  | PASS |
| EX.4 | Both results are in history and the rejection is audited | alice's decision history; audit trail | allowed and rejected rows present; DOC_UPLOAD_REJECTED event | history both=true; audit seq 162 | {"filename":"not-really.pdf","rule":"CONTENT_TYPE_MISMATCH","severity":"high","detected":"text","decisionId":"bd58ceee-358b-4549-87cd-d8fc23ccaae8"} | PASS |
| EX.5 | Sanitised report export contains both results | export CSV | both rules present, no keys or contents | contains rejection=true, sanitised=true | ts,actor,action,subject,decision,severity,rule,reason,recommendedAction,configVersion,latencyMs,id | PASS |
| EX.6 | Unauthorised user gets a generic denial; attempt logged without the record | mallory opens alice's document | 404 generic, ACCESS_DENIED logged without filename | 404 NOT_FOUND; audit seq 165 | {"permission":"doc.read_meta","reason":"no_grant"} | PASS |
| EX.7 | Client-detected tampering is recorded server-side | flip 1 bit in transit; browser reports the failure | INTEGRITY_CHECK_FAILED decision (high) + audit event | INTEGRITY_CHECK_FAILED (high); audit seq 167 | {"downloadId":"713815bf-a4f7-4bf8-b0e8-9aed69099945","check":"INTEGRITY_CHECK_FAILED","decisionId":"691ce316-af84-4810-ade1-9fcc75e85462"} | PASS |

## T-final — Malformed/oversized input, unauthorised and repeated requests, safe failure, restart

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| T-final.1 | Malformed JSON | truncated JSON body | 400 MALFORMED_JSON, no stack trace | 400 MALFORMED_JSON | requestId 80f13071 | PASS |
| T-final.2 | Oversized request body | 33 MB JSON body | 413 PAYLOAD_TOO_LARGE | 413 PAYLOAD_TOO_LARGE | express.json limit 32 MB | PASS |
| T-final.3 | File larger than policy limit | declare 11 MB PDF (limit 10 MB) | FILE_TOO_LARGE | FILE_TOO_LARGE | {"extension":"pdf","mimeType":"application/pdf","sizeBytes":11534336,"maxBytes":10485760,"allowed":["txt","md","csv","pdf","png","jpg","jpeg"],"detectedContent":"pdf","firstBytes":"255044462d312e37"} | PASS |
| T-final.4 | Unsafe file name/type rejected: report.pdf.exe | report.pdf.exe as application/octet-stream | TYPE_NOT_ALLOWED | TYPE_NOT_ALLOWED |  | PASS |
| T-final.5 | Unsafe file name/type rejected: invoice.exe.pdf | invoice.exe.pdf as application/pdf | TYPE_NOT_ALLOWED | TYPE_NOT_ALLOWED |  | PASS |
| T-final.6 | Unsafe file name/type rejected: notes.pdf | notes.pdf as text/plain | TYPE_NOT_ALLOWED | TYPE_NOT_ALLOWED |  | PASS |
| T-final.7 | Unexpected fields (mass assignment) rejected | extra field isAdmin:true | 400 VALIDATION_FAILED UNKNOWN_FIELD | 400 UNKNOWN_FIELD |  | PASS |
| T-final.8 | Injection-shaped input treated as data | username x'); DROP TABLE users;-- | 400 VALIDATION_FAILED; users table intact | 400; users=6 | parameterised statements + allow-list pattern | PASS |
| T-final.9 | Unauthorised request | viewer calls admin audit API | 403 FORBIDDEN + ACCESS_DENIED logged | 403; audit seq 177 | {"permission":"audit.read","method":"GET","path":"/audit"} | PASS |
| T-final.10 | Repeated submission | same share twice; same upload twice | 201 then 409 DUPLICATE_ACTIVE_GRANT; 409 ALREADY_UPLOADED | 201, 409 DUPLICATE_ACTIVE_GRANT; 409 ALREADY_UPLOADED |  | PASS |
| T-final.11 | Brute-force sign-in throttled | 11 wrong attempts in 15 min | 429 RATE_LIMITED with Retry-After | 429 retry-after=900s | RATE_LIMITED audited | PASS |
| T-final.12 | Safe failure after deletion (crypto-shred) | owner deletes shared file; recipient retries | denied; ciphertext and wrapped keys erased | DOCUMENT_UNAVAILABLE; blob=NULL | secure_delete pragma on | PASS |
| T-final.13 | Audit chain verifies before restart | 201 events | CHAIN_INTACT | CHAIN_INTACT | head 067a921cd02345f4… in 4 ms | PASS |
| T-final.14 | Recovery after restart | stop server, start on same data directory, bob opens file | data intact, chain intact, file decrypts | chain CHAIN_INTACT; plaintext ok=true | startup self-check: CHAIN_INTACT | PASS |
| T-final.15 | Audit tampering detected | attacker drops trigger and rewrites event 92 (DOWNLOAD_DENY → success) | HASH_MISMATCH at seq 92 | HASH_MISMATCH at seq 92 | HMAC key held outside the database | PASS |

## FR-5 — Watermark tracing

| ID | Case | Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|---|---|
| FR-5.1 | Leaked excerpt traces to recipient and download | 20-line excerpt without the visible banner | WATERMARK_VERIFIED → bob | WATERMARK_VERIFIED → bob | download 448b6a19 | PASS |
| FR-5.2 | Forged watermark rejected | alter last 4 chars of tag | WATERMARK_FORGED | WATERMARK_FORGED |  | PASS |

## Measurements

### Access-control matrix (rule-based)

| Requests | Correct allow | Correct deny | False permit | False deny | Coverage |
|---|---|---|---|---|---|
| 57 | 27 | 30 | 0 | 0 | 19/19 permissions probed over HTTP |

<details><summary>All 57 matrix requests</summary>

| Permission | Role | Expected | Actual | HTTP |
|---|---|---|---|---|
| doc.upload | admin | deny | deny | 403 |
| doc.upload | operator | allow | allow | 201 |
| doc.upload | viewer | deny | deny | 403 |
| doc.list | admin | deny | deny | 403 |
| doc.list | operator | allow | allow | 200 |
| doc.list | viewer | allow | allow | 200 |
| doc.read_meta | admin | deny | deny | 403 |
| doc.read_meta | operator | allow | allow | 200 |
| doc.read_meta | viewer | allow | allow | 200 |
| doc.download | admin | deny | deny | 403 |
| doc.download | operator | allow | allow | 200 |
| doc.download | viewer | allow | allow | 200 |
| doc.delete | admin | deny | deny | 403 |
| doc.delete | operator | allow | allow | 404 |
| doc.delete | viewer | deny | deny | 403 |
| grant.create | admin | deny | deny | 403 |
| grant.create | operator | allow | allow | 404 |
| grant.create | viewer | deny | deny | 403 |
| grant.revoke | admin | allow | allow | 404 |
| grant.revoke | operator | allow | allow | 404 |
| grant.revoke | viewer | deny | deny | 403 |
| directory.read | admin | deny | deny | 403 |
| directory.read | operator | allow | allow | 200 |
| directory.read | viewer | deny | deny | 403 |
| decision.read_own | admin | allow | allow | 200 |
| decision.read_own | operator | allow | allow | 200 |
| decision.read_own | viewer | allow | allow | 200 |
| decision.read_all | admin | allow | allow | 200 |
| decision.read_all | operator | deny | deny | 200 |
| decision.read_all | viewer | deny | deny | 200 |
| report.export_own | admin | allow | allow | 200 |
| report.export_own | operator | allow | allow | 200 |
| report.export_own | viewer | allow | allow | 200 |
| report.export_all | admin | allow | allow | 200 |
| report.export_all | operator | deny | deny | 200 |
| report.export_all | viewer | deny | deny | 200 |
| user.manage | admin | allow | allow | 200 |
| user.manage | operator | deny | deny | 403 |
| user.manage | viewer | deny | deny | 403 |
| config.read | admin | allow | allow | 200 |
| config.read | operator | deny | deny | 403 |
| config.read | viewer | deny | deny | 403 |
| config.write | admin | allow | allow | 409 |
| config.write | operator | deny | deny | 403 |
| config.write | viewer | deny | deny | 403 |
| audit.read | admin | allow | allow | 200 |
| audit.read | operator | deny | deny | 403 |
| audit.read | viewer | deny | deny | 403 |
| audit.verify | admin | allow | allow | 200 |
| audit.verify | operator | deny | deny | 403 |
| audit.verify | viewer | deny | deny | 403 |
| audit.export | admin | allow | allow | 200 |
| audit.export | operator | deny | deny | 403 |
| audit.export | viewer | deny | deny | 403 |
| watermark.trace | admin | allow | allow | 200 |
| watermark.trace | operator | deny | deny | 403 |
| watermark.trace | viewer | deny | deny | 403 |

</details>

### Tamper detection

500/500 random single-bit corruptions rejected (false-negative rate 0%).

### Policy decision latency (server-side, ms)

| Decision type | n | p50 | p95 | max |
|---|---|---|---|---|
| upload | 24 | 0.144 | 0.322 | 1.14 |
| upload_content | 18 | 0.111 | 0.525 | 0.525 |
| download | 96 | 0.104 | 0.178 | 0.457 |
| share | 18 | 0.174 | 0.532 | 0.532 |
| decrypt | 7 | 0.13 | 0.21 | 0.21 |
| audit_verify | 1 | 2.572 | 2.572 | 2.572 |
| watermark_trace | 3 | 0.404 | 0.449 | 0.449 |

Download request round trip (client-observed, includes JSON transfer): p50 2.889 ms, p95 4.791 ms over 60 requests.

Audit chain verification: 201 events in 4 ms.

### AES-256-GCM throughput (Node Web Crypto on this machine)

| Size | Encrypt ms | Decrypt ms |
|---|---|---|
| 1 MB | 1.16 | 1.141 |
| 5 MB | 5.025 | 5.17 |
| 10 MB | 16.168 | 11.485 |

Browser figures differ by device; the demonstration shows the in-browser timing for the sample files.
