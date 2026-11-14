# Threat model

**Assets:** document plaintext; document keys (DEKs); users' private keys and passwords; grant state (who may open what, until when); the audit trail as evidence; watermark keys.

**Actors:** an outsider on the network or with a stolen laptop file; a curious or malicious *authenticated* user (Mallory); a legitimate recipient who leaks a copy; an administrator who should manage but not read; an attacker with write access to the database file.

**Assumptions:** the server runs on `127.0.0.1` for the demonstration (production would add TLS); the user's browser and device are not compromised; the server code served to the browser is trusted (see limitation L1).

Trust boundaries are drawn in the [data-flow diagram](architecture.md#data-flow-diagram-with-trust-boundaries).

## Threats and mitigations

| # | STRIDE | Threat | Mitigation | Evidence |
|---|---|---|---|---|
| T-01 | Information disclosure | Database or backup theft reveals document contents | Client-side AES-256-GCM; server stores only ciphertext and DEKs wrapped to RSA-OAEP public keys; private keys stored only wrapped with a password-derived KEK | eval T1.1, T1.4; `api-documents` "T1: plaintext never reaches…" |
| T-02 | Information disclosure | Database theft enables offline password cracking or login | Password never sent; server stores scrypt(authKey) where authKey is already PBKDF2-600k + HKDF; per-user salts | `api-auth` "server never stores the password…" |
| T-03 | Tampering | Ciphertext altered in storage or transit, or swapped between documents | GCM tag over ciphertext with AAD = header ‖ docId ‖ ownerId; client refuses to decrypt and reports it (audited, high severity); server checks structure and exact length | eval T2.1–T2.9 (500/500 random flips caught), EX.7 |
| T-04 | Elevation of privilege | Viewer or operator calls admin or other users' functions | Server-side permission matrix on every route (`requirePerm`), ownership checks, admins hold no document keys | eval T3.1 (36 requests, 0 false permits), `unit-engine` matrix test |
| T-05 | Information disclosure | Probing for documents or accounts (enumeration) | Generic 404 for documents without a grant and for malformed IDs; identical sign-in errors; decoy KDF salts for unknown users; scrypt run even for unknown users | eval T3.2; `api-auth` prelogin and wrong-password tests |
| T-06 | Spoofing | Password guessing / credential stuffing | Per-IP+username rate limit (configurable), generic errors, audit of every failure | eval T-final.11 |
| T-07 | Spoofing / tampering | Cross-site request forgery | SameSite=Strict HttpOnly cookie, per-session synchronizer token, JSON-only bodies, Origin check | eval T3.6; `api-auth` CSRF and origin tests |
| T-08 | Tampering / injection | SQL injection, mass assignment, XSS through file names or details | Prepared statements only; strict schemas reject unknown fields; allow-listed patterns; DOM built with `textContent` only; strict CSP (`script-src 'self'`, no inline) | eval T-final.7–8; `api-documents` SQL-injection test |
| T-09 | Elevation / DoS | Unsafe uploads: wrong type, double extensions, disguised content, oversize, empty | Extension + MIME allow-list (admin-configurable), filename sanitiser, size limit, server-side first-bytes rule (`CONTENT_TYPE_MISMATCH`, high severity, audited), 32 MB body cap; files never touch the filesystem | eval EX.2–3, T-final.2–6 |
| T-10 | Information disclosure | Access continues after it should end | Expiry checked at every open; revocation nulls the wrapped key; atomic download counting stops concurrent over-use; delete crypto-shreds ciphertext | eval T4.1–T4.8, T-final.12 |
| T-11 | Spoofing | Server or admin substitutes a recipient public key to intercept a share | Fingerprint shown before sharing for out-of-band comparison; grant must carry the recipient's *current* fingerprint; client recomputes it from the fetched key | `api-documents` "T5: sharing to a stale fingerprint is refused" |
| T-12 | Repudiation | Audit records altered or deleted to hide activity | HMAC-SHA256 hash chain with key outside the DB; SQLite triggers block UPDATE/DELETE; sequence-gap and anchor checks; startup self-check | `unit-audit` (edit, delete, truncate), eval T-final.15 |
| T-13 | Information disclosure | A legitimate recipient leaks a decrypted copy | Per-download HMAC-signed watermark, visible and invisible, repeated through text; admin trace identifies recipient, grant and time; forged payloads rejected | eval FR-5.1–5.2 |
| T-14 | Information disclosure | Secrets or personal data leak through logs, errors or exports | Redaction of key/secret fields before logging; IPs stored as keyed hashes; errors return codes and request IDs, never stack traces; CSV formula neutralisation | `unit-engine` redaction test; `api-documents` "exported report is sanitised" |
| T-15 | Denial of service | Session hijack window or abandoned sessions | 32-byte random tokens stored hashed; idle (30 min) and absolute (8 h) expiry; sessions ended on password change, role change, disable and reset | `api-auth` idle-expiry, role-change and disable tests |
| T-16 | Availability / integrity | Key loss locks data | Documented, intentional: no escrow. Reset issues a new key, stale grants are explained as `KEY_MISMATCH`, owners re-share | eval T5.1–T5.6 |

## Residual risks

- **Malicious server code (L1).** A browser-based E2E system trusts the JavaScript the server sends. A compromised server could ship code that exfiltrates keys. Mitigation in production: signed releases, Subresource Integrity, or a packaged client.
- **Watermark removal.** A determined recipient can modify the client, screenshot, or strip zero-width characters. The watermark deters and traces casual leaks; it is not DRM-grade enforcement.
- **Server cannot content-scan.** Because it never sees plaintext, the server cannot detect malware inside uploads. It decides on the first bytes the uploader's browser reports, so an uploader who modifies the client can lie about them; the check protects honest users from mislabelled files, not against a malicious uploader. Recipients open files in the browser's sandboxed viewers.
- **Local-only transport.** The demo uses HTTP on loopback. Any non-local deployment must add TLS and set `VS_SECURE_COOKIES=1`.
- **Metadata is visible.** File names, sizes, sharing relationships and timing are visible to the server operator.
