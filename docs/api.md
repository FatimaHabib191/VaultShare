# API reference

All endpoints are under `/api`, accept and return JSON, and send `Cache-Control: no-store`. State-changing requests (`POST`, `PUT`, `DELETE`) must use `Content-Type: application/json`, must not carry a foreign `Origin`, and — once signed in — must send the session's `X-CSRF-Token`.

## Errors

```json
{ "error": { "code": "POLICY_DENIED", "message": "The grant passed its expiry time.", "requestId": "…", "decision": { … }, "details": [ { "field": "…", "rule": "…", "message": "…" } ] } }
```

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_FAILED` | 400 | Field-level problems in `details` |
| `MALFORMED_JSON` | 400 | Body is not valid JSON |
| `ENROLLMENT_INVALID` | 400 | Code wrong, used or expired |
| `AUTH_REQUIRED` / `SESSION_EXPIRED` | 401 | No session / session ended |
| `AUTH_FAILED` | 401 | Generic sign-in failure |
| `CSRF_FAILED` | 403 | Missing/invalid token or foreign origin |
| `FORBIDDEN` | 403 | Role lacks the permission |
| `POLICY_DENIED` | 403 | A policy rule denied the request; `decision` explains which |
| `NOT_FOUND` | 404 | Missing **or** not visible to you (deliberately indistinguishable) |
| `CONFLICT` | 409 | Duplicate grant, already uploaded, already revoked |
| `PAYLOAD_TOO_LARGE` | 413 | Body or declared file over the limit |
| `UNSUPPORTED_TYPE` | 415 | File type not allowed |
| `RATE_LIMITED` | 429 | `Retry-After` header and `retryAfter` seconds |
| `INTERNAL_ERROR` | 500 | Logged as `SERVER_ERROR`; no internals returned |

## Authentication

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/auth/prelogin` | `{ username }` | `{ kdfSalt, kdfIterations, userId }` (decoy values for unknown users) |
| POST | `/auth/login` | `{ username, authKey(b64, 32 B) }` | sets `vs_sid` cookie; `{ user, csrfToken, keys:{ wrappedPrivateKey, wrapIv, publicKey } }` |
| POST | `/auth/logout` | `{}` | ends session |
| GET | `/auth/me` | — | current user, CSRF token, KDF params, wrapped key (or `{ user: null }`) |
| POST | `/auth/enroll/start` | `{ username, code }` | `{ userId, role, kdfSalt, kdfIterations }` |
| POST | `/auth/enroll/complete` | `{ username, code, authKey, publicKey(SPKI b64), wrappedPrivateKey, wrapIv }` | 201, signed in |
| POST | `/auth/password` | `{ currentAuthKey, newAuthKey, wrappedPrivateKey, wrapIv }` | other sessions ended |

## Documents and sharing

| Method | Path | Permission | Body / notes |
|---|---|---|---|
| GET | `/documents` | doc.list | `{ owned[], shared[] }` |
| GET | `/documents/policy` | doc.list | live upload/share limits `{ allowedExtensions, maxFileSizeMb, maxGrantHours, defaultGrantHours, maxDownloads, settingsVersion }` |
| POST | `/documents` | doc.upload | `{ filename, mimeType, sizeBytes, content:{ headHex, utf8, hasNul } }` → `{ id, binding, decision }` |
| PUT | `/documents/:id/content` | doc.upload | `{ ciphertext(b64 container), wrappedKey(b64 256 B) }` |
| GET | `/documents/:id` | doc.read_meta | owner sees all grants; recipients see their own |
| DELETE | `/documents/:id` | doc.delete | `{ confirm: true }`; revokes all grants and erases ciphertext |
| GET | `/documents/:id/owner-key` | grant.create | owner's own wrapped DEK, for re-wrapping |
| POST | `/documents/:id/grants` | grant.create | `{ recipientId, wrappedKey, recipientKeyFingerprint(64 hex), expiresInMinutes, maxDownloads }` |
| POST | `/documents/:id/download` | doc.download | `{}` → `{ ciphertext, wrappedKey, binding, watermark:{ payload, label, downloadId }, decision }` |
| POST | `/documents/:id/integrity-failure` | doc.download | `{ downloadId, check }` — browser reports a failed AES-GCM check; recorded as a decision and `DOWNLOAD_INTEGRITY_FAILURE` |
| POST | `/grants/:id/revoke` | grant.revoke | `{ confirm: true, reason? }` (owner, or admin for incident response) |
| GET | `/directory` | directory.read | active non-admin users with fingerprints |
| GET | `/directory/:id/public-key` | directory.read | SPKI public key |

## History and reports

| Method | Path | Notes |
|---|---|---|
| GET | `/decisions?decision=&severity=&action=&rule=&from=&to=&scope=all&actor=` | own decisions; admins may pass `scope=all` |
| GET | `/reports/export?format=json\|csv&scope=all` | sanitised export; admin `scope=all` includes an audit verification result |

## Administration (admin role)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/admin/overview` | counts, decision statistics, versions, permission matrix, rule catalogue |
| GET | `/admin/users` | list |
| POST | `/admin/users` | `{ username, role }` → one-time `enrollmentCode` |
| POST | `/admin/users/:id/reset` | `{ confirm: true }` → new enrollment code, new key version |
| POST | `/admin/users/:id/status` | `{ status: active\|disabled, confirm: true }` |
| POST | `/admin/users/:id/role` | `{ role, confirm: true }` |
| GET / PUT | `/admin/settings` | PUT `{ changes:{…}, reason, confirm: true }` |
| GET | `/admin/audit?action=&outcome=&actor=&from=&to=&limit=` | newest first |
| POST | `/admin/audit/verify` | full chain verification; updates the anchor |
| GET | `/admin/audit/export` | full chain + verification + head hash |
| POST | `/admin/trace` | `{ payload }` → recipient, document, grant, time if the HMAC verifies |
