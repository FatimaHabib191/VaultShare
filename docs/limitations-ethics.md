# Limitations and ethics statement

## Technical limitations

| # | Limitation | Consequence | What production would add |
|---|---|---|---|
| L1 | Browser E2E encryption trusts the JavaScript the server delivers | A compromised server could ship code that steals keys | Signed releases, Subresource Integrity pinning, or a packaged desktop client |
| L2 | No key escrow or password recovery | Forgotten password = files owned by that person are lost; shares must be re-made | Optional organisational recovery key or Shamir-split escrow, with its own audit |
| L3 | Watermarking happens in the client | A modified client, screenshots or retyping can avoid it; zero-width characters can be stripped | Server-rendered view-only previews for high-risk files; DRM viewers (with their own trade-offs) |
| L4 | Revocation cannot recall copies already downloaded | A recipient keeps what they saved before revocation | Short default expiries; view-only mode; watermark tracing (implemented) |
| L5 | Server cannot scan encrypted content | Malware inside a file cannot be detected server-side; the server's content-type rule relies on first bytes reported by the uploader's browser, which a modified client could falsify | Client-side scanning or a separate trusted scanning step before encryption |
| L6 | Metadata (file names, sizes, who shares with whom, timing) is visible to the operator | Traffic analysis is possible | Encrypted file names, padding |
| L7 | Public-key authenticity relies on users comparing fingerprints | An attacker controlling the server could substitute keys if nobody checks | Key transparency log, or certificates signed by an organisational CA |
| L8 | Single-node SQLite, in-memory rate limits, HTTP on loopback | Not built for multiple servers or Internet exposure | TLS, shared rate-limit store, managed database, HSM/KMS for the audit and watermark keys |
| L9 | RSA-2048 and PBKDF2 are chosen for Web Crypto availability | Adequate today; not post-quantum; PBKDF2 is not memory-hard | Hybrid post-quantum KEM when browsers support it; Argon2id via WASM |
| L10 | Audit anchor is a local file | An attacker with full disk access and the key could rewrite both | Periodic export of the head hash to write-once storage or a third party |

## Ethics statement

**Purpose.** VaultShare protects confidential documents and gives owners control and evidence. Its watermarking and audit features are accountability tools for documents people are entrusted with — not tools for monitoring people's private lives.

**Data minimisation.** The server never receives passwords or file contents. Logs exclude secrets, keys and ciphertext; IP addresses are stored only as keyed hashes; exports are sanitised. Usernames and timestamps are retained because accountability needs them.

**Transparency to recipients.** Every watermark is visible as well as invisible, so a recipient knows their copy is traceable. The user guide says so explicitly. Covert tracking of individuals would be inappropriate.

**Administrator power is bounded.** Administrators cannot read documents. Their actions (role changes, resets, setting changes, revocations, audit exports and traces) are themselves audited and cannot be erased without detection.

**Honest failure.** Key loss is permanent by design, and the interface states this before enrollment and before a reset rather than implying recovery is possible.

**Test data and scope.** All sample and adverse files are invented and contain no real personal data. All testing ran against local instances only; no external systems were targeted, and no real attack tooling was deployed, in line with the project's scope boundary.

**Misuse considerations.** Strong encryption can also hide wrongdoing. VaultShare keeps sharing relationships and actions auditable to the organisation while keeping contents private, which balances confidentiality against legitimate oversight.
