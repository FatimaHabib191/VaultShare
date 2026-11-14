# VaultShare — Encrypted Document Exchange

Class 1, Group 4 · Cryptography and Digital Rights Management

VaultShare is a browser-based document exchange. Files are encrypted **in the browser** with AES-256-GCM before upload, each file key is **wrapped** separately for every recipient with RSA-OAEP, access grants **expire, can be revoked and have download limits**, every opened copy carries a **traceable watermark**, and every security-relevant action is written to a **tamper-evident, hash-chained audit trail**. Every allow/deny result is an explainable decision that records the rule, the evidence and the settings version that produced it.

It runs entirely on a laptop: Node.js, Express, SQLite (Node's built-in `node:sqlite`) and the Web Crypto API. No paid services, no Docker required.

## Quick start

Requirements: **Node.js 22.13 or newer** (check with `node --version`; Node 24 LTS recommended) and a current Chrome, Edge or Firefox. No compiler or native build tools are needed.

```bash
npm install          # 4 small runtime packages (express, pdf-lib, 2 font packages); SQLite is built into Node
npm run seed         # creates the demo accounts and one shared sample file
npm start            # http://localhost:3000
```

Open <http://localhost:3000> and sign in with one of the demo accounts the seed script prints:

| Role | Username | Password | Use it to show |
|---|---|---|---|
| Administrator | `admin` | `Admin#Vault2026` | people, policy settings, audit trail, leak tracing |
| Operator | `alice` | `Alice#Vault2026` | upload, share, revoke |
| Operator | `bob` | `Bob#Vault2026!` | receive and open a shared file |
| Viewer | `victor` | `Victor#Vault2026` | restricted, receive-only access |
| Operator | `mallory` | `Mallory#Vault2026` | the unauthorised user (no grants) |

These passwords exist only for the local demonstration. `npm run reset` wipes `data/` and seeds again.

To start without demo accounts, run `node scripts/seed.js --admin-only`; it prints a one-time enrollment code for `admin`, which you redeem through **Set up your account** on the sign-in screen.

### Opening in VS Code

Open the folder, run the three commands above in the integrated terminal, then use **Run and Debug → Node.js** on `server/server.js` if you want breakpoints. Everything listens on `127.0.0.1` only.

## Commands

| Command | What it does |
|---|---|
| `npm start` | Start the server on `127.0.0.1:3000` (`PORT`, `HOST`, `VS_DATA_DIR` override) |
| `npm run seed` / `npm run reset` | Create demo data / wipe and recreate it |
| `npm test` | 86 automated unit and integration tests (`node:test`) |
| `npm run evaluate` | Runs the mandatory evaluation cases T1–T5 and T-final, measures latency and error rates, writes `reports/evaluation.md` and `.json` |
| `npm run verify-audit` | Verifies the audit hash chain from the command line (works while the server is stopped) |

## Project layout

```
server/
  api/            API layer: routes, sessions, CSRF, permissions, rate limits, safe errors
  engine/         security engine: policy rules, access matrix, audit chain, watermark signing,
                  validation, settings, redaction (pure, independently testable)
  repo/           repository layer: SQLite schema and all SQL (parameterised)
  lib/            secrets, password hashing, error codes
shared/           crypto core + watermark codec, identical code in browser and Node
public/           browser client (vanilla JS modules, no framework), strict CSP
  css/app.css     the design system: tokens, components, layouts, responsive rules
  js/ui.js        shared components (buttons, chips, cards, decision card, dialogs, drawer, menus, toasts)
  js/icons.js     generated Lucide icon subset (scripts/build/icons.mjs)
  js/views/       one module per area: auth, dashboard, documents, history, admin
fixtures/         safe sample inputs (samples/) and adverse inputs (adverse/)
scripts/          seed, evaluation harness, audit verifier, headless client
tests/            automated tests
docs/             architecture, threat model, test plan, guides, report, demo script
reports/          generated evaluation evidence
data/             created at runtime: database, secrets.json, audit anchor (git-ignored)
```

## Interface

One design system drives every page: Inter type, a light-first palette with a single violet accent (green, amber and red are used only for status), a white sidebar, and a sticky header with breadcrumbs, search and an account menu. Shared components include buttons, inputs, status chips, cards, tables, dialogs, a side drawer, dropdown menus, toasts, skeleton loaders and empty states. Status is always shown with an icon and a word, never by colour alone.

- **Operators** get a dashboard (real counts, recent documents and activity, key status), a document browser (search, type filter, sort, grid or list view), multi-file upload with per-file progress and retry, and a document page with sharing, access management and a watermarked preview.
- **Viewers** see the same dashboard and their shared files.
- **Administrators** get an overview (needs-review list, decisions by rule, permission matrix), people management (search, role filter, add-person dialog with a copyable one-time code), grouped policy settings with change history, a paginated audit trail with chain verification, and leak tracing.

It works from 375px phones to wide desktops (the sidebar becomes a drawer, tables become stacked cards), supports keyboard use, dark mode (it follows the computer's light/dark setting) and reduced motion, and keeps the strict Content-Security-Policy: no inline scripts or styles, no external resources (fonts and icons are served locally).

## Documentation

- [Architecture and data flow](docs/architecture.md) — layers, data model, schemas, trust boundaries
- [Threat model](docs/threat-model.md) — 16 threats mapped to mitigations and tests
- [API reference](docs/api.md) — endpoints, error codes, decision and audit formats
- [Test plan and results](docs/test-plan.md) and the generated [evaluation results](reports/evaluation.md)
- [User guide](docs/user-guide.md) and [administrator guide](docs/admin-guide.md)
- [Limitations and ethics](docs/limitations-ethics.md)
- [Final report](docs/final-report.md)
- [Demonstration script](docs/demo-script.md) (12 minutes)

## Troubleshooting

| Problem | Fix |
|---|---|
| "VaultShare needs Node.js 22.13 or newer" | Install the current LTS from nodejs.org, open a new terminal, run `npm install` again |
| "Port 3000 is already in use" | VaultShare is already running in another terminal: close it, or run `PORT=3001 npm start` (PowerShell: `$env:PORT=3001; npm start`) |
| A demo password stops working | Too many wrong attempts or a key reset: run `npm run reset` |
| "Too many attempts, try again in …" | Rate limit: wait a minute, or run `npm run reset` before a demo |

## Recovery

- **Server crash or restart:** state lives in `data/vaultshare.db` (SQLite, WAL, `synchronous=FULL`). On start the server deletes expired sessions and abandoned half-uploads, verifies the audit chain and records the result in a `SYSTEM_START` event.
- **Back up** by stopping the server and copying the whole `data/` folder. `secrets.json` must travel with the database: without it the audit chain and watermarks cannot be verified.
- **Forgotten password:** there is no recovery by design. An administrator issues a new enrollment code (People → Reset key); documents shared to the old key must be shared again by their owners, and documents the person owned are unrecoverable. See [limitations](docs/limitations-ethics.md).
- **Audit verification fails:** do not keep using the instance as evidence. Export the audit trail, preserve `data/`, and compare with the last exported head hash (see the administrator guide).
