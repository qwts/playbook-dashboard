# AGENTS.md

Canonical, vendor-neutral agent context for this repository, per
[ENG-0006](https://github.com/qwts/playbook-engineering/blob/main/docs/decisions/ENG-0006-agentic-primitives-governance.md).
Vendor-specific files (Copilot instructions, Cursor rules, and similar) are
thin adapters onto this file — they never restate what is here.

## Shared agent conventions

PR-first workflow, validation-before-push, commit and PR hygiene, and the
untrusted-input threat model are defined once, for every repo, in the
[org-wide agent conventions](https://github.com/qwts/playbook-engineering/blob/main/docs/reference/agent-conventions.md).
This repository is governed by
[playbook-engineering](https://github.com/qwts/playbook-engineering) — shared
SOPs and decisions there apply here by default
([ENG-0008](https://github.com/qwts/playbook-engineering/blob/main/docs/decisions/ENG-0008-shared-sop-inheritance.md):
inherit by default, vary by explicit delta).

## What is specific to this repository

**Product.** Public, redacted fleet dashboard for governed `qwts` repos. It
visualizes security *counts*, manifest properties, and CI conclusions. It must
never publish alert titles, file paths, CVEs, secret material, or private
vulnerability report bodies.

**Stack.** Vite + React + TypeScript. `npm run dev` serves local HTTPS;
`npm run build` produces the Pages artifact; `npm run collect` rebuilds
`public/data/snapshot.json` from GitHub APIs; `npm run ci` is typecheck + build.

**Local TLS.** Certs live under `~/.quorum/certs` (CN `local.dev.zts1.com`).
The encrypted key passphrase is loaded only through the environment variable
`DASHBOARD_TLS_KEY_PASSPHRASE` — never hardcode or log it. `scripts/dev.mjs`
reads `~/.quorum/certs/key.passphrase` (or `DASHBOARD_TLS_KEY_PASSPHRASE_FILE`)
into that env var when unset. Bind `127.0.0.1`, browse
`https://local.dev.zts1.com:8443/` (port **8443**, not 443).

**Redaction contract.** Collector and UI share the `Snapshot` schema in
`src/types/snapshot.ts`. Prefer failing closed (null counts) over leaking
detail when an API denies access.
