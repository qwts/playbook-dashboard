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

**Product.** Redacted fleet dashboard for governed `qwts` repos, readable by any
signed-in account. It visualizes security *counts*, manifest properties,
and CI conclusions. It must never publish alert titles, file paths, CVEs, secret
material, or private vulnerability report bodies. Authentication narrows the
audience; it never widens what may be published.

**Stack.** Vite + React + TypeScript. `npm run dev` serves local HTTPS;
`npm run build` produces the Pages artifact (terser-minified, mangled, no source
maps); `npm run collect` rebuilds `public/data/snapshot.json` from GitHub APIs;
`npm run ci` is typecheck + test + build, and is required before every push.

**Auth.** `workers/dashboard-auth` is a Cloudflare Worker in front of the Pages
origin: Apple, Google, and GitHub sign-in, HMAC-signed session cookie. Sign-up is
open — no allowlist, no RBAC, every session is read-only and sees the same
snapshot. It is the only place IdP secrets may live and the only enforcement
point — it returns `401` for `/data/*` without a session. `public/sw.js` handles
the OAuth return trip and credentialed snapshot fetches, and is assumed
bypassable. The static shell is intentionally public so the SPA can render its
own sign-in screen. `npm run dev` defaults to `VITE_AUTH_DISABLED=1`; never make
that the production default.

**Local TLS.** Certs live under `~/.quorum/certs` (CN `local.dev.zts1.com`).
The encrypted key passphrase is loaded only through the environment variable
`DASHBOARD_TLS_KEY_PASSPHRASE` — never hardcode or log it. `scripts/dev.mjs`
reads `~/.quorum/certs/key.passphrase` (or `DASHBOARD_TLS_KEY_PASSPHRASE_FILE`)
into that env var when unset. Bind `127.0.0.1`, browse
`https://local.dev.zts1.com:8443/` (port **8443**, not 443).

**`FLEET_DASHBOARD_TOKEN` is an environment secret, not a repository secret.**
It is scoped to the `github-pages` environment deliberately, and the difference
is the security boundary: a repository secret is readable by any workflow on any
branch, so a PR that adds a step could read the fleet credential. Scoping it to
an environment whose branch policy is `main`-only means a run from any other ref
is refused before its first step and the PAT never reaches a runner. If the
collect job cannot see the token, the fix is to check the environment's branch
policy — never to move the secret up to the repository, and never to widen a
`permissions:` block. The cost is that the collect job cannot be smoke-tested
from a branch; that is the intended trade.

**Workflows are not exercised by CI.** `pages.yml` has no `pull_request`
trigger, so nothing runs it before merge. `tools/workflows.test.mjs` asserts
against its source — job bounds, SHA pinning, least-privilege, `outcome` vs
`conclusion`, and the output-key contract with the collector. Changing the
workflow means changing those assertions deliberately, not deleting them.

**Redaction contract.** Collector and UI share the `Snapshot` schema in
`src/types/snapshot.ts`. Prefer failing closed (null counts) over leaking
detail when an API denies access.

**Publication is opt-in.** A repo reaches the snapshot only if its manifest
entry sets `publish: true` *and* GitHub reports it public at collection time.
Withheld repos contribute a count and nothing else. Never widen these gates to
make a repo appear — fix the manifest instead. See DESIGN.md for the decision
and its rationale.
