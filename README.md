# playbook-dashboard

Redacted fleet dashboard for repositories governed by
[playbook-engineering](https://github.com/qwts/playbook-engineering).

It shows:

- **Security rollup** — open Dependabot / code-scanning / secret-scanning *counts*
- **Properties** — manifest fields plus security-floor toggles
- **CI / CD** — latest default-branch workflow conclusion

Alert bodies, file paths, CVEs, and secret material are never published.

Viewing requires a sign-in — Apple, Google, or GitHub. Any account works; there
are no roles or per-account permissions. See [Authentication](#authentication).

## Local development

Local HTTPS uses the shared certs under `~/.quorum/certs` (certificate CN
`local.dev.zts1.com`).

| Setting | Value |
| --- | --- |
| URL | `https://local.dev.zts1.com:8443/` |
| Port | **8443** (not 443) |
| Cert | `~/.quorum/certs/fullchain.pem` |
| Key | `~/.quorum/certs/key.pem` (encrypted) |
| Passphrase source | `~/.quorum/certs/key.passphrase` → env `DASHBOARD_TLS_KEY_PASSPHRASE` |

The passphrase is loaded **only** through the environment variable
`DASHBOARD_TLS_KEY_PASSPHRASE`. It is never committed, logged, or inlined in
config. `npm run dev` reads the passphrase file into that variable when unset
(`DASHBOARD_TLS_KEY_PASSPHRASE_FILE` overrides the file path).

Point the cert hostname at loopback (once):

```bash
# /etc/hosts
127.0.0.1 local.dev.zts1.com
```

```bash
npm install
npm run dev
# open https://local.dev.zts1.com:8443/
```

`npm run dev` sets `VITE_AUTH_DISABLED=1`, because the `/auth/*` endpoints live
in the Cloudflare Worker rather than in Vite. To exercise the real sign-in flow
locally, run the Worker in front of the dev server:

```bash
cd workers/dashboard-auth && npm install
PAGES_ORIGIN=https://local.dev.zts1.com:8443 npm run dev
# in the other shell
VITE_AUTH_DISABLED=0 npm run dev
```

Optional overrides (see `.env.example`):

- `DASHBOARD_DEV_PORT` — default `8443`
- `DASHBOARD_DEV_BIND` — default `127.0.0.1` (listen address)
- `DASHBOARD_TLS_CERTS_DIR` — default `~/.quorum/certs`

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | HTTPS Vite dev server on port **8443** (auth bypassed) |
| `npm test` | `node --test` over `src/**/*.test.ts` |
| `npm run build` | Production static build to `dist/` (terser-minified, no source maps) |
| `npm run collect` | Refresh `public/data/snapshot.json` (needs `GITHUB_TOKEN`) |
| `npm run ci` | Typecheck + test + build |

Node 24+ is required: tests are TypeScript and run through Node's built-in type
stripping, with no build step. Browser code and test code are typechecked as
separate projects (`tsconfig.json`, `tsconfig.test.json`) so Node globals stay
out of the bundle.

## Authentication

`dashboard.qwts.org` sits behind the Cloudflare Worker in
[`workers/dashboard-auth`](workers/dashboard-auth), which is the only component
holding identity-provider secrets. It gates `/data/*` — the static shell stays
public so the SPA can render its own sign-in screen.

```
browser → Cloudflare Worker (session gate) → GitHub Pages origin
```

[`public/sw.js`](public/sw.js) completes the OAuth return trip and keeps
snapshot fetches credentialed. It is convenience only; the Worker is the
enforcement point.

Authentication gates *who reaches the snapshot*, not *what it contains*. Because
any account can sign in, the redaction contract still governs every field the
collector publishes.

### One-time setup

1. **Apple Developer portal** — create a Services ID (the web `client_id`),
   enable Sign in with Apple, and register the return URL
   `https://dashboard.qwts.org/auth/callback`. Apple verifies the domain by
   fetching `/.well-known/apple-developer-domain-association.txt`, so the site
   must already be live at that host. Create a Sign in with Apple key and
   download the `AuthKey_XXXXXXXX.p8`.
2. **Google Cloud console** — create a project, configure the OAuth consent
   screen as **External** and publish it (an unpublished app only admits test
   users), verify `qwts.org` in Search Console and list it as an authorised
   domain, then create an **OAuth client ID** of type *Web application* with the
   authorised redirect URI `https://dashboard.qwts.org/auth/callback`.
3. **GitHub OAuth App** — set the authorization callback URL to
   `https://dashboard.qwts.org/auth/callback`.
4. **DNS** — in the Cloudflare `qwts.org` zone, add `dashboard` as a **proxied**
   `CNAME` to `qwts.github.io`. Because the record targets a hostname rather
   than an IP, Cloudflare validates the origin leg against GitHub's
   `*.github.io` certificate, so SSL/TLS mode **Full (strict)** works without
   Pages ever issuing a certificate of its own. Set the custom domain in repo
   Settings → Pages to match `public/CNAME`; a deploy resets it to whatever
   that file says.
5. **Worker secrets** — `SESSION_SECRET`, `GITHUB_CLIENT_ID`,
   `GITHUB_CLIENT_SECRET`, `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`,
   `APPLE_PRIVATE_KEY`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` via
   `wrangler secret put`. CI never sees them.
6. **Actions secrets** — `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, so
   `.github/workflows/worker.yml` can deploy. Attaching a route is a zone-level
   operation, so an account-only token uploads the script and then fails: the
   token needs *Account → Workers Scripts → Edit*, *Zone → Workers Routes →
   Edit*, and *Zone → Zone → Read*, which is what the built-in **Edit
   Cloudflare Workers** template grants. Scope it to this account and the
   `qwts.org` zone.

Any provider whose secrets are unset returns `provider_not_configured`; the
others keep working.

## Snapshot collection

```bash
export GITHUB_TOKEN=...   # fine-grained PAT with security-alert + actions read
npm run collect
```

The collector writes counts and booleans only. Prefer failing a field to `null`
over emitting privileged detail.

## Deploy

GitHub Actions builds the site and deploys to GitHub Pages at
`https://dashboard.qwts.org/`. The auth Worker deploys separately from
`.github/workflows/worker.yml` whenever `workers/` changes on `main`, using the
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets. The deploy step is
gated on the ref rather than the event, so a `workflow_dispatch` run cannot
publish an unreviewed branch as the production auth gate. Identity-provider
secrets live only in Cloudflare, never in the Pages build environment.

The hostname is a Route 53 `CNAME` to `qwts.github.io`, and `public/CNAME`
carries it into every Pages artifact. GitHub Pages issues and renews the
production certificate; no TLS private key for this hostname exists in this
repository. Because the site is served from the domain root, `/` is the default base
for both local dev and the production build; `VITE_BASE` overrides it for a
project-site deployment under `qwts.github.io/<repo>/`. `pages.yml` still sets
it explicitly, so the deployed base is stated rather than inherited.

## Governance

This repository follows
[playbook-engineering](https://github.com/qwts/playbook-engineering) baselines.
See `AGENTS.md` and `CONTRIBUTING.md`.
