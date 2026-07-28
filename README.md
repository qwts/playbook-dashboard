# playbook-dashboard

Public, redacted fleet dashboard for repositories governed by
[playbook-engineering](https://github.com/qwts/playbook-engineering).

It shows:

- **Security rollup** — open Dependabot / code-scanning / secret-scanning *counts*
- **Properties** — manifest fields plus security-floor toggles
- **CI / CD** — latest default-branch workflow conclusion

Alert bodies, file paths, CVEs, and secret material are never published.

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

Optional overrides (see `.env.example`):

- `DASHBOARD_DEV_PORT` — default `8443`
- `DASHBOARD_DEV_BIND` — default `127.0.0.1` (listen address)
- `DASHBOARD_TLS_CERTS_DIR` — default `~/.quorum/certs`

## Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | HTTPS Vite dev server on port **8443** |
| `npm test` | `node --test` over `src/**/*.test.ts` |
| `npm run build` | Production static build to `dist/` |
| `npm run collect` | Refresh `public/data/snapshot.json` (needs `GITHUB_TOKEN`) |
| `npm run ci` | Typecheck + test + build |

Node 24+ is required: tests are TypeScript and run through Node's built-in type
stripping, with no build step. Browser code and test code are typechecked as
separate projects (`tsconfig.json`, `tsconfig.test.json`) so Node globals stay
out of the bundle.

## Snapshot collection

```bash
export GITHUB_TOKEN=...   # fine-grained PAT with security-alert + actions read
npm run collect
```

The collector writes counts and booleans only. Prefer failing a field to `null`
over emitting privileged detail.

## Deploy

GitHub Actions builds the site and deploys to GitHub Pages at
`https://dashboard.dev.zts1.com/`.

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
