# dashboard-auth Worker

Edge auth gate for `dashboard.dev.zts1.com`. Apple, Google, and GitHub are all
accepted identity providers. This Worker is the only component that holds IdP
secrets — the SPA and its service worker never do.

There is no allowlist and no RBAC: any account that completes a sign-in with a
configured provider gets a session. Authentication narrows *who reaches the
snapshot*, never *what the snapshot may contain*.

## What it enforces

| Path | Behaviour |
| --- | --- |
| `/data/*` | Requires a valid session; otherwise `401` |
| `/auth/*` | Auth endpoints below, plus the SPA shell for `/auth/callback` |
| everything else | Proxied to the GitHub Pages origin (static shell stays public) |

The static shell is deliberately public so the SPA can render its own sign-in
screen. The redacted snapshot under `/data/` is the payload that requires a
session.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /auth/login?provider=&state=&code_challenge=` | Signs a short-lived transaction cookie and redirects to Apple, Google, or GitHub |
| `POST /auth/exchange` | Body `{ code, state, code_verifier }`; validates state + PKCE binding, exchanges the code, sets the session cookie |
| `GET /auth/me` | `{ authenticated, provider, login, email, expiresAt }` or `401` |
| `GET /auth/logout` | Clears the session cookie |

## Flow notes

- Authorization code, not implicit. Apple requests no scope, which allows
  `response_mode=query` and keeps the callback a plain `GET`. Google requests
  `openid email` — the smallest scope that yields a stable subject.
- Google enforces PKCE itself; Apple and GitHub OAuth Apps do not, so the Worker
  verifies the `code_challenge` / `code_verifier` binding for every provider
  before spending the code. The challenge travels in a signed `HttpOnly` cookie;
  the verifier stays in the browser until exchange time.
- Cookies are signed with HMAC-SHA256, not encrypted. They carry only provider,
  subject, login, and expiry.
- Apple's and Google's `id_token`s are read from a direct TLS response to their
  token endpoints; `iss`, `aud`, and `exp` are validated in place of a JWKS
  lookup.

## Configuration

Vars live in `wrangler.toml`:

| Var | Meaning |
| --- | --- |
| `PAGES_ORIGIN` | Empty = pass through to the zone origin; set a full origin for `wrangler dev` |
| `SESSION_TTL_SECONDS` | Session lifetime, default `28800` |

Secrets (`wrangler secret put <NAME>`):

`SESSION_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `APPLE_CLIENT_ID`,
`APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`.

`APPLE_PRIVATE_KEY` is the full PKCS8 PEM body of the `AuthKey_XXXXXXXX.p8`
downloaded from the Apple Developer portal.

A provider whose secrets are unset returns `provider_not_configured` from
`/auth/login`; the remaining providers keep working.

## Local development

```bash
npm install
PAGES_ORIGIN=https://local.dev.zts1.com:8443 npm run dev
```

Local secrets go in `.dev.vars` (gitignored). Placeholder values are enough to
exercise redirects, state, and PKCE binding; only the final token call needs
real credentials.

For SPA-only work, skip the Worker entirely and use `VITE_AUTH_DISABLED=1`
in the dashboard dev server (see the repository README).

## Deploy

```bash
npm run deploy
```

CI deploys via `.github/workflows/worker.yml` on changes under `workers/`, using
the `CLOUDFLARE_API_TOKEN` (account-scoped, *Workers Scripts: Edit*) and
`CLOUDFLARE_ACCOUNT_ID` Actions secrets. IdP secrets are set once with
`wrangler secret put` and are never exposed to CI.
