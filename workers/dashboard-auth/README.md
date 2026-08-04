# dashboard-auth Worker

Edge auth gate for `dashboard.qwts.org`. Apple, Google, and GitHub are all
accepted identity providers. This Worker is the only component that holds IdP
secrets — the SPA and its service worker never do.

Any account that completes a sign-in with a configured provider gets a session.
Authentication narrows *who reaches the snapshot*, never *what the snapshot may
contain*.

Identities listed in `ADMIN_SUBJECTS` additionally reach `/admin/*`, where a
pull request review is submitted **as that person**, using their own GitHub App
user token. This Worker holds no credential that can write to the fleet on its
own — see the privileged-actions decision in the repository `DESIGN.md`.

## What it enforces

| Path | Behaviour |
| --- | --- |
| `/data/*` | Requires a valid session; otherwise `401` |
| `/admin/*` | Requires a session, the allowlist, and — to write — a recent one |
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
| `GET /auth/me` | `{ authenticated, provider, login, expiresAt, admin, privileged }` or `401` |
| `GET /auth/logout` | Clears the session cookie **and deletes the stored actor token** |

`admin` means the allowlist permits the panel. `privileged` means an action
would actually reach GitHub — allowlisted, signed in with GitHub, and holding a
live token. They differ for an admin signed in with Apple or Google, and the
SPA needs both to say something true rather than fail on click.

`login` is non-null only for a privileged admin — it is read from the sealed
actor-token bundle, which is the only place the Worker keeps a display field.
Every other session renders as simply signed in.

### Privileged endpoints

Every one requires the `X-Dashboard-Action: 1` header; the write additionally
requires an `Origin` matching this host. Responses are `private, no-store`.

| Endpoint | Purpose |
| --- | --- |
| `GET /admin/repos` | Repositories reachable through the App installation, filtered to `ALLOWED_OWNERS` |
| `GET /admin/pulls?repo=owner/name` | Open pull requests: number, title, author, head sha, draft |
| `POST /admin/review` | Body `{ repo, number, head_sha, event, body, idempotency_key }` |

`event` is `APPROVE`, `REQUEST_CHANGES`, or `COMMENT` — nothing else, and
nothing that merges. `head_sha` must still be the pull request's head or the
call returns `409 head_moved` carrying the sha it moved to; the same sha is
passed to GitHub as `commit_id`, so a push landing mid-request is refused there
too. `idempotency_key` becomes the audit row's primary key, so a replayed
submit returns the first outcome instead of acting again.

## Flow notes

- Authorization code, not implicit. Apple requests no scope, which allows
  `response_mode=query` and keeps the callback a plain `GET`. Google requests
  `openid` — the smallest scope that yields a stable subject, which is all the
  Worker keeps.
- Google enforces PKCE itself; Apple and GitHub do not, so the Worker
  verifies the `code_challenge` / `code_verifier` binding for every provider
  before spending the code. The challenge travels in a signed `HttpOnly` cookie;
  the verifier stays in the browser until exchange time.
- Cookies are signed with HMAC-SHA256, not encrypted — their payload is
  readable wherever the cookie travels. They therefore carry only opaque
  identifiers: provider, subject, session id, and clocks. Display fields come
  from `/auth/me`, never from the cookie.
- The session cookie and the transaction cookie share one `SESSION_SECRET`, so
  each is signed for a purpose that is mixed into the HMAC and the reader
  validates the full claim shape. Without both, the transaction token handed to
  any unauthenticated caller by `/auth/login` would verify as a session.
- Apple's and Google's `id_token`s are read from a direct TLS response to their
  token endpoints; `iss`, `aud`, and `exp` are validated in place of a JWKS
  lookup.

## Configuration

Vars live in `wrangler.toml`:

| Var | Meaning |
| --- | --- |
| `PAGES_ORIGIN` | Empty = pass through to the zone origin; set a full origin for `wrangler dev` |
| `SESSION_TTL_SECONDS` | Session lifetime, default `28800` |

| `ALLOWED_OWNERS` | Owners a privileged action may name, default `qwts` |
| `PRIVILEGED_MAX_AGE_SECONDS` | How recently a session must have authenticated to act, default `3600` |
| `PRIVILEGED_RATE_LIMIT` | Privileged attempts per identity per minute, default `10` |

Secrets (`wrangler secret put <NAME>`):

`SESSION_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `APPLE_CLIENT_ID`,
`APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `TOKEN_ENCRYPTION_KEY`, `ADMIN_SUBJECTS`.

`GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` must belong to a **GitHub App**,
not an OAuth App: callback `https://dashboard.qwts.org/auth/callback`, *Expire
user authorization tokens* enabled, repository permission *Pull requests: read
and write*, installed on the repositories the dashboard may act on. That
installation is the closed set of repositories, enforced by GitHub. OAuth App
credentials still sign people in, and every privileged call then fails.

`ADMIN_SUBJECTS` is space- or comma-separated `provider:subject` — e.g.
`github:1234567`, where the subject is the numeric user id from
`https://api.github.com/users/<login>`, not the login. **Unset means nobody is
privileged**, which is the correct resting state.

`TOKEN_ENCRYPTION_KEY` seals actor tokens at rest in D1. Rotating it does not
break sign-in; it invalidates every stored token, so admins re-authenticate
once.

### D1

```bash
wrangler d1 create playbook-dashboard-auth      # paste the id into wrangler.toml
wrangler d1 execute playbook-dashboard-auth --remote --file=schema.sql
```

Three tables: `identities` (sign-in tracking, best effort), `actor_tokens`
(sealed, one row per privileged session), and `audit_log` (append-only,
written before the action). Without the binding, `/admin/*` returns
`503 privileges_unavailable` and sign-in is unaffected.

An `actor_tokens` row is deleted on sign-out, superseded when the same
identity signs in fresh, and reaped opportunistically on privileged requests
once its refresh expiry has passed — no row outlives every path that could
use it.

`identities` stores only the provider, the provider's stable subject, first and
last seen timestamps, and a sign-in counter — no logins, no emails. The subject
is provider-attested and identifies the account *to the provider* if an
incident ever requires it; everything richer would be a copy of evidence the
provider already holds better. The `audit_log` is different on purpose: its
rows record what an account *did*, so they keep the `login` and must stay
readable on their own.

Reading the audit log:

```bash
wrangler d1 execute playbook-dashboard-auth --remote \
  --command "SELECT started_at, login, verb, repo, target, head_sha, outcome
             FROM audit_log ORDER BY started_at DESC LIMIT 20"
```

A row still at `attempted` is the one to look at: the request left this Worker
and nothing came back to say what GitHub did with it.

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
the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` Actions secrets. The
token must cover the route as well as the script — *Account → Workers Scripts →
Edit*, *Zone → Workers Routes → Edit*, *Zone → Zone → Read*, which the built-in
**Edit Cloudflare Workers** template grants. A token holding only the account
permission uploads the script and then fails to attach the route. IdP secrets
are set once with `wrangler secret put` and are never exposed to CI.

`npx wrangler tail` streams live request logs, which is the fastest way to see
why a provider rejected an exchange.
