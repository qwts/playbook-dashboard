# Design — playbook-dashboard

## Goal

A single public pane of glass for the playbook-engineering governed fleet:
security posture (counts), repository properties, and CI status. Hosted on
GitHub Pages. No authentication on day 1 — privacy is enforced by redaction.

## Data flow

1. `governance/repos.json` in `qwts/playbook-engineering` defines the fleet.
2. `tools/collect.mjs` reads the manifest and GitHub APIs with a token that can
   see security alerts.
3. It writes `public/data/snapshot.json` containing only aggregates and booleans.
4. The Vite SPA renders that file; the browser never holds a privileged token.

## Redaction rules

| Allowed | Forbidden |
| --- | --- |
| Open alert counts by type | Alert titles, CVEs, URLs into alert APIs |
| Security-floor booleans | Secret scanning snippets |
| Manifest fields already public | Private vulnerability report bodies |
| Latest workflow conclusion + link to Actions | Job logs, artifacts |

## Local development

- Browse URL: `https://local.dev.zts1.com:8443/`
- Listen bind: `127.0.0.1`
- Port **8443** (documented; not 443)
- TLS material from `~/.quorum/certs`, passphrase via `DASHBOARD_TLS_KEY_PASSPHRASE`
