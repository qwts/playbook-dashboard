# Design — playbook-dashboard

## Goal

A single public pane of glass for the playbook-engineering governed fleet:
security posture (counts), repository properties, and CI status. Hosted on
GitHub Pages. No authentication on day 1 — privacy is enforced by redaction.

## Data flow

1. `governance/repos.json` in `qwts/playbook-engineering` defines the fleet.
2. `tools/collect.mjs` reads the manifest and GitHub APIs with a token that can
   see security alerts.
3. It writes `public/data/snapshot.json` containing only aggregates and booleans,
   and only for repositories cleared for publication (see below).
4. The Vite SPA renders that file; the browser never holds a privileged token.

## Redaction rules

| Allowed | Forbidden |
| --- | --- |
| Open alert counts by type | Alert titles, CVEs, URLs into alert APIs |
| Security-floor booleans | Secret scanning snippets |
| Manifest fields already public | Private vulnerability report bodies |
| Latest workflow conclusion + link to Actions | Job logs, artifacts |
| Count of repos withheld from publication | Which repos were withheld, and why |

## Decision: publication is opt-in and double-gated

**Decision.** A repository is published only when both gates pass:

1. Its manifest entry sets `publish: true`. Absent, `false`, or any truthy
   non-boolean (`"true"`, `1`) means do not publish.
2. GitHub reports it public at collection time — `private: false` *and*
   `visibility: "public"` on the repo response, which must agree.

A repository failing either gate contributes nothing to the artifact: no name,
no counts, no security-floor bits, no CI row. It increments `withheld`, a count
the page displays so a partial view is stated rather than implied.

**Why.** Each row is mundane; the composition is not. The rollup table is sorted
by open alert count descending and the properties table renders every disabled
control, so an unrestricted dashboard publishes a ranked list of the
organization's least-defended repositories. For a repository the organization
chose not to make public, that inverts the decision — and it happens silently,
by omission, at manifest-edit time, decided by whoever adds the entry rather
than by anyone weighing publication.

Opt-in makes publication an explicit act, reviewed in the governance repo's own
PR process, and makes the published surface grow only deliberately. The second
gate exists because the manifest's `visibility` is a *claim*: a repository
flipped private on GitHub stays "public" in the manifest until someone
remembers to edit a file in another repository. Checking observed state means
the gate closes on its own, within the hour, without that edit. Unknown or
partial repo responses are not public, so both gates fail closed.

**Rejected alternatives.** *Aggregates only* (no row, but counted in headline
stats) leaks by subtraction: headline minus visible rows is the withheld
repositories' alert count, recomputed hourly on a fleet small enough for
single-repo movements to be inferrable. *Aliasing* names does not survive a
fleet this size — stable identifiers de-anonymize against public activity
timing — and it turns the mapping table into another secret to hold. *Publish
as-is* is coherent for a transparency-first organization, but it should not be
reached by default, and this repository's stated posture is to fail closed.

**Consequence.** Until the manifest carries `publish: true`, the collector
publishes nothing. The manifest must be updated before this ships to Pages.

## Decision: manifest free text

`note` is **not published**. It was collected and written into the artifact but
never rendered, so it was public and simultaneously unreviewed — the worst
combination. It is removed from the snapshot schema entirely.

`delta` **is published**, for published repositories only, subject to
validation at the collector: at most 200 characters and no control characters.
A violating value is dropped whole rather than truncated — a half-sentence
reads as authored copy — and the collector logs the repository name and reason,
never the value, because the manifest is untrusted input and Actions logs on a
public repository are themselves public.

Publishing `delta` is republication, not disclosure: it is governance text that
already lives in a public manifest, and repositories that fail the publication
gates emit no `delta` at all. The cap exists because the threat model treats the
manifest as attacker-controlled, and unbounded free text reaching a public page
is a blast radius worth bounding regardless of who authored it.

## Local development

- Browse URL: `https://local.dev.zts1.com:8443/`
- Listen bind: `127.0.0.1`
- Port **8443** (documented; not 443)
- TLS material from `~/.quorum/certs`, passphrase via `DASHBOARD_TLS_KEY_PASSPHRASE`
