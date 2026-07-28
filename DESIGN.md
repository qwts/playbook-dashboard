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

**A snapshot may state what it is; it may not assert what the fleet is.**
`withheld` is therefore `number | null`, and the committed fixture states
`null`. The fixture is the fallback deployed whenever collection fails —
`continue-on-error` on the collect step means an unset token produces a fully
green run that publishes it — and it has no knowledge of the fleet it would be
describing. A fixture claiming `withheld: 0` renders "published N of N
governed" in green: a positive claim of completeness made by a file that cannot
know. Unknown renders as unknown.

**Nothing about a withheld repo reaches a log.** Not its name, not its request
path, not GitHub's response body, and not its *position paired with an
outcome* — candidate order comes from a public manifest, so position plus
outcome re-identifies the repo the gates just withheld. Actions logs on a
public repository are public. The collector logs bare progress positions and
aggregates every failure into sorted, tallied counts.

This last rule generalizes beyond the code that introduced it: any logic
written while every governed repo was published may be wrong now that some are
not, whether or not it appears in the diff that introduced withholding.

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

## Decision: unknown is a value, not a default

Missing data is never resolved in the direction that prompts no follow-up. This
is one rule with two former violations (#3, #8), and it applies to any field
added later.

**Counts.** `null` in `SecurityCounts` means the collector was denied the count,
not that there are none. `sumOpenSecurity` returns `{ known, unknown }` rather
than a single number, so a partially-read total can say what it actually knows:
`6` when fully read, `≥6` when part could not be, `?` when none could. A total
with any unknown is never green — green claims "nothing open here", which an
incomplete read cannot claim. A repo with unreadable counts also sorts *above*
every measured repo in the rollup, because it cannot be ranked as safer than
something that was actually measured.

**Manifest fields.** An absent field publishes `null`, never a compliant-looking
default. A repo nobody has configured and a repo deliberately configured must
not be indistinguishable on the page. If "omission means X" is genuinely the
fleet contract, it belongs in the manifest as an explicit field, where the
reader can see it — not in a collector fallback, where they cannot.

**Untrusted input.** The snapshot is fetched by a browser and may be stale,
cached, or tampered with. Anything that is not a sane value — wrong type,
negative, `NaN` — is unknown, not zero. Validation happens where the value
enters, not where it is displayed.

The failure this prevents is specific: a dashboard that looks most reassuring
exactly where it knows least. For a tool whose entire job is reporting posture,
that is the one error nobody ever investigates.

## Decision: a run that succeeded is not a run that was complete

The rule above governs the page. This one governs the run that builds it, and it
is the same rule one layer out: a green check must not be the most reassuring
thing about a collection that could not read the fleet.

`continue-on-error` on the collect step distinguishes exactly two states —
collection failed, collection succeeded. A collection that succeeded while
denied half its reads is a third, and it wore the first one's colours: green
check, published page, question marks nobody was told about. The UI stopped
lying about it in #3; CI kept lying about it until #12.

So the workflow carries two independent signals out of the collect job, because
they want opposite handling:

| | `fresh` | `degraded` | outcome |
|---|---|---|---|
| clean run | `true` | `false` | publish, green |
| partial reads | `true` | `true` | **publish**, then fail |
| collection failed | `false` | — | publish the committed fixture, then fail |

The middle row is the decision. A degraded snapshot is still the freshest truth
available, so it ships — degradation must not ride on the step's exit code,
because a non-zero exit makes `fresh` false and swaps in the committed fixture,
discarding the better artifact to report the smaller problem. Both gates run
*after* `deploy-pages` for the same reason #20 established: a legible degraded
dashboard beats an outage.

**Degradation is read from the artifact, not the counters.** A 404 yields a
`null` count without touching a health counter, and a failed gate call
increments one for a repo that was never going to be published. The question the
gate asks is whether the page will show a `?`, and that is a property of the
snapshot. A fact the manifest never asserted (`codexSyncEnabled`) is not a read
that failed and does not count — a gate that is always red is a gate nobody
reads.

**Bounding the run.** Every request has a deadline, but a deadline cannot bound
a wedged runner or a hung install, so every job declares `timeout-minutes`. The
default is 360: six hours holding a concurrency group that does not cancel, on
an hourly schedule, while holding the fleet credential.

`cancel-in-progress` stays `false`, and that is now a decision rather than an
inherited default. Cancelling would interrupt `deploy-pages` mid-flight; the
queue argument for accepting that risk does not survive bounded jobs, since
Actions holds at most one pending run per group and a newer arrival replaces the
pending one rather than stacking behind it.

**`pages.yml` is never executed by a pull request.** It has no `pull_request`
trigger, so a change that breaks it merges clean and is discovered by the hourly
schedule, in production, with the credential in hand. `tools/workflows.test.mjs`
asserts against the workflow source instead — including the contract between the
collector's output keys and the gate that reads them, which spans two files and
which neither file's own tests can see.

## Local development

- Browse URL: `https://local.dev.zts1.com:8443/`
- Listen bind: `127.0.0.1`
- Port **8443** (documented; not 443)
- TLS material from `~/.quorum/certs`, passphrase via `DASHBOARD_TLS_KEY_PASSPHRASE`
