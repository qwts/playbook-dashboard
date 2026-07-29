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

**A thrown error carries a literal and a status, never a response.** The two
functions that can end the run — `ghJson` and, historically, `countOpenAlerts` —
both state at their definition that they must not be called before the
visibility gate, because `main().catch()` prints what they throw. The message
uses a label supplied as a constant at the call site rather than the request
path, so the safety does not depend on which path was requested or on the next
caller reading the constraint. Request paths and response bodies are available
only under `COLLECT_DEBUG`, which the Pages workflow has no way to set — the
collect step passes it nothing but a token. GitHub's error bodies are ordinarily
harmless, but they cross a boundary the threat model treats as
attacker-controlled, and this was safe before only by where the callers happened
to sit.

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

## Decision: the job that signs runs nothing that could abuse the signature

`id-token: write` mints an OIDC token asserting `repo:qwts/playbook-dashboard`,
which matters wherever a cloud role trusts that subject. It sat in the job that
runs `npm run build` — vite, esbuild, and every plugin in the tree.
`--ignore-scripts` closes *install*-time execution and does nothing about
*build*-time execution, which is the entire purpose of a bundler.

Nothing in this organization trusts that subject today. That is why this was low
severity rather than urgent — and it is also the reason not to leave the
capability lying there, because "nothing trusts it today" is exactly the kind of
assumption that stops being true when someone adds a cloud role, without anyone
revisiting this workflow.

**Attestation moved to its own job.** `attest` downloads the built files and
signs them, running no checkout, no npm, and no repository code at all — only
SHA-pinned GitHub-owned actions over files this workflow already produced.
`build` drops to `contents: read`, the same property `collect` has.

**Rejected: attesting from `deploy`.** It needs one job fewer and `deploy`
already holds `id-token: write` for `deploy-pages`, so it looked like the
cheapest answer. It attests the Pages **tarball** — one subject instead of many.
`data/snapshot.json` would stop being individually verifiable, and for a
repository whose product is auditable claims about security posture, binding the
published snapshot by digest to a run of this workflow *is* the product. A
reader can check where the bytes came from; coarsening the subject to a tarball
removes that and is hard to walk back.

**What the attestation proves — and what it does not.** Provenance: these exact
bytes were produced by this workflow, at this commit, in this run. Not
freshness. A run whose credential died still builds, attests, and publishes the
committed fixture, and its attestation is valid and never revoked — the fixture
genuinely *was* produced by this workflow at that commit. Freshness lives in
the run's conclusion, which is exactly what the gates in the next section
redden. A verifier who cares that a number is *current*, not merely authentic,
must check both: the digest against the attestation, and the attested run's
conclusion.

**Rejected: leaving it in `build`.** Best granularity, but it keeps a signing
grant beside the toolchain that executes third-party build code — the thing
being avoided.

The cost is one job and one artifact round-trip: `build` uploads `dist` a second
time as individual files, because `upload-pages-artifact` produces a tarball and
per-file subjects need the files. Same bytes either way.

`attest` runs in parallel with `deploy` rather than gating it. An attestation
failure must not take the site down — but the run still goes red, which is the
shape every other gate in this workflow uses.

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

**Degradation is read from the artifact and the counters, overlapping on
purpose.** A 404 yields a `null` count without touching a health counter, so
only the snapshot knows whether the page will show a `?`; a denied read against
a repo the gates then withheld leaves no trace in the snapshot, so only the
counters see it. The overlap means a denied posture read can be reported twice
and a failed gate call reddens the run for a repo that was never going to be
published — accepted, because this gate exists to defeat silence and every
overlap errs loud.

Not every `null` is a failed read. A fact the manifest never asserted
(`codexSyncEnabled`) does not count, and neither does a count whose feature the
owner turned off — GitHub answers 403/404 on the alerts endpoints for a
disabled scanner, a permanent chosen state the page already shows via the floor
flag. Counting either would redden every hourly run forever, and a gate that is
always red is a gate nobody reads.

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

## Decision: the page has no third-party origin, and a policy that says so

The page loaded two IBM Plex families from Google's CDN. Two costs, and the
second is the one specific to this repository.

A stylesheet from another host sits **inside the page's trust boundary** — it can
set content, pull further resources, and is a live dependency on every load. A
page whose entire job is publishing the organization's security posture should
not itself depend on an origin outside the organization's control.

And **every visitor was disclosed to a third party**. Who reads a fleet security
dashboard, and when, is meaningful signal even though the page itself is public.
`preconnect` made that disclosure happen before any resource was even requested,
and would have outlived deleting the stylesheet it was added for.

**Both families are now served from this origin**, so the policy needs no
allowances at all. That is the argument for removing the links rather than
allow-listing them: an allowance is a standing permission, and the page now has
none to grant.

```
default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self';
img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none';
object-src 'none'
```

`script-src 'self'` with no `unsafe-inline` and no `unsafe-eval` is the one
control here that keeps working after something upstream in the build pipeline
has already gone wrong; `connect-src 'self'` denies an injected beacon anywhere
to report to. Two inline `style` props were moved into a class — React sets
those through the CSSOM, which CSP does not intercept, but relying on that
distinction to satisfy a policy stops being true after one refactor.

**`frame-ancestors` is deliberately absent.** It is ignored when a policy is
delivered in a `<meta>` element, and Pages serves static files with no way to set
a response header. Writing it would read as clickjacking protection while
providing none — the exact failure this repository exists to avoid. Framing
protection is not available on Pages without a proxy in front; that is a real
residual, not an oversight.

**Latin1 plus Pi, per weight.** `unicode-range` means a browser fetches each
subset only when it needs a glyph from it. Pi is not optional: U+2265 lives
there, and `openSecurityLabel` renders `≥6` for a partially-read total — Latin1
alone would render that one glyph in a fallback face, in the security label.
Verified in a browser: forcing an unreadable count pulled exactly the two Pi
files whose faces render it, and no others.

Vendored from the official IBM packages `@ibm/plex-sans@1.1.0` and
`@ibm/plex-mono@2.5.0`, SIL Open Font License 1.1 (`public/fonts/LICENSE.txt`).
Fetched with `npm pack`, so nothing was added to `dependencies`. Digests are
recorded because a binary blob is the one thing in this repository that review
cannot read — 207 KB across 14 files:

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `IBMPlexMono-Medium-Latin1.woff2` | 17,868 | `41201b658a328b9d00368215c2f1102770f80b15952ab82631e4006255e6365d` |
| `IBMPlexMono-Medium-Pi.woff2` | 13,968 | `92bd18415e8c43a2569f615e4e84a94b1b1c4e0377ba9d8f4d894bbf6ffcc39d` |
| `IBMPlexMono-Regular-Latin1.woff2` | 17,544 | `e8993d946649b9d01abb1ed06d574b19d8ea3e66b5c3948602db335c44c18e56` |
| `IBMPlexMono-Regular-Pi.woff2` | 13,780 | `b8002770aa636f544ba43e124da6a227301769754f295eae26e16475b469c767` |
| `IBMPlexMono-SemiBold-Latin1.woff2` | 17,872 | `b7acd05041ab65f3b7039e218ddd893065e11a07e85ea85019473152a51b6b7d` |
| `IBMPlexMono-SemiBold-Pi.woff2` | 13,872 | `1637166246d386507b1351d59ddda93b732f781d06c0a6574e486104a00897b1` |
| `IBMPlexSans-Bold-Latin1.woff2` | 21,256 | `914f1400f363e636b6f9cc7965aa807ff01e93586e1437617525cba0a62aa78d` |
| `IBMPlexSans-Bold-Pi.woff2` | 7,656 | `be77a1e1773f42f0abf473795b0890da2d098e36f49fe15ef95480acf4be91d8` |
| `IBMPlexSans-Medium-Latin1.woff2` | 21,960 | `b5610af04d0d4b5a14a621d96d974b993e945a065db1a8861918f69ef9321934` |
| `IBMPlexSans-Medium-Pi.woff2` | 7,768 | `bf05f10c977353cfb5a5c11e8973adf77c2b93a4798da3aa0dd8ba5088e12515` |
| `IBMPlexSans-Regular-Latin1.woff2` | 20,984 | `b5ad7bd39f996144915f0ad9849a90183b27d8c28ad97ed98af5b1bebc51f6b1` |
| `IBMPlexSans-Regular-Pi.woff2` | 7,500 | `1487059829a180f975627e473acc81ff22c2c0faf1da09b314c27eeb41b7f2e4` |
| `IBMPlexSans-SemiBold-Latin1.woff2` | 22,260 | `fff0ab3a88b0b4aa0b693e4f0201359a15183b08e3fa5696d1918d8f0ade8ad5` |
| `IBMPlexSans-SemiBold-Pi.woff2` | 7,824 | `768421433d850d3a30118dddf05972625d99ee49bc32c5a8fd26bbe020c4d0f9` |

## Local development

- Browse URL: `https://local.dev.zts1.com:8443/`
- Listen bind: `127.0.0.1`
- Port **8443** (documented; not 443)
- TLS material from `~/.quorum/certs`, passphrase via `DASHBOARD_TLS_KEY_PASSPHRASE`
