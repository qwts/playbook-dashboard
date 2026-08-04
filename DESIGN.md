# Design — playbook-dashboard

## Goal

A single pane of glass for the playbook-engineering governed fleet: security
posture (counts), repository properties, and CI status. Hosted on GitHub Pages
behind a Cloudflare Worker. Privacy is enforced by two independent layers —
redaction in the snapshot, and an authenticated session in front of it.

## Data flow

1. `governance/repos.json` in `qwts/playbook-engineering` defines the fleet.
2. `tools/collect.mjs` reads the manifest and GitHub APIs with a token that can
   see security alerts.
3. It writes `public/data/snapshot.json` containing only aggregates and booleans,
   and only for repositories cleared for publication (see below).
4. The Vite SPA renders that file; the browser never holds a privileged token.

## Access control

Apple, Google, and GitHub are accepted identity providers. Any account that
completes a sign-in gets a session, and every session sees the same snapshot.

Reading and acting are separate questions. An identity named in `ADMIN_SUBJECTS`
additionally sees the review panel, and what it can *do* there is decided by
GitHub rather than by this system — see the privileged-actions decision below.

| Layer | Responsibility |
| --- | --- |
| `workers/dashboard-auth` | Holds all IdP secrets, mints the session cookie, returns `401` for `/data/*` without one, and is the only place a privileged action is authorized or recorded. Sole enforcement point. |
| `public/sw.js` | Completes the OAuth return trip, keeps snapshot fetches credentialed, and signals the SPA when a session lapses. UX only, assumed bypassable. Never touches `/admin/*`. |
| `src/App.tsx` | Renders the sign-in composition or the dashboard based on `/auth/me`. |
| `src/Review.tsx` | The privileged panel. Renders for an allowlisted session only, and reads live GitHub state that never enters the artifact. |

The static shell stays public so the SPA can render its own sign-in screen. The
redacted snapshot under `/data/` is what requires a session.

Flow is authorization code with PKCE. Google enforces the binding itself; Apple
and GitHub do not, so the Worker verifies `code_challenge` against
`code_verifier` for every provider. Redaction rules below still apply in full —
and carry more weight now that sign-up is open: authentication narrows the
audience, it does not widen what may be published.

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

**A failure to decide is not a decision.** `withheld` counts governed repos the
collector *chose* not to publish — not opted in, or observed non-public. A repo
whose gate lookup was denied, rate-limited, or timed out publishes no row
either, which is why the two were once a single number, but they are opposite
claims to a reader judging whether the fleet is under control: one says the
fleet is deliberately curated, the other says this run could not tell. Folding
the second into the first made a rate limit look like governance. `unreadable`
is therefore its own count, never summed with `withheld` in the collector or the
page, and `published + withheld + unreadable === governed` is asserted rather
than trusted — a denominator that cannot be derived is not published as a guess.

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

## Decision: the redaction contract is executable, and it fails closed

Nothing inspected the snapshot between generating it and publishing it. The rule
lived in a comment at the top of `collect.mjs`, and a comment cannot fail a
build. `Snapshot` in `src/types/snapshot.ts` describes the intended shape, but it
is a compile-time type over a file written at runtime and fetched by a browser —
`tsc` never sees the bytes that ship.

So the published surface could only grow. Any change adding a field to a
collector return value published that field silently, on the next hourly cron,
with no step at which anyone saw that the artifact now contained something it
did not contain before.

`tools/snapshot-schema.mjs` is the contract. `npm run validate` runs it, in
`npm run ci` and between collect and build in the workflow — the same script in
both, because two definitions of "is this publishable" drift and the drift is
invisible until one of them is wrong.

**The assertion that matters is the closed key set at every level.** Checking
that known fields are well-formed catches malformed data; only rejecting unknown
keys catches *new* data, and new data is how a leak arrives. Adding a field to
the artifact now requires adding it here too — a deliberate act with a diff
attached. Everything else the check does (counts null-or-non-negative-integer,
URLs through the collector's own `sanitizeGithubUrl` rather than a second copy
of the rule, string caps, `visibility` exactly `public`, no duplicate rows,
timestamps parseable and not in the future) is worth having but would not have
caught the failure this exists to prevent.

**This gate fails closed, and it is the only one that does.** The stale and
degraded gates deploy first and then redden the run, because a legible degraded
dashboard beats an outage. That trade does not survive here: a snapshot failing
validation may contain something the contract forbids, and publishing it to find
out is the entire failure. A non-zero exit fails the collect job, so build and
deploy never run and the previously published artifact stays where it is.

**Staleness is a property of a run, not of the contract.** `--fresh` is passed
only when collection actually succeeded. The committed fixture must satisfy every
structural rule — it is a published artifact whenever collection fails — but it
is deliberately old, and demanding freshness of it would fail every run in
exactly the situation it exists to cover. A *future* timestamp is refused
either way: it makes a stale artifact read as current for as long as the skew
lasts, which is the one direction that suppresses the staleness warning.

**A violation names the field path and the reason, never the value.** The thing
that failed validation is exactly the thing not to copy into a log that is
public on this repository.

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

## Decision: a privileged action is the person's, not the dashboard's

**Decision.** Signing in with GitHub uses a **GitHub App user authorization**,
not an OAuth App. For an identity on the `ADMIN_SUBJECTS` allowlist the
resulting user-to-server token is kept — sealed with AES-GCM, keyed by session
id, in D1 — and every privileged call is made with it. For everyone else it is
used once to resolve a login and discarded, exactly as before.

So the dashboard does not decide whether a pull request may be approved.
GitHub does, against the person's own access, and the review it records says
their name.

**Why.** The obvious build is a bot: give the Worker an installation token with
`pull_requests: write`, keep a list of who may press the button, and act. It
needs no token store, works from any provider, and is wrong in two ways that
compound.

The first is blast radius. That token is a standing, fleet-wide write
capability sitting at the edge of a public static site, and the only thing
between it and the fleet is a list this repository maintains. Every bug in the
gate, every stolen session, every future route that forgets a check inherits
the full permissions of the App. Nothing about it is bounded by who is asking.

The second is worse for a governance tool specifically: it launders authorship.
This organization's pull requests are frequently opened by an agent bot. If a
bot then approves them, the two-eyes property is gone on paper as well as in
fact — the audit trail on GitHub reads `dashboard-bot approved`, and the
control that was supposed to be a human looking at a diff has become a service
account with a checkbox. A dashboard that makes that easy is worse than one
that cannot act at all.

A user token inverts both. It cannot exceed what the person could already do,
so the permission question is answered by the system that owns the answer
rather than duplicated into a matrix here that will drift. It expires in hours
and refreshes on rotation, so a leaked store is a short-lived problem rather
than a permanent one. Losing org access revokes the dashboard automatically,
with no list to remember to edit. And the review reads as the human, because it
was.

**The allowlist survives, demoted.** It decides who *sees* privileged UI, not
what succeeds. Two independent gates, and the outer one is not ours. It is
keyed on provider subject rather than login or email: a GitHub login can be
renamed and then claimed by someone else, an email can be reassigned, and
Apple's relay address is per-app. It is re-read from configuration on every
request rather than baked into the session cookie, so removing someone takes
effect on their next request rather than at their next sign-in — the direction
that matters when the reason for removing them is urgent.

**The set of actions is closed, and there is no proxy.** Three routes: list the
App's installation repositories, list one repository's open pull requests,
submit one review. No route forwards an arbitrary method and path to GitHub,
because a generic proxy has whatever permissions the token has, and this token
can write. Adding a verb is a diff, reviewed, the same property the snapshot
validator's closed key set gives the published artifact.

**An approval names the commit it approves.** The request carries the head sha
that was on screen; the Worker compares it and refuses `409` if it moved, then
passes `commit_id` so GitHub refuses independently if it moves between the
check and the call. A push between render and click makes it a different pull
request wearing the same number, and approving that is precisely the failure
a review control exists to prevent. This is stricter than GitHub's own UI.

**The record precedes the act.** The audit row is written before the request
leaves, and a write that fails refuses the action — 503, nothing sent. The
alternative, recording outcomes afterwards, cannot represent the state that
matters most: a call that left here and never came back. That state has a name
in the schema (`attempted`) and is the one worth investigating. A row left at
`attempted` after a successful call is a false alarm; a missing row after a
successful call is a false all-clear, and this repository errs in the first
direction. The client's idempotency key is the row's primary key, so a double
submit collides with the row it already wrote instead of approving twice.

**A stored token does not outlive every path that could use it.** The session
cookie lasts eight hours; the refresh token its row seals is honored for
months. Deleting rows only on sign-out would leave routine daily sign-ins
accreting live-credential rows nothing ever reads again. So the privileged
path opportunistically reaps rows whose refresh expiry has passed, and a fresh
admin sign-in deletes any prior row for the same identity — the session that
wrote it can no longer reach it. Best effort in both cases: cleanup must never
be the reason a sign-in or an action fails.

**Reading and acting have different clocks.** The session lasts eight hours
because re-authenticating to read a dashboard hourly is theatre. Acting
requires authentication within the last hour, because a cookie lifted from a
walked-away laptop should usually be too old to approve anything, and for an
App the person has already authorized, re-authenticating is a silent redirect.

**Identity tracking is best effort; the audit log is not.** A database that
cannot take a write must never be able to deny every account a read-only
dashboard, so a failed sign-in record is logged and ignored. The same failure
on the audit path stops the action. Two stores, two postures, and the
difference is whether anything irreversible depends on the write.

**A sign-in record is a subject, not a person.** `identities` keeps the
provider, its stable subject, two timestamps, and a counter — no login, no
email. The subject arrives through the OAuth code exchange, cannot be forged
by the client, and identifies the account *to the provider*, who already holds
login, email, and cross-service history at higher fidelity than this Worker
could record. Anything beyond it would be a low-quality copy of evidence
someone else keeps better — and, for a table nothing reads back, pure leak
surface. The audit log is the deliberate exception: stored-because-it-acted
keeps the `login`, stored-because-it-existed does not.

**Nothing privileged is publishable.** The panel shows pull request titles and
authors — both on the forbidden list the snapshot is validated against. That is
the reason they are served live, per session, `private, no-store`, from a route
the collector never touches, rather than added to the artifact. The redaction
contract is unchanged by this work, and the privileged surface must not become
the way around it.

**Rejected alternatives.** *Bot installation token*, above — the design this
exists instead of. *An OAuth App with `repo` scope* also acts as the person and
needs no D1, but its token never expires and carries write access to every
repository that person can reach, which is the opposite of an installation
boundary. *Dashboard proposes, a workflow disposes* — dispatch an intent to a
workflow with environment protection — has the smallest edge blast radius of
all and is the right shape for a genuinely destructive fleet-wide action; for
approving a pull request it means approving twice, and the indirection buys
nothing the user token does not already give.

**Consequence.** Sign-in with GitHub now requires a GitHub App, and existing
sessions sign out once on deploy because the session claim shape gained an id.
Until `ADMIN_SUBJECTS` is set, nobody is privileged and the panel renders for
no one — which is the correct resting state for a deployment that has not
decided who may act.

## Local development

- Browse URL: `https://local.dev.zts1.com:8443/`
- Listen bind: `127.0.0.1`
- Port **8443** (documented; not 443)
- TLS material from `~/.quorum/certs`, passphrase via `DASHBOARD_TLS_KEY_PASSPHRASE`
- Auth is bypassed by default (`VITE_AUTH_DISABLED=1`); the `/auth/*` endpoints
  live in the Worker, not in Vite
