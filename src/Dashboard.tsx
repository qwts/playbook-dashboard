import { useEffect, useState } from 'react';
import {
  boolLabel,
  ciClass,
  ciLabel,
  compareByExposure,
  countByStatus,
  countCiFailing,
  countMissingCi,
  floorCoverage,
  formatRelative,
  governedCount,
  isSnapshotStale,
  openSecurityLabel,
  pillarCoverage,
  sumOpenSecurity,
  toneForCount,
  toneForFloorCoverage,
  toneForOpenSecurity,
  toneForPillarCoverage,
  visibleRepos,
  unreadableCount,
  withheldCount,
  latestQualifications,
  qualificationRunLabel,
  toneForQualification,
  toneForQualificationRun,
} from './lib/aggregate';
import type { Tone } from './lib/aggregate';
import { PROVIDER_LABELS, type Session } from './lib/auth';
import { Review } from './Review';
import { PILLARS, validateSnapshot } from './lib/snapshot-schema.ts';
import type { PillarResult, RepoSnapshot, Snapshot } from './types/snapshot';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; snapshot: Snapshot };

type DashboardProps = {
  session: Session | null;
  onSignOut: () => void;
  /** Session lapsed mid-view — a snapshot refresh came back 401. */
  onAuthRequired?: () => void;
};

/** The collector republishes hourly; a pinned tab should notice without a reload. */
const REFRESH_INTERVAL_MS = 15 * 60 * 1000;

/** Relative timestamps and the stale pill re-evaluate on this cadence. */
const CLOCK_TICK_MS = 60 * 1000;

/**
 * A repo name, linked only when the collector published a validated URL.
 *
 * `rel="noreferrer"` on every outbound anchor so the dashboard's own URL is not
 * sent to the destination.
 */
function RepoLink({ repo }: { repo: RepoSnapshot }) {
  if (!repo.htmlUrl) return <span className="repo-link">{repo.name}</span>;
  return (
    <a className="repo-link" href={repo.htmlUrl} rel="noreferrer">
      {repo.name}
    </a>
  );
}

/**
 * A glyph-only verdict with its word for the screen reader. `?` announces as
 * "question mark" or is skipped and `—` is usually silent — without the word,
 * unknown and absent collapse in audio, the two states the design works
 * hardest to keep apart.
 */
function Glyph({ glyph, word }: { glyph: string; word: string }) {
  return (
    <>
      <span aria-hidden="true">{glyph}</span>
      <span className="sr-only">{word}</span>
    </>
  );
}

/**
 * UI-owned literals keyed by reason code — nothing from the snapshot is ever
 * rendered as text. Class of problem, never an instance: no file, job, step,
 * line, action name, or count. Each literal names the standing grant, not the
 * detector. Copy owned by Design (handoff §5); changing it here without them
 * is scope creep.
 */
const PILLAR_FINDING_TEXT: Record<string, string> = {
  'unpinned-third-party': 'Third-party actions run from a mutable tag rather than a pinned commit.',
  'unpinned-first-party': 'First-party actions run from a mutable tag rather than a pinned commit.',
  // "by default" was dropped from the handoff wording: this code fires only on
  // an *explicit* write-all grant, and the literal must claim exactly what the
  // detector found (flagged to Design; the deletion is pending their blessing).
  'write-all': 'Workflows are granted write access to everything.',
  'no-permissions-block': 'Workflows declare no permissions and inherit the repository default.',
  'privileged-trigger-checkout': 'A privileged trigger checks out untrusted code.',
  'secrets-in-privileged-trigger': 'A privileged trigger exposes repository secrets to untrusted code.',
  'privileged-trigger': 'A privileged trigger is present, with nothing unsafe found in it.',
};

/** Unknown is a gap in the run; absent is a decision by the owner. */
const PILLAR_UNKNOWN_TEXT = 'Could not be read this run. Unknown, not clean.';
const PILLAR_NONE_TEXT = 'No workflows. Nothing to assess, and nothing withheld.';

/**
 * Pillar chips: workflow content, deliberately not the floor's `key:value`
 * grammar — a different family flag, a different fixer (a pull request, not a
 * settings pane). Chips iterate `PILLARS`; render order never reads payload
 * key order, so no artifact can reorder the badges. `data-reason` is a test
 * hook, never rendered as text. Chips are not interactive and not focusable.
 */
function PillarBits({ repo }: { repo: RepoSnapshot }) {
  return (
    <div className="pillar-grid">
      {PILLARS.map((name) => {
        const result: PillarResult | undefined = repo.actionsPosture?.[name];
        const status = result?.status;
        if (status === 'pass' || status === 'warn' || status === 'fail') {
          const tone: Tone = status === 'pass' ? 'ok' : status === 'warn' ? 'warn' : 'danger';
          return (
            <span
              key={name}
              className="badge"
              data-family="pillar"
              data-tone={tone}
              data-reason={result?.reason ?? undefined}
            >
              {name} <span className="v">{status}</span>
            </span>
          );
        }
        const absent = status === 'none';
        return (
          <span
            key={name}
            className="badge"
            data-family="pillar"
            data-tone="muted"
            data-state={absent ? 'absent' : 'unknown'}
          >
            {name}{' '}
            <span className="v" aria-hidden="true">
              {absent ? '—' : '?'}
            </span>
            <span className="sr-only">{absent ? 'no workflows' : 'unknown'}</span>
          </span>
        );
      })}
    </div>
  );
}

/**
 * One line per non-`pass` pillar, in pillar order, never severity order — a
 * severity-ordered list is a ranking, and pillars do not get one. Unknown
 * pillars collapse into one line; an all-`pass` row prints a quiet dash and
 * says nothing else (nothing congratulated).
 */
function PillarFindings({ repo }: { repo: RepoSnapshot }) {
  const posture = repo.actionsPosture;
  if (posture?.workflowCount === 0) {
    return (
      <ul className="findings">
        <li>
          <span className="p">workflows</span>
          <span className="t" data-tone="muted">
            {PILLAR_NONE_TEXT}
          </span>
        </li>
      </ul>
    );
  }

  const items: { key: string; label: string; text: string; muted?: boolean }[] = [];
  let unknown = 0;
  for (const name of PILLARS) {
    const result = posture?.[name];
    if (result?.status === 'warn' || result?.status === 'fail') {
      // A validated snapshot guarantees the code is in vocabulary; a missing
      // literal degrades to the unknown line rather than rendering the code.
      const text = (result.reason && PILLAR_FINDING_TEXT[result.reason]) || PILLAR_UNKNOWN_TEXT;
      items.push({ key: name, label: name, text });
    } else if (result?.status !== 'pass') {
      unknown += 1;
    }
  }
  if (unknown > 0) {
    items.push({
      key: 'unknown',
      label: `${unknown} pillar${unknown === 1 ? '' : 's'}`,
      text: PILLAR_UNKNOWN_TEXT,
      muted: true,
    });
  }
  if (items.length === 0) {
    return (
      <span className="muted">
        <Glyph glyph="—" word="none" />
      </span>
    );
  }
  return (
    <ul className="findings">
      {items.map((item) => (
        <li key={item.key}>
          <span className="p">{item.label}</span>
          <span className="t" data-tone={item.muted ? 'muted' : undefined}>
            {item.text}
          </span>
        </li>
      ))}
    </ul>
  );
}

function toneForCi(repo: RepoSnapshot): Tone {
  switch (ciClass(repo)) {
    case 'passing':
      return 'ok';
    case 'none':
      return 'muted';
    case 'running':
    case 'inconclusive':
      return 'warn';
    case 'failing':
      return 'danger';
  }
}

function FloorBits({ repo }: { repo: RepoSnapshot }) {
  const floor = repo.securityFloor;
  type Bit = { key: string; label: string; tone: Tone; title: string };

  const flag = (key: string, value: boolean | null): Bit => ({
    key,
    label: boolLabel(value),
    tone: value === true ? 'ok' : value === false ? 'danger' : 'muted',
    title: `${key}: ${boolLabel(value)}`,
  });

  const codeqlLabel = floor.codeqlSetup ?? '?';
  const codeql: Bit = {
    key: 'codeql',
    label: codeqlLabel,
    tone: floor.codeqlSetup === 'default' || floor.codeqlSetup === 'advanced' ? 'ok' : floor.codeqlSetup === 'none' ? 'danger' : 'muted',
    title: `codeql: ${codeqlLabel}${floor.codeqlLastAnalysisAt ? ` (last: ${new Date(floor.codeqlLastAnalysisAt).toLocaleDateString()})` : ''}`,
  };

  const bits: Bit[] = [
    flag('secrets', floor.secretScanning),
    flag('push', floor.pushProtection),
    flag('dependabot', floor.dependabotAlerts),
    flag('pvr', floor.privateVulnerabilityReporting),
    codeql,
    flag('ruleset', floor.defaultBranchRuleset),
  ];

  return (
    <div className="floor-grid">
      {bits.map((bit) => (
        <span key={bit.key} className="badge" data-tone={bit.tone} title={bit.title}>
          {/* A bare `?` announces as "question mark" or is skipped; the word
              rides along visually hidden so unknown survives audio. */}
          {bit.key}:{bit.label === '?' ? <Glyph glyph="?" word="unknown" /> : bit.label}
        </span>
      ))}
    </div>
  );
}

/**
 * Who is signed in, and the way back out.
 *
 * Renders nothing when auth is bypassed for local development, since there is
 * no session to describe.
 */
function AccountRow({ session, onSignOut }: DashboardProps) {
  if (!session) return null;

  const who = session.login ?? 'signed in';

  return (
    <div className="account">
      <span className="account-who">
        {PROVIDER_LABELS[session.provider]} · {who}
      </span>
      <button type="button" className="signout" onClick={onSignOut}>
        Sign out
      </button>
    </div>
  );
}

export function Dashboard({ session, onSignOut, onAuthRequired }: DashboardProps) {
  const [state, setState] = useState<LoadState>({ status: 'loading' });
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const url = `${import.meta.env.BASE_URL}data/snapshot.json`;
    let cancelled = false;
    // A request that stalls past the next tick overlaps the one that replaces
    // it, and nothing guarantees the responses resolve in start order. Only
    // the most recently started request may write state, so a slow response
    // carrying an older artifact cannot overwrite a newer one.
    let latestRequest = 0;

    // Credentialed so the Worker sees the session cookie on /data/*.
    async function load() {
      const seq = ++latestRequest;
      try {
        const response = await fetch(url, { credentials: 'include' });
        if (cancelled || seq !== latestRequest) return;
        if (response.status === 401) {
          // The Worker no longer honors the session. Degrade to sign-in
          // instead of leaving a stale snapshot up as if it were current.
          onAuthRequired?.();
          return;
        }
        if (!response.ok) {
          throw new Error(`Failed to load snapshot (${response.status})`);
        }
        const payload: unknown = await response.json();
        if (cancelled || seq !== latestRequest) return;
        // The snapshot is untrusted input — a stale cache, a hand-edited file,
        // or an artifact that predates the contract. Hold it to the same
        // executable contract `npm run validate` applies before publication,
        // and fail closed instead of partially rendering whatever parsed.
        //
        // The violation list is not rendered, logged, or embedded in the
        // error: its paths quote key names from the artifact that just failed
        // the trust check, which is exactly the text that must not reach a
        // reader. One violation is enough to refuse, so collection stops at
        // one — a hostile payload does not get to bill the tab a string per
        // defect. Wide clock skew because this runs on the reader's machine,
        // and an end-user clock minutes behind must not take the dashboard
        // down.
        const violations = validateSnapshot(payload, {
          clockSkewMs: 5 * 60_000,
          maxViolations: 1,
        });
        if (violations.length > 0) {
          throw new Error('Snapshot failed validation and was not rendered');
        }
        setState({ status: 'ready', snapshot: payload as Snapshot });
      } catch (error: unknown) {
        if (cancelled || seq !== latestRequest) return;
        // A failed refresh keeps the last good snapshot on screen — its own
        // timestamp says how old it is. Only the initial load renders the
        // error state, because there is nothing better to show.
        setState((current) =>
          current.status === 'ready'
            ? current
            : {
                status: 'error',
                message: error instanceof Error ? error.message : 'Failed to load snapshot',
              },
        );
      }
    }

    void load();
    const timer = window.setInterval(() => void load(), REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [onAuthRequired]);

  // Relative labels ("3h ago") and the stale pill drift out of truth in a
  // long-lived tab if they are computed only at fetch time.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), CLOCK_TICK_MS);
    return () => window.clearInterval(timer);
  }, []);

  if (state.status === 'loading') {
    return (
      <div className="app">
        <div className="state">Loading fleet snapshot…</div>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div className="app">
        <div className="state error">{state.message}</div>
      </div>
    );
  }

  const repos = visibleRepos(state.snapshot);
  const stale = isSnapshotStale(state.snapshot.generatedAt, now);
  const openSecurity = sumOpenSecurity(repos);
  const failing = countCiFailing(repos);
  const missingCi = countMissingCi(repos);
  const floor = floorCoverage(repos);
  const withheld = withheldCount(state.snapshot);
  const unreadable = unreadableCount(state.snapshot);
  const pillars = pillarCoverage(repos);
  // Derived from the unfiltered snapshot, not from `repos`: a row the frontend
  // backstop drops must widen the gap between published and governed, not
  // shrink both sides in step and vanish. `withheld` and `unreadable` stay
  // separate pills — the denominator needs both, the reader needs them apart.
  const governed = governedCount(state.snapshot);

  return (
    <div className="app">
      <header className="hero">
        <div className="hero-top">
          <div className="brand">Playbook Dashboard</div>
          <AccountRow session={session} onSignOut={onSignOut} />
        </div>
        <h1>Governed fleet posture</h1>
        <p>
          Redacted view of security counts, repository properties, and CI status across the qwts
          playbook-engineering manifest. Alert bodies, paths, and secret material are never
          published here. Repositories appear only where the manifest opts them in and GitHub
          reports them public, so this is a deliberate subset of the governed fleet.
        </p>
        <div className="meta-row">
          <span className="pill" data-tone={stale ? 'warn' : 'ok'}>
            snapshot {formatRelative(state.snapshot.generatedAt, now)}
            {stale ? ' · stale' : ''}
          </span>
          <span
            className="pill"
            data-tone={governed === null || unreadable ? 'warn' : withheld ? 'warn' : 'ok'}
            title="Governed repos are those the manifest lists as not retired. Withheld repos were deliberately not published and publish no name, counts, or posture. Unreadable repos are ones whose gate lookup failed — denied, rate-limited, timed out, or a 404 for a repo deleted or renamed since the manifest was written. A failure, not a decision."
          >
            published {repos.length} of {governed ?? '?'} governed
            {withheld ? ` · ${withheld} withheld` : ''}
            {unreadable ? ` · ${unreadable} unreadable` : ''}
            {governed === null ? ' · count unknown' : ''}
          </span>
          <span className="pill">
            source {state.snapshot.source.manifestRepo}/{state.snapshot.source.manifestPath}
          </span>
        </div>
      </header>

      <section className="overview" aria-label="Fleet overview">
        <div className="stat">
          <div className="label">Active</div>
          <div className="value">{countByStatus(repos, 'active')}</div>
        </div>
        <div className="stat">
          <div className="label">Onboarding</div>
          <div className="value">{countByStatus(repos, 'onboarding')}</div>
        </div>
        <div className="stat">
          <div className="label">Open security</div>
          <div className="value" data-tone={toneForOpenSecurity(openSecurity)}>
            {openSecurityLabel(openSecurity) === '?' ? (
              <Glyph glyph="?" word="unknown" />
            ) : (
              openSecurityLabel(openSecurity)
            )}
            {openSecurity.unknown > 0 ? (
              <span className="muted qualifier">
                {' '}
                · {openSecurity.unknown} unreadable
              </span>
            ) : null}
          </div>
        </div>
        <div className="stat">
          <div className="label">CI failing</div>
          <div className="value">
            {failing}
            <span className="muted qualifier">
              {' '}
              / {missingCi} no CI
            </span>
          </div>
        </div>
        <div className="stat">
          <div className="label">Floor complete</div>
          <div
            className="value"
            data-tone={toneForFloorCoverage(floor)}
            title="Published repos where every security-floor setting is enabled: secret scanning, push protection, Dependabot alerts, private vulnerability reporting, CodeQL (default or advanced setup), and a default-branch ruleset. A repo with any unreadable setting is not counted as complete."
          >
            {floor.complete} / {floor.total}
            {floor.unknown > 0 ? (
              <span className="muted qualifier">
                {' '}
                · {floor.unknown} unknown
              </span>
            ) : null}
          </div>
        </div>
        <div className="stat">
          <div className="label">Pillars clean</div>
          <div
            className="value"
            data-tone={toneForPillarCoverage(pillars)}
            title="Published repos where every Actions pillar is pass, out of the published repositories that run workflows. A repo with any unreadable pillar never counts as clean."
          >
            {!pillars.evaluated ? (
              <>
                <Glyph glyph="?" word="unknown" />
                <span className="muted qualifier"> · not evaluated</span>
              </>
            ) : pillars.total === 0 ? (
              <>
                0 / 0<span className="muted qualifier"> · no workflows in the fleet</span>
              </>
            ) : (
              <>
                {pillars.clean} / {pillars.total}
                {/* The unknown count is part of the value, never dropped when
                    zero — a tile that shows unknowns only sometimes teaches
                    the reader to stop looking for them. The no-workflows
                    clause renders only when it explains a denominator gap:
                    total + noWorkflows === published rows, by construction. */}
                <span className="muted qualifier">
                  {' '}
                  · {pillars.unknown} unknown
                  {pillars.noWorkflows > 0 ? ` · ${pillars.noWorkflows} no workflows` : ''}
                </span>
              </>
            )}
          </div>
        </div>
      </section>

      {/* Renders nothing at all for a session that is not on the allowlist —
          the panel is the one part of this page that is not the same for
          everyone, and it reads live GitHub state that never enters the
          snapshot. */}
      {session ? (
        <Review session={session} onReauthRequired={onAuthRequired ?? (() => {})} />
      ) : null}

      <section className="section">
        <header>
          <h2>Security rollup</h2>
          <p className="lede">Open alert counts only — Dependabot, CodeQL, secret scanning.</p>
        </header>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Repo</th>
                <th>Dependabot</th>
                <th>Code scanning</th>
                <th>Secrets</th>
                <th>Total</th>
              </tr>
            </thead>
            <tbody>
              {[...repos]
                .sort(compareByExposure)
                .map((repo) => {
                  const total = sumOpenSecurity([repo]);
                  return (
                    <tr key={repo.name}>
                      <td>
                        <RepoLink repo={repo} />
                      </td>
                      <td>
                        <span className="badge" data-tone={toneForCount(repo.security.dependabotOpen)}>
                          {repo.security.dependabotOpen ?? <Glyph glyph="—" word="unknown" />}
                        </span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          data-tone={toneForCount(repo.security.codeScanningOpen)}
                        >
                          {repo.security.codeScanningOpen ?? <Glyph glyph="—" word="unknown" />}
                        </span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          data-tone={toneForCount(repo.security.secretScanningOpen)}
                        >
                          {repo.security.secretScanningOpen ?? <Glyph glyph="—" word="unknown" />}
                        </span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          data-tone={toneForOpenSecurity(total)}
                          title={
                            total.unknown > 0
                              ? `${total.unknown} of 3 counts could not be read — the true total is at least ${total.known}`
                              : undefined
                          }
                        >
                          {openSecurityLabel(total) === '?' ? (
                            <Glyph glyph="?" word="unknown" />
                          ) : (
                            openSecurityLabel(total)
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <header>
          <h2>Properties</h2>
          <p className="lede">Manifest fields plus security-floor toggles.</p>
        </header>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Repo</th>
                <th>Status</th>
                <th>Visibility</th>
                <th>Shared CI</th>
                <th>Codex sync</th>
                <th>Floor</th>
                <th>Delta</th>
              </tr>
            </thead>
            <tbody>
              {repos.map((repo) => (
                <tr key={repo.name}>
                  <td>
                    <RepoLink repo={repo} />
                  </td>
                  <td>
                    <span
                      className="badge"
                      data-tone={repo.status === 'active' ? 'ok' : 'warn'}
                    >
                      {repo.status}
                    </span>
                  </td>
                  <td>{repo.visibility}</td>
                  <td>{repo.sharedCi ? 'yes' : 'no'}</td>
                  <td>
                    {repo.codexSyncEnabled === null ? (
                      <Glyph glyph="—" word="not declared" />
                    ) : repo.codexSyncEnabled ? (
                      'managed'
                    ) : (
                      'off'
                    )}
                  </td>
                  <td>
                    <FloorBits repo={repo} />
                  </td>
                  <td className="muted">{repo.delta || <Glyph glyph="—" word="none" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <header>
          <h2>Actions pillars</h2>
          <p className="lede">
            {pillars.evaluated
              ? `Workflow content, assessed for ${pillars.total} of the ${repos.length} published ` +
                `repositories${
                  pillars.noWorkflows > 0
                    ? `; ${pillars.noWorkflows} ${pillars.noWorkflows === 1 ? 'runs' : 'run'} no workflows`
                    : ''
                }. Class of problem only: no workflow, job, or line is ever named. Manifest order, not ranked.`
              : 'Workflow content. Class of problem only: no workflow, job, or line is ever named. ' +
                'Manifest order, not ranked.'}
          </p>
        </header>
        {!pillars.evaluated ? (
          // Present-and-empty rather than absent, so the section's absence is
          // never mistaken for a clean fleet.
          <div className="state">Actions pillars could not be evaluated this run.</div>
        ) : pillars.total === 0 ? (
          <div className="state">No published repository runs workflows.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Repo</th>
                  <th scope="col">Pillars</th>
                  <th scope="col">Findings</th>
                </tr>
              </thead>
              <tbody>
                {repos.map((repo) => (
                  <tr key={repo.name}>
                    <td>
                      <RepoLink repo={repo} />
                    </td>
                    <td>
                      <PillarBits repo={repo} />
                    </td>
                    <td>
                      <PillarFindings repo={repo} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="lede">
          pinning — third-party actions pinned to a commit · permissions — least-privilege workflow
          token · triggers — privileged-trigger hygiene · ? unknown · — no workflows · ? never counts
          as clean
        </p>
      </section>

      <section className="section">
        <header>
          <h2>CI / CD</h2>
          <p className="lede">Latest default-branch workflow conclusion per repo.</p>
        </header>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Repo</th>
                <th>Workflow</th>
                <th>Status</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {repos.map((repo) => (
                <tr key={repo.name}>
                  <td>
                    <RepoLink repo={repo} />
                  </td>
                  <td className="muted">{repo.ci.workflowName ?? <Glyph glyph="—" word="none" />}</td>
                  <td>
                    {repo.ci.htmlUrl ? (
                      <a className="repo-link" href={repo.ci.htmlUrl} rel="noreferrer">
                        <span className="badge" data-tone={toneForCi(repo)}>
                          {ciLabel(repo)}
                        </span>
                      </a>
                    ) : (
                      <span className="badge" data-tone={toneForCi(repo)}>
                        {ciLabel(repo)}
                      </span>
                    )}
                  </td>
                  <td className="muted">
                    {formatRelative(repo.ci.updatedAt, now) === '—' ? (
                      <Glyph glyph="—" word="none" />
                    ) : (
                      formatRelative(repo.ci.updatedAt, now)
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="section">
        <header>
          <h2>Judge qualifications</h2>
          <p className="lede">
            ACA calibrate lane — which provider/model routes are qualified to judge each check, and
            the exam history behind them.
          </p>
        </header>
        {state.snapshot.qualifications === null ? (
          <p className="lede">
            Qualification data is unavailable in this snapshot — unknown, not empty. The collector
            could not read the calibrate lane on {'qwts/agentic-code-analysis'}.
          </p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Check</th>
                    <th>Route</th>
                    <th>Qualified</th>
                    <th>Level</th>
                    <th>Prompt</th>
                    <th>Fixture suite</th>
                    <th>Examined</th>
                  </tr>
                </thead>
                <tbody>
                  {latestQualifications(state.snapshot.qualifications).map((row) => (
                    <tr key={`${row.check} ${row.provider ?? ''} ${row.model ?? ''}`}>
                      <td>{row.check}</td>
                      <td className="muted">
                        {row.provider ?? '?'}/{row.model ?? '?'}
                      </td>
                      <td>
                        <span className="badge" data-tone={toneForQualification(row)}>
                          {row.qualified ? 'yes' : 'no'}
                        </span>
                      </td>
                      <td className="muted">
                        {row.requiredLevel === null ? (
                          'ungraded'
                        ) : (
                          `${row.achievedLevel ?? 'none'} of ${row.requiredLevel}`
                        )}
                      </td>
                      <td className="muted">{row.promptVersion ?? <Glyph glyph="—" word="unknown" />}</td>
                      <td className="muted">{row.fixtureSuite ?? <Glyph glyph="—" word="unknown" />}</td>
                      <td className="muted">
                        {row.url ? (
                          <a className="repo-link" href={row.url} rel="noreferrer">
                            {formatRelative(row.createdAt, now)}
                          </a>
                        ) : (
                          formatRelative(row.createdAt, now)
                        )}
                      </td>
                    </tr>
                  ))}
                  {latestQualifications(state.snapshot.qualifications).length === 0 && (
                    <tr>
                      <td colSpan={7} className="muted">
                        No readable exam artifacts in the collection window — routes may exist whose
                        artifacts have expired; see the history below.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Exam</th>
                    <th>Route</th>
                    <th>Commit</th>
                    <th>Outcome</th>
                    <th>Checks</th>
                  </tr>
                </thead>
                <tbody>
                  {state.snapshot.qualifications.runs.map((run) => (
                    <tr key={run.runId}>
                      <td className="muted">
                        {run.url ? (
                          <a className="repo-link" href={run.url} rel="noreferrer">
                            {formatRelative(run.createdAt, now)}
                          </a>
                        ) : (
                          formatRelative(run.createdAt, now)
                        )}
                      </td>
                      <td className="muted">
                        {run.provider ?? '?'}/{run.model ?? '?'}
                      </td>
                      <td className="muted">{run.headSha ?? <Glyph glyph="—" word="unknown" />}</td>
                      <td>
                        <span className="badge" data-tone={toneForQualificationRun(run)}>
                          {qualificationRunLabel(run)}
                        </span>
                      </td>
                      <td className="muted">
                        {run.results === null ? (
                          <Glyph glyph="—" word="unknown" />
                        ) : (
                          run.results
                            .map((result) => `${result.check}${result.qualified ? '' : ' ✗'}`)
                            .join(', ')
                        )}
                      </td>
                    </tr>
                  ))}
                  {state.snapshot.qualifications.runs.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        No completed calibrate runs in the collection window.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <p className="lede">
              A qualification is a tuple — check, prompt version, fixture suite, provider, model — so
              a changed prompt or fixture suite means the route re-sits the exam. Artifacts expire
              after 30 days; expired rows state the run, never its verdicts.
            </p>
          </>
        )}
      </section>
    </div>
  );
}
