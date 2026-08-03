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
  sumOpenSecurity,
  toneForCount,
  toneForFloorCoverage,
  toneForOpenSecurity,
  visibleRepos,
  unreadableCount,
  withheldCount,
} from './lib/aggregate';
import type { Tone } from './lib/aggregate';
import { PROVIDER_LABELS, type Session } from './lib/auth';
import { Review } from './Review';
import { validateSnapshot } from './lib/snapshot-schema.ts';
import type { RepoSnapshot, Snapshot } from './types/snapshot';

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
          {bit.key}:{bit.label}
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

  const who = session.login ?? session.email ?? 'signed in';

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
            {openSecurityLabel(openSecurity)}
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
                          {repo.security.dependabotOpen ?? '—'}
                        </span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          data-tone={toneForCount(repo.security.codeScanningOpen)}
                        >
                          {repo.security.codeScanningOpen ?? '—'}
                        </span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          data-tone={toneForCount(repo.security.secretScanningOpen)}
                        >
                          {repo.security.secretScanningOpen ?? '—'}
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
                          {openSecurityLabel(total)}
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
                    {repo.codexSyncEnabled === null
                      ? '—'
                      : repo.codexSyncEnabled
                        ? 'managed'
                        : 'off'}
                  </td>
                  <td>
                    <FloorBits repo={repo} />
                  </td>
                  <td className="muted">{repo.delta || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
                  <td className="muted">{repo.ci.workflowName ?? '—'}</td>
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
                  <td className="muted">{formatRelative(repo.ci.updatedAt, now)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
