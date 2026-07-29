import { useEffect, useState } from 'react';
import {
  boolLabel,
  ciLabel,
  compareByExposure,
  countByStatus,
  countCiFailing,
  countMissingCi,
  formatRelative,
  governedCount,
  isSnapshotStale,
  openSecurityLabel,
  sumOpenSecurity,
  toneForCount,
  toneForOpenSecurity,
  visibleRepos,
  unreadableCount,
  withheldCount,
} from './lib/aggregate';
import type { Tone } from './lib/aggregate';
import { PROVIDER_LABELS, type Session } from './lib/auth';
import type { RepoSnapshot, Snapshot } from './types/snapshot';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; snapshot: Snapshot };

type DashboardProps = {
  session: Session | null;
  onSignOut: () => void;
};

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
  const label = ciLabel(repo);
  if (label === 'success') return 'ok';
  if (label === 'no CI') return 'muted';
  if (label === 'running') return 'warn';
  return 'danger';
}

function FloorBits({ repo }: { repo: RepoSnapshot }) {
  const bits: Array<[string, boolean | null]> = [
    ['secrets', repo.securityFloor.secretScanning],
    ['push', repo.securityFloor.pushProtection],
    ['dependabot', repo.securityFloor.dependabotAlerts],
    ['pvr', repo.securityFloor.privateVulnerabilityReporting],
    ['codeql', repo.securityFloor.codeqlConfigured],
    ['ruleset', repo.securityFloor.defaultBranchRuleset],
  ];

  return (
    <div className="floor-grid">
      {bits.map(([key, value]) => (
        <span
          key={key}
          className="badge"
          data-tone={value === true ? 'ok' : value === false ? 'danger' : 'muted'}
          title={`${key}: ${boolLabel(value)}`}
        >
          {key}:{boolLabel(value)}
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

export function Dashboard({ session, onSignOut }: DashboardProps) {
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    const url = `${import.meta.env.BASE_URL}data/snapshot.json`;
    let cancelled = false;

    // Credentialed so the Worker sees the session cookie on /data/*.
    fetch(url, { credentials: 'include' })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`Failed to load snapshot (${response.status})`);
        }
        return (await response.json()) as Snapshot;
      })
      .then((snapshot) => {
        if (!cancelled) setState({ status: 'ready', snapshot });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({
            status: 'error',
            message: error instanceof Error ? error.message : 'Failed to load snapshot',
          });
        }
      });

    return () => {
      cancelled = true;
    };
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
  const stale = isSnapshotStale(state.snapshot.generatedAt);
  const openSecurity = sumOpenSecurity(repos);
  const failing = countCiFailing(repos);
  const missingCi = countMissingCi(repos);
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
            snapshot {formatRelative(state.snapshot.generatedAt)}
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
      </section>

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
                  <td className="muted">{formatRelative(repo.ci.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
