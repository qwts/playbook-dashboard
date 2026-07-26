import { useEffect, useState } from 'react';
import {
  boolLabel,
  ciLabel,
  countByStatus,
  countCiFailing,
  countMissingCi,
  formatRelative,
  isSnapshotStale,
  sumOpenSecurity,
  visibleRepos,
} from './lib/aggregate';
import type { RepoSnapshot, Snapshot } from './types/snapshot';

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; snapshot: Snapshot };

function toneForCi(repo: RepoSnapshot): 'ok' | 'warn' | 'danger' | 'muted' {
  const label = ciLabel(repo);
  if (label === 'success') return 'ok';
  if (label === 'no CI') return 'muted';
  if (label === 'running') return 'warn';
  return 'danger';
}

function toneForCount(n: number | null): 'ok' | 'warn' | 'danger' | 'muted' {
  if (n === null) return 'muted';
  if (n === 0) return 'ok';
  if (n < 3) return 'warn';
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

export function App() {
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    const url = `${import.meta.env.BASE_URL}data/snapshot.json`;
    let cancelled = false;

    fetch(url)
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

  return (
    <div className="app">
      <header className="hero">
        <div className="brand">Playbook Dashboard</div>
        <h1>Governed fleet posture</h1>
        <p>
          Public, redacted view of security counts, repository properties, and CI status across
          the qwts playbook-engineering manifest. Alert bodies, paths, and secret material are never
          published here.
        </p>
        <div className="meta-row">
          <span className="pill" data-tone={stale ? 'warn' : 'ok'}>
            snapshot {formatRelative(state.snapshot.generatedAt)}
            {stale ? ' · stale' : ''}
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
          <div className="value">{openSecurity}</div>
        </div>
        <div className="stat">
          <div className="label">CI failing</div>
          <div className="value">
            {failing}
            <span className="muted" style={{ fontSize: '0.9rem', fontWeight: 500 }}>
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
                .sort((a, b) => sumOpenSecurity([b]) - sumOpenSecurity([a]))
                .map((repo) => {
                  const total = sumOpenSecurity([repo]);
                  return (
                    <tr key={repo.name}>
                      <td>
                        <a className="repo-link" href={repo.htmlUrl}>
                          {repo.name}
                        </a>
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
                        <span className="badge" data-tone={toneForCount(total)}>
                          {total}
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
                    <a className="repo-link" href={repo.htmlUrl}>
                      {repo.name}
                    </a>
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
                    <a className="repo-link" href={repo.htmlUrl}>
                      {repo.name}
                    </a>
                  </td>
                  <td className="muted">{repo.ci.workflowName ?? '—'}</td>
                  <td>
                    {repo.ci.htmlUrl ? (
                      <a className="repo-link" href={repo.ci.htmlUrl}>
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
