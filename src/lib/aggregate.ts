import type { RepoSnapshot, Snapshot } from '../types/snapshot';

const STALE_MS = 24 * 60 * 60 * 1000;

/**
 * Rows the page is allowed to render.
 *
 * The real publication gate lives in the collector — a repo that is not
 * cleared for publication never reaches `snapshot.json` at all. This is the
 * backstop for a stale, hand-edited, or otherwise untrusted snapshot: anything
 * not observed as public at collection time is dropped rather than rendered.
 * Unknown visibility is not public, so it fails closed too.
 */
export function visibleRepos(snapshot: Snapshot): RepoSnapshot[] {
  return snapshot.repos.filter((repo) => repo.status !== 'retired' && repo.visibility === 'public');
}

/**
 * Count of governed repos this snapshot deliberately omitted, or `null` when
 * the snapshot does not state it. Null renders as unknown, never as zero.
 */
export function withheldCount(snapshot: Snapshot): number | null {
  const value: unknown = snapshot.withheld;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) return null;
  return value;
}

export function sumOpenSecurity(repos: RepoSnapshot[]): number {
  return repos.reduce((total, repo) => {
    const d = repo.security.dependabotOpen ?? 0;
    const c = repo.security.codeScanningOpen ?? 0;
    const s = repo.security.secretScanningOpen ?? 0;
    return total + d + c + s;
  }, 0);
}

export function countByStatus(repos: RepoSnapshot[], status: RepoSnapshot['status']): number {
  return repos.filter((repo) => repo.status === status).length;
}

export function countCiFailing(repos: RepoSnapshot[]): number {
  return repos.filter((repo) => {
    if (!repo.ci.status && !repo.ci.conclusion) return false;
    if (repo.ci.status === 'in_progress' || repo.ci.status === 'queued') return false;
    return repo.ci.conclusion !== null && repo.ci.conclusion !== 'success';
  }).length;
}

export function countMissingCi(repos: RepoSnapshot[]): number {
  return repos.filter((repo) => !repo.ci.workflowName && !repo.ci.conclusion).length;
}

export function isSnapshotStale(generatedAt: string, now = Date.now()): boolean {
  const ts = Date.parse(generatedAt);
  if (Number.isNaN(ts)) return true;
  return now - ts > STALE_MS;
}

export function formatRelative(iso: string | null, now = Date.now()): string {
  if (!iso) return '—';
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return '—';
  const deltaSec = Math.round((now - ts) / 1000);
  if (deltaSec < 60) return `${deltaSec}s ago`;
  const mins = Math.round(deltaSec / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export function boolLabel(value: boolean | null): string {
  if (value === true) return 'on';
  if (value === false) return 'off';
  return '?';
}

export function ciLabel(repo: RepoSnapshot): string {
  if (!repo.ci.workflowName && !repo.ci.conclusion) return 'no CI';
  if (repo.ci.status === 'in_progress' || repo.ci.status === 'queued') return 'running';
  return repo.ci.conclusion ?? repo.ci.status ?? 'unknown';
}
