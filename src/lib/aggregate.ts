import type { RepoSnapshot, Snapshot } from '../types/snapshot';
import { STALE_MS } from './snapshot-schema.ts';

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
  return nonNegativeInteger(snapshot.withheld);
}

/**
 * Count of governed repos whose publication gate could not be evaluated, or
 * `null` when the snapshot does not state it.
 *
 * Never added to `withheldCount`. A reader deciding whether the fleet is under
 * control needs "we chose not to publish these" and "we could not tell" kept
 * apart; summing them restores the conflation this field exists to undo.
 */
export function unreadableCount(snapshot: Snapshot): number | null {
  return nonNegativeInteger(snapshot.unreadable);
}

/**
 * The denominator for "published X of Y governed", or `null` when either
 * stated count is unknown.
 *
 * Built on every row the snapshot carries, not the rows `visibleRepos` lets
 * through. The frontend filter is a backstop against a snapshot that should
 * never have shipped, and a backstop that fires must leave evidence: counting
 * only visible rows would shrink numerator and denominator in step, so a
 * dropped row vanishes instead of reading as "published 7 of 9". The gap is
 * the signal.
 */
export function governedCount(snapshot: Snapshot): number | null {
  const withheld = withheldCount(snapshot);
  const unreadable = unreadableCount(snapshot);
  if (withheld === null || unreadable === null) return null;
  return snapshot.repos.length + withheld + unreadable;
}

/** The snapshot is untrusted input: anything that is not a sane count is unknown. */
function nonNegativeInteger(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) return null;
  return value;
}

export type Tone = 'ok' | 'warn' | 'danger' | 'muted';

/**
 * An open-alert total that keeps "could not be read" separate from "zero".
 *
 * `null` in `SecurityCounts` means the collector was denied the count, not that
 * there are none. Collapsing the two produces a confidently clean repo exactly
 * where the dashboard knows least — the one error that never prompts anyone to
 * look.
 */
export type OpenSecurityTotal = {
  /** Sum of the counts that could be read. The true total is at least this. */
  known: number;
  /** How many individual counts could not be read. */
  unknown: number;
};

export function sumOpenSecurity(repos: RepoSnapshot[]): OpenSecurityTotal {
  let known = 0;
  let unknown = 0;

  for (const repo of repos) {
    const counts = [
      repo.security?.dependabotOpen,
      repo.security?.codeScanningOpen,
      repo.security?.secretScanningOpen,
    ];
    for (const count of counts) {
      // The snapshot is untrusted input: anything that is not a sane count is
      // unknown, not zero. Negatives and NaN included.
      if (typeof count === 'number' && Number.isFinite(count) && count >= 0) known += count;
      else unknown += 1;
    }
  }

  return { known, unknown };
}

/**
 * `6` when fully known, `≥6` when only part of the total could be read, and `?`
 * when none of it could. Never a bare number standing in for missing data.
 */
export function openSecurityLabel(total: OpenSecurityTotal): string {
  if (total.unknown === 0) return String(total.known);
  if (total.known === 0) return '?';
  return `≥${total.known}`;
}

export function toneForCount(n: number | null): Tone {
  if (n === null) return 'muted';
  if (n === 0) return 'ok';
  if (n < 3) return 'warn';
  return 'danger';
}

/**
 * A partially-read total is never green, however small the readable part is.
 * Green is a claim of "nothing open here", which an incomplete read cannot make.
 */
export function toneForOpenSecurity(total: OpenSecurityTotal): Tone {
  if (total.unknown > 0) return total.known >= 3 ? 'danger' : 'warn';
  return toneForCount(total.known);
}

/**
 * Most-exposed first. A repo with unreadable counts sorts above every repo with
 * known counts: it cannot be ranked as safer than one that was actually
 * measured, so it does not get to sit quietly at the bottom of the table.
 */
export function compareByExposure(a: RepoSnapshot, b: RepoSnapshot): number {
  const ta = sumOpenSecurity([a]);
  const tb = sumOpenSecurity([b]);
  if (ta.unknown > 0 !== tb.unknown > 0) return ta.unknown > 0 ? -1 : 1;
  return tb.known - ta.known;
}

export function countByStatus(repos: RepoSnapshot[], status: RepoSnapshot['status']): number {
  return repos.filter((repo) => repo.status === status).length;
}

/**
 * What the latest run says about the repo's health.
 *
 * `cancelled`, `skipped`, `neutral`, and `stale` are deliberate no-ops, not
 * verdicts: a cancelled run says nothing about whether the code passes, so it
 * must not read as red or inflate the failing count. Everything else that is
 * not an explicit success is `failing` — including conclusions this code does
 * not recognize, because the snapshot is untrusted input and an unrecognized
 * verdict cannot be presumed fine.
 */
export type CiClass = 'passing' | 'failing' | 'inconclusive' | 'running' | 'none';

const CI_INCONCLUSIVE = new Set(['cancelled', 'skipped', 'neutral', 'stale']);

export function ciClass(repo: RepoSnapshot): CiClass {
  if (!repo.ci.workflowName && !repo.ci.conclusion) return 'none';
  if (repo.ci.status === 'in_progress' || repo.ci.status === 'queued') return 'running';
  if (repo.ci.conclusion === 'success') return 'passing';
  // A workflow that exists but carries no verdict — `null` or a deliberate
  // no-op — proves nothing either way: not green, not red, visibly neither.
  if (repo.ci.conclusion === null || CI_INCONCLUSIVE.has(repo.ci.conclusion)) {
    return 'inconclusive';
  }
  return 'failing';
}

export function countCiFailing(repos: RepoSnapshot[]): number {
  return repos.filter((repo) => ciClass(repo) === 'failing').length;
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
