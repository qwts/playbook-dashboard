import type { Qualifications, QualificationRun, RepoSnapshot, Snapshot } from '../types/snapshot';
import { PILLARS, STALE_MS } from './snapshot-schema.ts';

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
 * How much of the fleet meets the whole security floor.
 *
 * `complete` counts repos where every floor bit is `true`. A `null` bit means
 * the collector could not read the setting, and an unread setting cannot be
 * claimed as met — so a repo with any `null` is not complete, and `unknown`
 * counts it so the tile can say the read was partial instead of quietly
 * treating "could not tell" as "off".
 */
export type FloorCoverage = {
  /** Repos with every floor bit `true`. */
  complete: number;
  /** Repos with at least one bit the collector could not read. */
  unknown: number;
  /** All repos considered. */
  total: number;
};

export function floorCoverage(repos: RepoSnapshot[]): FloorCoverage {
  let complete = 0;
  let unknown = 0;

  for (const repo of repos) {
    // The snapshot is untrusted input, checked field-by-field rather than
    // flattened: only a literal `true` is a met boolean bit, and only a member
    // of the closed enum is a met `codeqlSetup`. A corrupted enum value is
    // unknown — never silently met, and never silently ignored — matching the
    // answer `degradedReasons` gives for the same field.
    const boolBits = [
      repo.securityFloor?.secretScanning,
      repo.securityFloor?.pushProtection,
      repo.securityFloor?.dependabotAlerts,
      repo.securityFloor?.privateVulnerabilityReporting,
      repo.securityFloor?.defaultBranchRuleset,
    ];
    const codeqlSetup = repo.securityFloor?.codeqlSetup;

    const boolsMet = boolBits.every((bit) => bit === true);
    const boolsUnknown = boolBits.some((bit) => typeof bit !== 'boolean');
    const codeqlMet = codeqlSetup === 'default' || codeqlSetup === 'advanced';
    const codeqlUnknown = codeqlSetup !== 'default' && codeqlSetup !== 'advanced' && codeqlSetup !== 'none';

    if (boolsMet && codeqlMet) complete += 1;
    else if (boolsUnknown || codeqlUnknown) unknown += 1;
  }

  return { complete, unknown, total: repos.length };
}

/**
 * Green is the claim "every published repo meets the whole floor", which a
 * partial read cannot make — same rule as `toneForOpenSecurity`.
 */
export function toneForFloorCoverage(coverage: FloorCoverage): Tone {
  if (coverage.total === 0) return 'muted';
  if (coverage.unknown > 0) return 'warn';
  return coverage.complete === coverage.total ? 'ok' : 'warn';
}

/**
 * The `Pillars clean` tile's numbers, or the honest refusal to produce them.
 *
 * `evaluated: false` means no published repo has a known `workflowCount` —
 * the run read nothing, so the denominator would be a pure guess, and a
 * denominator that cannot be derived is not published as one. The tile
 * renders `?` alone, not `? / N`.
 *
 * When evaluated, `total` excludes repos with no workflow files: a vacuous
 * pass is not a pass claim, and an absence is not a deficit — those repos are
 * out of both the numerator and the denominator, counted in `noWorkflows`
 * instead. A repo whose *listing failed* is not "no workflows": it stays in
 * `total` and counts `unknown`, because a repo that secretly has no workflows
 * can only make the tile less green — the loud direction.
 *
 * Invariant the renderer relies on: `total + noWorkflows === repos.length`,
 * by construction — `total` is defined as published-minus-`noWorkflows`,
 * never computed independently, so the on-screen reconciliation (8 + 1 = 9)
 * cannot fail to add up.
 *
 * `clean` + `unknown` do not partition `total`, deliberately: a repo that is
 * both failing and partially unread counts `unknown` (the loud direction),
 * and a repo failing cleanly counts in neither.
 */
export type PillarCoverage =
  | { evaluated: false }
  | { evaluated: true; clean: number; unknown: number; total: number; noWorkflows: number };

export function pillarCoverage(repos: RepoSnapshot[]): PillarCoverage {
  let anyKnownCount = false;
  let noWorkflows = 0;
  let clean = 0;
  let unknown = 0;

  for (const repo of repos) {
    // The snapshot is untrusted input: anything that is not a sane count is
    // an unknown count, and the repo stays in the denominator.
    const count = repo.actionsPosture?.workflowCount;
    const countKnown = typeof count === 'number' && Number.isInteger(count) && count >= 0;
    if (countKnown) anyKnownCount = true;

    const statuses = PILLARS.map((pillar) => repo.actionsPosture?.[pillar]?.status);
    if (countKnown && count === 0) {
      // Only a row whose pillars all agree it has nothing to assess leaves
      // the denominator. A zero count beside an assessed status is a
      // contradiction the validator refuses at publish time; here it would
      // let a corrupted row *shrink* the denominator — the flattering
      // direction — so it stays in `total` and counts unknown instead.
      if (statuses.every((status) => status === 'none')) {
        noWorkflows += 1;
        continue;
      }
      unknown += 1;
      continue;
    }
    if (statuses.every((status) => status === 'pass')) clean += 1;
    // In-denominator repos: `'none'` here contradicts the count beside it, so
    // it is corruption — unknown, never silently clean, never silently ignored.
    if (statuses.some((status) => status !== 'pass' && status !== 'warn' && status !== 'fail')) {
      unknown += 1;
    }
  }

  if (!anyKnownCount) return { evaluated: false };
  return { evaluated: true, clean, unknown, total: repos.length - noWorkflows, noWorkflows };
}

/**
 * Green only when every assessed repo passes every pillar and nothing is
 * unknown — the same claim discipline as `toneForFloorCoverage`, over the
 * pillar denominator. Unevaluated and an all-`none` fleet are muted: there is
 * nothing to be green *about*.
 */
export function toneForPillarCoverage(coverage: PillarCoverage): Tone {
  if (!coverage.evaluated) return 'muted';
  if (coverage.total === 0) return 'muted';
  if (coverage.unknown > 0) return 'warn';
  return coverage.clean === coverage.total ? 'ok' : 'warn';
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

/**
 * The current qualification matrix: the latest verdict per check and
 * provider/model route, derived from run history at render time. The snapshot
 * deliberately carries no denormalized "current" table — one source of truth,
 * and a stale hand-edited artifact cannot disagree with itself about what is
 * current.
 *
 * Runs whose artifacts expired or failed to read contribute nothing here:
 * absence of evidence about a route is rendered in the history, not silently
 * promoted into the matrix as if it were a measurement.
 */
export type QualificationRouteRow = {
  check: string;
  provider: string | null;
  model: string | null;
  qualified: boolean;
  requiredLevel: string | null;
  achievedLevel: string | null;
  promptVersion: string | null;
  fixtureSuite: string | null;
  runId: number;
  url: QualificationRun['url'];
  createdAt: string;
};

export function latestQualifications(qualifications: Qualifications | null): QualificationRouteRow[] {
  if (qualifications === null) return [];
  const latest = new Map<string, QualificationRouteRow>();
  for (const run of qualifications.runs) {
    if (run.artifacts !== 'read' || run.results === null) continue;
    for (const result of run.results) {
      const key = `${result.check} ${run.provider ?? ''} ${run.model ?? ''}`;
      const seen = latest.get(key);
      // GitHub lists runs newest-first, but ordering is the API's claim, not
      // the artifact's — compare timestamps rather than trusting position.
      if (seen && Date.parse(seen.createdAt) >= Date.parse(run.createdAt)) continue;
      latest.set(key, {
        check: result.check,
        provider: run.provider,
        model: run.model,
        qualified: result.qualified,
        requiredLevel: result.requiredLevel,
        achievedLevel: result.achievedLevel,
        promptVersion: result.promptVersion,
        fixtureSuite: result.fixtureSuite,
        runId: run.runId,
        url: run.url,
        createdAt: run.createdAt,
      });
    }
  }
  return [...latest.values()].sort(
    (a, b) =>
      a.check.localeCompare(b.check) ||
      (a.provider ?? '').localeCompare(b.provider ?? '') ||
      (a.model ?? '').localeCompare(b.model ?? ''),
  );
}

export function toneForQualification(row: QualificationRouteRow): Tone {
  return row.qualified ? 'ok' : 'danger';
}

/** One run's outcome for the history table, without reading absence as failure. */
export function qualificationRunLabel(run: QualificationRun): string {
  if (run.artifacts === 'expired') return 'artifacts expired';
  if (run.artifacts === 'unreadable') return 'unreadable';
  const results = run.results ?? [];
  const qualified = results.filter((result) => result.qualified).length;
  return `${qualified}/${results.length} qualified`;
}

export function toneForQualificationRun(run: QualificationRun): Tone {
  if (run.artifacts !== 'read') return 'muted';
  const results = run.results ?? [];
  return results.every((result) => result.qualified) ? 'ok' : 'warn';
}
