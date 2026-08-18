/** Versioned redacted fleet snapshot served to the public dashboard. */
export type Snapshot = {
  schemaVersion: 1;
  generatedAt: string;
  source: {
    account: string;
    manifestRepo: string;
    manifestPath: string;
  };
  /**
   * Governed repos the collector deliberately did not publish — a count only,
   * never which ones. Present so the page can say it is showing a subset
   * instead of silently implying the fleet is smaller than it is.
   *
   * `null` when the snapshot cannot state it. The committed fixture is exactly
   * that case: it is the fallback deployed when collection fails, and it has no
   * knowledge of the fleet it would be describing. A snapshot may state what it
   * *is*; it may not assert what the fleet *is*.
   */
  withheld: number | null;
  /**
   * Governed repos whose publication gate could not be evaluated at all — any
   * failed gate lookup lands here: denied, rate-limited, timed out, a 404 for
   * a repo deleted or renamed out from under the manifest, or a response body
   * that would not parse. A count only, never which.
   *
   * Separate from `withheld` because they are different claims. `withheld` says
   * the collector *decided* not to publish, which is a statement about a fleet
   * under deliberate control. This says it could not tell — and no promise is
   * made about why: a rate limit clears next run, a deleted repo stays
   * unreadable until the manifest catches up. Folding the second into the
   * first makes a failure read as curation — the same defect as a denied count
   * rendering as a green zero, one level up.
   *
   * `null` when the snapshot cannot state it, for the same reason as `withheld`.
   */
  unreadable: number | null;
  /**
   * Why reads were missing, in aggregate — never which repo.
   *
   * A `null` count means the collector could not read it, but not why. Denied
   * is a permission that will not change during the run; rate-limited is
   * transient and was retried first. Collapsing them loses the difference
   * between "fix the token" and "wait".
   */
  collection: CollectionHealth;
  repos: RepoSnapshot[];
  /**
   * The ACA calibrate lane's judge-qualification history, read from public
   * workflow artifacts on `qwts/agentic-code-analysis`. `null` when the
   * section could not be collected at all — the committed fixture's state,
   * and the fail-closed result of a missing Actions-read grant. Unknown
   * renders as unknown, never as an empty-but-healthy matrix.
   */
  qualifications: Qualifications | null;
};

/** Route-qualification history from the ACA calibrate workflow. */
export type Qualifications = {
  source: {
    /** e.g. `qwts/agentic-code-analysis`. */
    repo: string;
    /** e.g. `calibrate.yml`. */
    workflow: string;
  };
  /** Most-recent completed calibrate runs, newest first as listed by GitHub. */
  runs: QualificationRun[];
};

/**
 * How one run's artifacts resolved. `read` is the only state that may carry
 * results. `expired` is GitHub's 30-day retention doing its documented job;
 * `unreadable` is this collection failing to learn something it set out to
 * learn. The two absence states are deliberately not collapsed.
 */
export type QualificationArtifactState = 'read' | 'expired' | 'unreadable';

export type QualificationRun = {
  runId: number;
  url: GithubUrl | null;
  createdAt: string;
  /** Abbreviated commit id of the aca tree the exam ran against, or null. */
  headSha: string | null;
  conclusion: string | null;
  /** Route under exam. From the artifact when readable, else the run title. */
  provider: string | null;
  model: string | null;
  artifacts: QualificationArtifactState;
  /** Non-null and non-empty iff `artifacts` is `'read'`. */
  results: QualificationResult[] | null;
};

/**
 * One check's verdict inside one run — structured facts only, never judge
 * prose. `requiredLevel: null` means the check reports ungraded pass/fail
 * (no ACA-0012 manifest), which is not the same claim as level-zero.
 */
export type QualificationResult = {
  check: string;
  promptVersion: string | null;
  /** Content id of the fixture suite the exam used, e.g. `sha256:…`. */
  fixtureSuite: string | null;
  requiredLevel: string | null;
  achievedLevel: string | null;
  qualified: boolean;
  levels: { id: string; status: 'passed' | 'failed' | 'skipped' }[];
  /**
   * Per-fixture grading, or `null` when the detail was refused at collect
   * time (malformed or over-bound) — the verdict stands alone in that case.
   * Absent entirely on snapshots published before the field existed; both
   * render as "detail unavailable", never as zero fixtures.
   */
  fixtures?: QualificationFixture[] | null;
};

/**
 * One fixture's grading: what the exam expected against what the judge
 * decided, with the criteria codes it flagged. Names and vocabulary tokens
 * only — the judge's free-text note never reaches the snapshot.
 */
export type QualificationFixture = {
  name: string;
  level: string | null;
  /** `skipped` is a level the ladder never reached — not graded either way. */
  status: 'ok' | 'miss' | 'skipped';
  expected: { assessment: string | null; verdict: string | null };
  /**
   * `null` when the judged claim is unavailable — a skipped rung the ladder
   * never reached, or an artifact that omitted the judged tokens. The
   * `status` column, not this field, is what says whether grading happened.
   */
  actual: { assessment: string | null; verdict: string | null; criteria: string[] } | null;
};

/** Counts only, fleet-wide. Never attributed to a repository. */
export type CollectionHealth = {
  /** GitHub refused: the token lacks the permission. */
  denied: number;
  /** GitHub rate-limited, after bounded retry was exhausted. */
  rateLimited: number;
  /** Timed out, or failed transport-side. */
  failed: number;
};

export type RepoStatus = 'active' | 'onboarding' | 'retired';

export type SecurityFloor = {
  secretScanning: boolean | null;
  pushProtection: boolean | null;
  dependabotAlerts: boolean | null;
  privateVulnerabilityReporting: boolean | null;
  codeqlSetup: 'default' | 'advanced' | 'none' | null;
  codeqlLastAnalysisAt: string | null;
  defaultBranchRuleset: boolean | null;
};

/** Counts only — never titles, paths, CVEs, or secret material. */
export type SecurityCounts = {
  dependabotOpen: number | null;
  codeScanningOpen: number | null;
  secretScanningOpen: number | null;
};

/**
 * A URL the collector verified is `https:` at exactly `https://github.com`.
 *
 * The type states the invariant; `sanitizeGithubUrl` in the collector enforces
 * it. Anything failing that check is published as `null`, so every consumer of
 * a URL field has to handle the absence and cannot assume a link exists.
 */
export type GithubUrl = `https://github.com/${string}`;

/**
 * One Actions pillar's verdict for one repo.
 *
 * `'none'` is owner-chosen absence — the repo has no workflow files — and is
 * repo-wide by construction: `workflowCount === 0` sets every pillar to it.
 * `null` is unknown — the collector could not read or could not parse — and is
 * never rendered green, never counted clean.
 *
 * `reason` is a machine code from the closed per-pillar vocabulary in
 * `src/lib/snapshot-schema.ts`, non-null iff `status` is `'warn'`/`'fail'`.
 * It names the class of problem, never the instance: no workflow file, job,
 * or line ever reaches the artifact. The prose a reader sees is a UI literal
 * keyed by the code.
 */
export type PillarResult = {
  status: 'pass' | 'warn' | 'fail' | 'none' | null;
  reason: string | null;
};

/** Statically assessed posture of the repo's own workflow files. */
export type ActionsPosture = {
  /** Workflow files on the default branch, or `null` when the listing failed. */
  workflowCount: number | null;
  pinning: PillarResult;
  permissions: PillarResult;
  triggers: PillarResult;
};

export type CiStatus = {
  workflowName: string | null;
  conclusion: string | null;
  status: string | null;
  updatedAt: string | null;
  htmlUrl: GithubUrl | null;
};

export type RepoSnapshot = {
  name: string;
  /**
   * Visibility as *observed* on GitHub at collection time, not as claimed by
   * the manifest. Only `public` is ever published; the field is retained so a
   * stale or hand-edited snapshot can still be filtered at render time.
   */
  visibility: 'public' | 'private' | 'internal' | string;
  status: RepoStatus;
  sharedCi: boolean;
  codexSyncEnabled: boolean | null;
  /** Manifest free text, length-capped and control-character rejected. */
  delta: string;
  /** `null` when the repo's URL failed origin validation — render unlinked. */
  htmlUrl: GithubUrl | null;
  securityFloor: SecurityFloor;
  security: SecurityCounts;
  ci: CiStatus;
  actionsPosture: ActionsPosture;
};
