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
   * Why reads were missing, in aggregate — never which repo.
   *
   * A `null` count means the collector could not read it, but not why. Denied
   * is a permission that will not change during the run; rate-limited is
   * transient and was retried first. Collapsing them loses the difference
   * between "fix the token" and "wait".
   */
  collection: CollectionHealth;
  repos: RepoSnapshot[];
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
  codeqlConfigured: boolean | null;
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
};
