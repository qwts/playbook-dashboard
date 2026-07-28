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
   */
  withheld: number;
  repos: RepoSnapshot[];
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

export type CiStatus = {
  workflowName: string | null;
  conclusion: string | null;
  status: string | null;
  updatedAt: string | null;
  htmlUrl: string | null;
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
  htmlUrl: string;
  securityFloor: SecurityFloor;
  security: SecurityCounts;
  ci: CiStatus;
};
