/** Versioned redacted fleet snapshot served to the public dashboard. */
export type Snapshot = {
  schemaVersion: 1;
  generatedAt: string;
  source: {
    account: string;
    manifestRepo: string;
    manifestPath: string;
  };
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
  visibility: 'public' | 'private' | 'internal' | string;
  status: RepoStatus;
  sharedCi: boolean;
  codexSyncEnabled: boolean | null;
  delta: string;
  note: string;
  htmlUrl: string;
  securityFloor: SecurityFloor;
  security: SecurityCounts;
  ci: CiStatus;
};
