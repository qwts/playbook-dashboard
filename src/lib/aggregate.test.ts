import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { CiStatus, RepoSnapshot, SecurityCounts, Snapshot } from '../types/snapshot.ts';
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
  toneForFloorCoverage,
  toneForOpenSecurity,
  visibleRepos,
  unreadableCount,
  withheldCount,
} from './aggregate.ts';

const NO_CI: CiStatus = {
  workflowName: null,
  conclusion: null,
  status: null,
  updatedAt: null,
  htmlUrl: null,
};

function repo(overrides: Partial<RepoSnapshot> = {}): RepoSnapshot {
  return {
    name: 'example',
    visibility: 'public',
    status: 'active',
    sharedCi: false,
    codexSyncEnabled: true,
    delta: '',
    htmlUrl: 'https://github.com/qwts/example',
    securityFloor: {
      secretScanning: true,
      pushProtection: true,
      dependabotAlerts: true,
      privateVulnerabilityReporting: true,
      codeqlSetup: 'advanced',
      codeqlLastAnalysisAt: '2026-07-26T12:00:00.000Z',
      defaultBranchRuleset: true,
    },
    security: { dependabotOpen: 0, codeScanningOpen: 0, secretScanningOpen: 0 },
    ci: { ...NO_CI },
    ...overrides,
  };
}

function counts(overrides: Partial<SecurityCounts> = {}): SecurityCounts {
  return { dependabotOpen: 0, codeScanningOpen: 0, secretScanningOpen: 0, ...overrides };
}

function snapshot(repos: RepoSnapshot[], withheld = 0, unreadable = 0): Snapshot {
  return {
    schemaVersion: 1,
    generatedAt: '2026-07-26T12:00:00.000Z',
    source: {
      account: 'qwts',
      manifestRepo: 'qwts/playbook-engineering',
      manifestPath: 'governance/repos.json',
    },
    withheld,
    unreadable,
    collection: { denied: 0, rateLimited: 0, failed: 0 },
    repos,
  };
}

test('retired repos leave the fleet view but stay in the manifest', () => {
  const repos = [
    repo({ name: 'active-one' }),
    repo({ name: 'onboarding-one', status: 'onboarding' }),
    repo({ name: 'retired-one', status: 'retired' }),
  ];

  const visible = visibleRepos(snapshot(repos));

  assert.deepEqual(
    visible.map((r) => r.name),
    ['active-one', 'onboarding-one'],
  );
});

test('a non-public repo is never rendered, even if it reaches the snapshot', () => {
  const repos = [
    repo({ name: 'public-one' }),
    repo({ name: 'private-one', visibility: 'private' }),
    repo({ name: 'internal-one', visibility: 'internal' }),
  ];

  const visible = visibleRepos(snapshot(repos));

  assert.deepEqual(
    visible.map((r) => r.name),
    ['public-one'],
  );
});

test('unknown visibility is withheld rather than assumed public', () => {
  for (const visibility of ['', 'unknown', 'PUBLIC', 'public ', undefined as unknown as string]) {
    const visible = visibleRepos(snapshot([repo({ name: 'mystery', visibility })]));
    assert.deepEqual(visible, [], `visibility ${JSON.stringify(visibility)} should not render`);
  }
});

test('the withheld count is reported so a partial view is visible', () => {
  assert.equal(withheldCount(snapshot([repo()], 3)), 3);
  assert.equal(withheldCount(snapshot([repo()], 0)), 0);
});

test('an absent or nonsensical withheld count reads as unknown, not zero', () => {
  for (const value of [undefined, null, -1, 1.5, Number.NaN, '2', {}]) {
    const bad = { ...snapshot([repo()]), withheld: value as number };
    assert.equal(withheldCount(bad), null, `withheld ${JSON.stringify(value)} should be unknown`);
  }
});

test('status counts separate active from onboarding', () => {
  const repos = [
    repo({ status: 'active' }),
    repo({ status: 'active' }),
    repo({ status: 'onboarding' }),
  ];

  assert.equal(countByStatus(repos, 'active'), 2);
  assert.equal(countByStatus(repos, 'onboarding'), 1);
  assert.equal(countByStatus(repos, 'retired'), 0);
});

test('open security totals every alert type across the fleet when all are known', () => {
  const repos = [
    repo({ security: counts({ dependabotOpen: 6 }) }),
    repo({ security: counts({ codeScanningOpen: 1, secretScanningOpen: 2 }) }),
  ];

  assert.deepEqual(sumOpenSecurity(repos), { known: 9, unknown: 0 });
  assert.deepEqual(sumOpenSecurity([]), { known: 0, unknown: 0 });
});

test('a repo with unreadable counts is not reported as a clean zero', () => {
  const unknown = repo({ security: counts({ dependabotOpen: null }) });
  const total = sumOpenSecurity([unknown]);

  assert.deepEqual(total, { known: 0, unknown: 1 });
  assert.notEqual(openSecurityLabel(total), '0');
  assert.notEqual(toneForOpenSecurity(total), 'ok');
});

test('an entirely unreadable repo reports unknown, not zero', () => {
  const total = sumOpenSecurity([
    repo({
      security: counts({ dependabotOpen: null, codeScanningOpen: null, secretScanningOpen: null }),
    }),
  ]);

  assert.deepEqual(total, { known: 0, unknown: 3 });
  assert.equal(openSecurityLabel(total), '?');
  assert.equal(toneForOpenSecurity(total), 'warn');
});

test('a mixed total states the floor it knows, and is never green', () => {
  const total = sumOpenSecurity([
    repo({ security: counts({ dependabotOpen: 2, codeScanningOpen: null }) }),
  ]);

  assert.deepEqual(total, { known: 2, unknown: 1 });
  assert.equal(openSecurityLabel(total), '≥2');
  assert.equal(toneForOpenSecurity(total), 'warn');
});

test('a known-high partial total escalates rather than merely warning', () => {
  const total = sumOpenSecurity([
    repo({ security: counts({ dependabotOpen: 7, secretScanningOpen: null }) }),
  ]);

  assert.equal(openSecurityLabel(total), '≥7');
  assert.equal(toneForOpenSecurity(total), 'danger');
});

test('a fully-known zero is still allowed to be green', () => {
  const total = sumOpenSecurity([repo()]);

  assert.deepEqual(total, { known: 0, unknown: 0 });
  assert.equal(openSecurityLabel(total), '0');
  assert.equal(toneForOpenSecurity(total), 'ok');
});

test('malformed counts in an untrusted snapshot are unknown, not zero', () => {
  for (const bad of [undefined, 'three', Number.NaN, -1, {}, [], true, Infinity]) {
    const total = sumOpenSecurity([
      repo({ security: counts({ dependabotOpen: bad as unknown as number }) }),
    ]);

    assert.equal(total.unknown, 1, `${JSON.stringify(bad)} should count as unreadable`);
    assert.notEqual(toneForOpenSecurity(total), 'ok');
  }
});

test('a repo with unreadable counts sorts above one that was actually measured', () => {
  const measuredHigh = repo({ name: 'measured', security: counts({ dependabotOpen: 9 }) });
  const partlyUnknown = repo({ name: 'unknown', security: counts({ dependabotOpen: null }) });
  const clean = repo({ name: 'clean' });

  const sorted = [clean, measuredHigh, partlyUnknown].sort(compareByExposure);

  assert.deepEqual(
    sorted.map((r) => r.name),
    ['unknown', 'measured', 'clean'],
  );
});

test('CI failures count, but pending and unbuilt repos do not', () => {
  const repos = [
    repo({ name: 'green', ci: { ...NO_CI, workflowName: 'CI', conclusion: 'success', status: 'completed' } }),
    repo({ name: 'red', ci: { ...NO_CI, workflowName: 'CI', conclusion: 'failure', status: 'completed' } }),
    repo({ name: 'timed-out', ci: { ...NO_CI, workflowName: 'CI', conclusion: 'timed_out', status: 'completed' } }),
    repo({ name: 'running', ci: { ...NO_CI, workflowName: 'CI', conclusion: null, status: 'in_progress' } }),
    repo({ name: 'queued', ci: { ...NO_CI, workflowName: 'CI', conclusion: null, status: 'queued' } }),
    repo({ name: 'no-ci' }),
  ];

  assert.equal(countCiFailing(repos), 2);
});

// #38. A cancelled run says nothing about whether the code passes: counting it
// as failing inflates the headline stat with verdicts that were never reached.
test('deliberate no-ops are inconclusive, not failing', () => {
  const repos = ['cancelled', 'skipped', 'neutral', 'stale'].map((conclusion) =>
    repo({ name: conclusion, ci: { ...NO_CI, workflowName: 'CI', conclusion, status: 'completed' } }),
  );

  assert.equal(countCiFailing(repos), 0);
  for (const r of repos) assert.equal(ciClass(r), 'inconclusive');
});

// The snapshot is untrusted input: a verdict this code does not recognize
// cannot be presumed fine, so it stays in the failing count.
test('an unrecognized conclusion fails closed', () => {
  const weird = repo({
    name: 'weird',
    ci: { ...NO_CI, workflowName: 'CI', conclusion: 'totally_new_verdict', status: 'completed' },
  });

  assert.equal(ciClass(weird), 'failing');
  assert.equal(countCiFailing([weird]), 1);
});

test('a workflow with no verdict is inconclusive, not green or missing', () => {
  const noVerdict = repo({
    name: 'no-verdict',
    ci: { ...NO_CI, workflowName: 'CI', conclusion: null, status: 'completed' },
  });

  assert.equal(ciClass(noVerdict), 'inconclusive');
  assert.equal(countCiFailing([noVerdict]), 0);
});

test('a repo with no workflows is missing CI, not failing it', () => {
  const repos = [
    repo({ name: 'no-ci' }),
    repo({ name: 'green', ci: { ...NO_CI, workflowName: 'CI', conclusion: 'success', status: 'completed' } }),
  ];

  assert.equal(countMissingCi(repos), 1);
  assert.equal(countCiFailing(repos), 0);
});

test('a snapshot goes stale after a day', () => {
  const now = Date.parse('2026-07-26T12:00:00.000Z');
  const hoursAgo = (h: number) => new Date(now - h * 60 * 60 * 1000).toISOString();

  assert.equal(isSnapshotStale(hoursAgo(23), now), false);
  assert.equal(isSnapshotStale(hoursAgo(25), now), true);
});

test('an unparseable timestamp is treated as stale rather than fresh', () => {
  assert.equal(isSnapshotStale('not a date', Date.parse('2026-07-26T12:00:00.000Z')), true);
});

test('relative time scales from seconds to days', () => {
  const now = Date.parse('2026-07-26T12:00:00.000Z');
  const ago = (ms: number) => new Date(now - ms).toISOString();

  assert.equal(formatRelative(ago(30_000), now), '30s ago');
  assert.equal(formatRelative(ago(5 * 60_000), now), '5m ago');
  assert.equal(formatRelative(ago(3 * 60 * 60_000), now), '3h ago');
  assert.equal(formatRelative(ago(5 * 24 * 60 * 60_000), now), '5d ago');
});

test('a missing or unparseable timestamp renders as an em dash', () => {
  const now = Date.parse('2026-07-26T12:00:00.000Z');

  assert.equal(formatRelative(null, now), '—');
  assert.equal(formatRelative('not a date', now), '—');
});

test('security-floor booleans distinguish off from unknown', () => {
  assert.equal(boolLabel(true), 'on');
  assert.equal(boolLabel(false), 'off');
  assert.equal(boolLabel(null), '?');
});

test('CI labels name the state a reader has to act on', () => {
  assert.equal(ciLabel(repo()), 'no CI');
  assert.equal(
    ciLabel(repo({ ci: { ...NO_CI, workflowName: 'CI', conclusion: null, status: 'in_progress' } })),
    'running',
  );
  assert.equal(
    ciLabel(repo({ ci: { ...NO_CI, workflowName: 'CI', conclusion: 'success', status: 'completed' } })),
    'success',
  );
  assert.equal(
    ciLabel(repo({ ci: { ...NO_CI, workflowName: 'CI', conclusion: 'failure', status: 'completed' } })),
    'failure',
  );
});

// #12, finding 3. Both produce no published row, which is why they were one
// number — but "we chose not to publish these" and "we could not tell" are
// opposite claims to anyone judging whether the fleet is under control. A rate
// limit used to make the fleet look more deliberately curated than it was.
test('a repo the collector could not evaluate is not counted as deliberately withheld', () => {
  const snap = snapshot([repo()], 2, 3);

  assert.equal(withheldCount(snap), 2);
  assert.equal(unreadableCount(snap), 3);
});

test('an absent or nonsensical unreadable count reads as unknown, not zero', () => {
  for (const value of [undefined, null, -1, 1.5, Number.NaN, '2', {}]) {
    const bad = { ...snapshot([repo()]), unreadable: value as number };
    assert.equal(unreadableCount(bad), null, `unreadable ${JSON.stringify(value)} is unknown`);
  }
});

test('the governed denominator counts every row the snapshot carries', () => {
  const snap = snapshot([repo()], 2, 1);
  assert.equal(governedCount(snap), 4);
});

// The backstop firing must leave evidence. Deriving the denominator from
// `visibleRepos` shrank both sides of "published X of Y governed" in step, so
// a row dropped at render time vanished instead of reading as a discrepancy.
test('a row dropped by the frontend backstop widens the gap instead of vanishing', () => {
  const snap = snapshot(
    [repo({ name: 'clean' }), repo({ name: 'leaked', visibility: 'private' })],
    0,
    0,
  );

  const published = visibleRepos(snap).length;
  const governed = governedCount(snap);
  assert.equal(published, 1, 'the backstop must drop the non-public row');
  assert.equal(governed, 2, 'the denominator must still count it');
  assert.ok(governed !== null && published < governed, 'the gap is the signal');
});

test('an unknown withheld or unreadable count makes the denominator unknown', () => {
  for (const [withheld, unreadable] of [
    [null, 0],
    [0, null],
    [-1, 0],
    [0, 1.5],
  ]) {
    const snap = { ...snapshot([repo()]), withheld, unreadable } as Snapshot;
    assert.equal(governedCount(snap), null, `withheld ${withheld}, unreadable ${unreadable}`);
  }
});

test('the two counts are never collapsed into one number', () => {
  // Zero withheld with a non-zero unreadable must stay visibly different from
  // the reverse: one says the fleet is fully opted in, the other says the run
  // could not tell. Summing them loses exactly that.
  const couldNotTell = snapshot([repo()], 0, 4);
  const deliberate = snapshot([repo()], 4, 0);

  assert.notDeepEqual(
    [withheldCount(couldNotTell), unreadableCount(couldNotTell)],
    [withheldCount(deliberate), unreadableCount(deliberate)],
  );
});

test('floor coverage counts only repos with every bit literally true', () => {
  const repos = [
    repo({ name: 'all-on' }),
    repo({
      name: 'one-off',
      securityFloor: { ...repo().securityFloor, pushProtection: false },
    }),
    repo({
      name: 'one-unread',
      securityFloor: { ...repo().securityFloor, codeqlSetup: null },
    }),
  ];

  assert.deepEqual(floorCoverage(repos), { complete: 1, unknown: 1, total: 3 });
});

test('codeqlSetup enum values map correctly to met/unmet/unknown', () => {
  const advanced = repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: 'advanced' } });
  const defaultSetup = repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: 'default' } });
  const none = repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: 'none' } });
  const unknown = repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: null } });

  assert.deepEqual(floorCoverage([advanced]), { complete: 1, unknown: 0, total: 1 });
  assert.deepEqual(floorCoverage([defaultSetup]), { complete: 1, unknown: 0, total: 1 });
  assert.deepEqual(floorCoverage([none]), { complete: 0, unknown: 0, total: 1 });
  assert.deepEqual(floorCoverage([unknown]), { complete: 0, unknown: 1, total: 1 });
});

test('an unread floor bit can never count as met', () => {
  // "Could not read the setting" is not "the setting is on". A repo whose
  // other five bits are all true still fails complete on the sixth null —
  // and shows up in `unknown` so the tile can say the read was partial.
  const partial = repo({
    securityFloor: { ...repo().securityFloor, defaultBranchRuleset: null },
  });

  const coverage = floorCoverage([partial]);

  assert.equal(coverage.complete, 0);
  assert.equal(coverage.unknown, 1);
  assert.notEqual(toneForFloorCoverage(coverage), 'ok');
});

test('the floor tile is never green while any bit is unknown', () => {
  // Same rule as toneForOpenSecurity: green claims "every published repo
  // meets the whole floor", which a partial read cannot make — even when
  // every repo that could be read is complete.
  const unknownAmongComplete = [
    repo({ name: 'complete' }),
    repo({
      name: 'unreadable',
      securityFloor: { ...repo().securityFloor, secretScanning: null },
    }),
  ];
  assert.equal(toneForFloorCoverage(floorCoverage(unknownAmongComplete)), 'warn');

  const allComplete = [repo({ name: 'a' }), repo({ name: 'b' })];
  assert.equal(toneForFloorCoverage(floorCoverage(allComplete)), 'ok');

  const knownGap = [
    repo({ name: 'complete' }),
    repo({
      name: 'incomplete',
      securityFloor: { ...repo().securityFloor, dependabotAlerts: false },
    }),
  ];
  assert.equal(toneForFloorCoverage(floorCoverage(knownGap)), 'warn');
});

test('an empty fleet renders the floor tile muted, not green', () => {
  const coverage = floorCoverage([]);

  assert.deepEqual(coverage, { complete: 0, unknown: 0, total: 0 });
  assert.equal(toneForFloorCoverage(coverage), 'muted');
});
