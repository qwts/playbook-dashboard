import assert from 'node:assert/strict';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { CAPS, STALE_MS, validateSnapshot } from './snapshot-schema.mjs';
import { main as validateMain } from './validate-snapshot.mjs';

const FIXTURE = JSON.parse(
  readFileSync(new URL('../public/data/snapshot.json', import.meta.url), 'utf8'),
);

/** A structurally perfect snapshot, generated now. Every test starts here. */
function valid(overrides = {}) {
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    source: {
      account: 'qwts',
      manifestRepo: 'qwts/playbook-engineering',
      manifestPath: 'governance/repos.json',
    },
    withheld: 0,
    unreadable: 0,
    collection: { denied: 0, rateLimited: 0, failed: 0 },
    repos: [repo()],
    ...overrides,
  };
}

function repo(overrides = {}) {
  return {
    name: 'example',
    visibility: 'public',
    status: 'active',
    sharedCi: false,
    codexSyncEnabled: null,
    delta: '',
    htmlUrl: 'https://github.com/qwts/example',
    securityFloor: {
      secretScanning: true,
      pushProtection: true,
      dependabotAlerts: true,
      privateVulnerabilityReporting: true,
      codeqlSetup: 'none',
      codeqlLastAnalysisAt: null,
      defaultBranchRuleset: true,
    },
    security: { dependabotOpen: 0, codeScanningOpen: 1, secretScanningOpen: 0 },
    ci: {
      workflowName: 'CI',
      conclusion: 'success',
      status: 'completed',
      updatedAt: new Date().toISOString(),
      htmlUrl: 'https://github.com/qwts/example/actions',
    },
    actionsPosture: posture(),
    ...overrides,
  };
}

function posture(overrides = {}) {
  return {
    workflowCount: 2,
    pinning: { status: 'pass', reason: null },
    permissions: { status: 'pass', reason: null },
    triggers: { status: 'pass', reason: null },
    ...overrides,
  };
}

test('a snapshot that upholds the contract passes', () => {
  assert.deepEqual(validateSnapshot(valid()), []);
});

// The assertion the whole file exists for. Checking that known fields are
// well-formed catches malformed data; only a closed key set catches *new* data,
// and new data is how a leak arrives — a field added to a collector return value
// used to publish itself on the next hourly cron with nobody in the loop.
test('a field nobody decided to publish is rejected, at every level', () => {
  const cases = [
    [valid({ alertTitles: ['RCE in parser'] }), 'snapshot.alertTitles'],
    [valid({ source: { ...valid().source, token: 'ghp_x' } }), 'snapshot.source.token'],
    [valid({ repos: [repo({ note: 'internal only' })] }), 'snapshot.repos[0].note'],
    [
      valid({ repos: [repo({ security: { ...repo().security, cves: ['CVE-2031-1'] } })] }),
      'snapshot.repos[0].security.cves',
    ],
    [
      valid({ repos: [repo({ ci: { ...repo().ci, logUrl: 'https://github.com/x' } })] }),
      'snapshot.repos[0].ci.logUrl',
    ],
    [
      valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, extra: true } })] }),
      'snapshot.repos[0].securityFloor.extra',
    ],
    [valid({ collection: { denied: 0, rateLimited: 0, failed: 0, paths: [] } }), 'snapshot.collection.paths'],
  ];

  for (const [snapshot, expected] of cases) {
    const violations = validateSnapshot(snapshot);
    assert.ok(
      violations.some((v) => v.startsWith(`${expected} is not in the published schema`)),
      `${expected} should have been rejected, got: ${JSON.stringify(violations)}`,
    );
  }
});

// `in` walks the prototype chain, so before Object.hasOwn a field named after
// an Object.prototype member — an ordinary own key once JSON.parse has run —
// matched the inherited property, passed the closed-key-set check, and shipped
// with its value never validated. Prototype-named keys are exactly the ones an
// attacker reaches for.
test('a key named after an Object.prototype member is rejected, not inherited past', () => {
  // Injected via JSON, as the real artifact would carry it: an object literal
  // with a `__proto__` key sets the prototype instead of creating an own key.
  const inject = (json, key) => `${json.slice(0, -1)},${JSON.stringify(key)}:true}`;

  for (const key of ['toString', 'valueOf', 'constructor', '__proto__', 'hasOwnProperty']) {
    const top = JSON.parse(inject(JSON.stringify(valid()), key));
    assert.ok(
      validateSnapshot(top).some((v) => v.startsWith(`snapshot.${key} is not in the published schema`)),
      `top-level ${key} should have been rejected`,
    );

    const nested = valid();
    nested.repos = [JSON.parse(inject(JSON.stringify(repo()), key))];
    assert.ok(
      validateSnapshot(nested).some((v) =>
        v.startsWith(`snapshot.repos[0].${key} is not in the published schema`),
      ),
      `repo-level ${key} should have been rejected`,
    );
  }
});

test('a missing field is a violation too, not a silently absent one', () => {
  const { withheld, ...withoutWithheld } = valid();
  assert.ok(validateSnapshot(withoutWithheld).includes('snapshot.withheld is missing'));

  const { security, ...bare } = repo();
  const violations = validateSnapshot(valid({ repos: [bare] }));
  assert.ok(violations.includes('snapshot.repos[0].security is missing'));
});

test('the schema version has to be the one this code understands', () => {
  for (const version of [0, 2, '1', null, undefined, 1.0000001]) {
    const violations = validateSnapshot(valid({ schemaVersion: version }));
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.schemaVersion')),
      `schemaVersion ${JSON.stringify(version)} should be rejected`,
    );
  }
});

test('a count is null or a non-negative integer, and nothing else', () => {
  for (const bad of ['3', -1, 1.5, Number.NaN, Infinity, {}, [], true, undefined]) {
    const violations = validateSnapshot(
      valid({ repos: [repo({ security: { ...repo().security, dependabotOpen: bad } })] }),
    );
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.repos[0].security.dependabotOpen')),
      `${JSON.stringify(bad)} should not be publishable as a count`,
    );
  }

  // null is the whole point of the type: unreadable, not zero.
  assert.deepEqual(
    validateSnapshot(valid({ repos: [repo({ security: { ...repo().security, dependabotOpen: null } })] })),
    [],
  );
});

test('a URL is checked by the collector, not by a second copy of the rule', () => {
  const hostile = [
    'javascript:alert(1)',
    'http://github.com/qwts/x',
    'https://github.com.evil.example/qwts/x',
    'https://user:pass@github.com/qwts/x',
    'https://raw.githubusercontent.com/qwts/x',
  ];

  for (const value of hostile) {
    const violations = validateSnapshot(valid({ repos: [repo({ htmlUrl: value })] }));
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.repos[0].htmlUrl')),
      `${value} should not survive validation`,
    );
  }
});

test('free text is capped and control characters are refused', () => {
  const overLong = validateSnapshot(valid({ repos: [repo({ delta: 'x'.repeat(CAPS.delta + 1) })] }));
  assert.ok(overLong.some((v) => v.includes('exceeds the')));

  assert.deepEqual(validateSnapshot(valid({ repos: [repo({ delta: 'x'.repeat(CAPS.delta) })] })), []);

  for (const char of ['\u0000', '\u001b', '\u007f', '\n', '\r']) {
    const violations = validateSnapshot(valid({ repos: [repo({ delta: `ok${char}bad` })] }));
    assert.ok(
      violations.some((v) => v.includes('control characters')),
      `${JSON.stringify(char)} should not reach the page`,
    );
  }
});

test('only a repo observed public may be in the artifact at all', () => {
  for (const visibility of ['private', 'internal', 'PUBLIC', 'public ', '', null]) {
    const violations = validateSnapshot(valid({ repos: [repo({ visibility })] }));
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.repos[0].visibility')),
      `visibility ${JSON.stringify(visibility)} must not be publishable`,
    );
  }
});

test('codeqlSetup is a closed enum or null', () => {
  const validValues = ['default', 'advanced', 'none', null];
  for (const value of validValues) {
    assert.deepEqual(
      validateSnapshot(valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: value } })] })),
      [],
      `${JSON.stringify(value)} should be valid`,
    );
  }

  const invalidValues = ['configured', 'CodeQL exists', 'true', 'false', 1, {}, []];
  for (const value of invalidValues) {
    const violations = validateSnapshot(
      valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, codeqlSetup: value } })] }),
    );
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.repos[0].securityFloor.codeqlSetup')),
      `${JSON.stringify(value)} should be rejected`,
    );
  }
});

test('codeqlLastAnalysisAt is a timestamp or null', () => {
  const validTimestamp = new Date().toISOString();
  assert.deepEqual(
    validateSnapshot(
      valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, codeqlLastAnalysisAt: validTimestamp } })] }),
    ),
    [],
  );

  assert.deepEqual(
    validateSnapshot(valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, codeqlLastAnalysisAt: null } })] })),
    [],
  );

  const invalidValues = ['not a timestamp', 123, {}, []];
  for (const value of invalidValues) {
    const violations = validateSnapshot(
      valid({ repos: [repo({ securityFloor: { ...repo().securityFloor, codeqlLastAnalysisAt: value } })] }),
    );
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.repos[0].securityFloor.codeqlLastAnalysisAt')),
      `${JSON.stringify(value)} should be rejected`,
    );
  }
});

test('a timestamp in the future is refused however fresh it looks', () => {
  const now = Date.now();
  const violations = validateSnapshot(
    valid({ generatedAt: new Date(now + 60 * 60 * 1000).toISOString() }),
    { now },
  );
  // A future timestamp makes a stale artifact read as current for as long as
  // the skew lasts — the one direction that suppresses the staleness warning.
  assert.ok(violations.includes('snapshot.generatedAt is in the future'));
  assert.equal(
    violations.filter((v) => v.startsWith('snapshot.generatedAt')).length,
    1,
    'one violation per field — the shape walk and the freshness block must not both report it',
  );
});

// DESIGN.md says timestamps, plural. `generatedAt` was the only one checked;
// a future `ci.updatedAt` passed and read as maximally current CI — the same
// suppression, one field down.
test('every timestamp field refuses the future, not just generatedAt', () => {
  const now = Date.now();
  const future = new Date(now + 60 * 60 * 1000).toISOString();
  const violations = validateSnapshot(
    valid({ repos: [repo({ ci: { ...repo().ci, updatedAt: future } })] }),
    { now },
  );
  assert.ok(violations.includes('snapshot.repos[0].ci.updatedAt is in the future'));

  // Inside the skew allowance is not "the future" — clocks drift.
  const nearby = new Date(now + 30_000).toISOString();
  assert.deepEqual(
    validateSnapshot(valid({ repos: [repo({ ci: { ...repo().ci, updatedAt: nearby } })] }), { now }),
    [],
  );
});

// The browser runs this same validation on the reader's clock, and end-user
// machines drift by minutes. A caller that far from the runner widens the
// allowance explicitly; the default stays tight for CI-side validation.
test('clock skew is a caller decision, and widening it loosens nothing else', () => {
  const now = Date.now();
  const twoMinutesAhead = new Date(now + 2 * 60_000).toISOString();
  const snapshot = valid({ generatedAt: twoMinutesAhead });

  assert.ok(validateSnapshot(snapshot, { now }).includes('snapshot.generatedAt is in the future'));
  assert.deepEqual(validateSnapshot(snapshot, { now, clockSkewMs: 5 * 60_000 }), []);

  // The wider skew rescues the honest timestamp, not the leaked field.
  const withLeak = valid({ generatedAt: twoMinutesAhead, alertTitles: ['RCE in parser'] });
  assert.deepEqual(validateSnapshot(withLeak, { now, clockSkewMs: 5 * 60_000 }), [
    'snapshot.alertTitles is not in the published schema',
  ]);
});

// The browser only needs to know *whether* the artifact conforms, and a
// hostile payload — say, thousands of unexpected keys — must not bill the
// reader's tab a materialized string per defect.
test('a violation cap bounds the work a hostile artifact can cause', () => {
  const junk = Object.fromEntries(Array.from({ length: 500 }, (_, i) => [`leak${i}`, i]));
  const capped = validateSnapshot(valid({ ...junk }), { maxViolations: 5 });
  assert.equal(capped.length, 5);

  // The default stays uncapped: a CI validator describing a trusted
  // collector's output reports everything, once.
  const all = validateSnapshot(valid({ ...junk }));
  assert.equal(all.length, 500);
});

test('an unparseable timestamp never passes', () => {
  for (const value of ['not a date', '', 42, null, undefined]) {
    const violations = validateSnapshot(valid({ generatedAt: value }));
    assert.ok(
      violations.some((v) => v.startsWith('snapshot.generatedAt')),
      `generatedAt ${JSON.stringify(value)} should be rejected`,
    );
  }
});

// Staleness is a property of a run, not of the contract. The committed fixture
// is deliberately old — being the fallback is its job — so only a run that
// actually collected may demand freshness.
test('staleness is only enforced when a run claims to have just collected', () => {
  const now = Date.now();
  const old = valid({ generatedAt: new Date(now - STALE_MS - 1000).toISOString() });

  assert.deepEqual(validateSnapshot(old, { now }), [], 'structure alone must still pass');
  assert.ok(
    validateSnapshot(old, { now, requireFresh: true }).includes(
      'snapshot.generatedAt is older than the staleness threshold',
    ),
  );
});

test('two rows for the same repo are refused', () => {
  const violations = validateSnapshot(valid({ repos: [repo(), repo()] }));
  assert.ok(violations.includes('snapshot.repos contains duplicate names'));
});

test('every violation is reported, not just the first', () => {
  const violations = validateSnapshot(
    valid({ schemaVersion: 9, leaked: true, repos: [repo({ visibility: 'private', extra: 1 })] }),
  );
  assert.ok(violations.length >= 4, `expected several violations, got ${violations.length}`);
});

// A violation message names the field and the reason. It must never quote the
// value: the thing that failed validation is exactly the thing not to put into
// a log that is public on this repository.
test('no violation message quotes the offending value', () => {
  const secret = 'ghp_livetokenmarker9271';
  const violations = validateSnapshot(
    valid({
      repos: [repo({ delta: `${secret}${'x'.repeat(CAPS.delta)}`, htmlUrl: `https://evil.example/${secret}` })],
      source: { account: secret.repeat(4), manifestRepo: 'a', manifestPath: 'b' },
    }),
  );

  assert.ok(violations.length >= 3, 'expected the violations that carry values');
  for (const violation of violations) {
    assert.doesNotMatch(violation, /livetokenmarker9271/u, `a value reached a message: ${violation}`);
  }
});

// The same rule one layer down: a snapshot that is not even JSON. V8's
// SyntaxError message embeds a snippet of the input, so printing
// `error.message` republishes the bytes the gate exists to keep out of a
// public log.
test('a parse failure never echoes the file contents either', () => {
  const secret = 'ghp_livetokenmarker9271';
  const file = join(tmpdir(), `bad-snapshot-${process.pid}.json`);
  // Invalid JSON, with the marker at the point the parser will complain about.
  writeFileSync(file, `{"generatedAt": ${secret}}`);

  const written = [];
  const realWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => {
    written.push(String(chunk));
    return true;
  };
  try {
    assert.equal(validateMain([file]), 1, 'an unparseable snapshot must refuse to publish');
  } finally {
    process.stderr.write = realWrite;
    rmSync(file, { force: true });
  }

  const output = written.join('');
  assert.doesNotMatch(output, /livetokenmarker9271/u, `file contents reached stderr: ${output}`);
  assert.match(output, /could not be read as JSON/u, 'the fixed complaint must still explain itself');
});

test('the committed fallback fixture upholds the contract it will be published under', () => {
  // It is deployed verbatim whenever collection fails, so it is a published
  // artifact in its own right and gets no exemption from the structural rules.
  assert.deepEqual(validateSnapshot(FIXTURE), []);
});

test('a non-object, or a repos field that is not an array, fails closed', () => {
  for (const bad of [null, undefined, 42, 'snapshot', []]) {
    assert.ok(validateSnapshot(bad).length > 0, `${JSON.stringify(bad)} is not a snapshot`);
  }
  assert.ok(validateSnapshot(valid({ repos: {} })).includes('snapshot.repos must be an array'));
});

// --- actionsPosture: the pillar contract -----------------------------------

test('the pillar subtree is a closed key set at every level', () => {
  const cases = [
    [repo({ actionsPosture: posture({ extra: true }) }), 'snapshot.repos[0].actionsPosture.extra'],
    [
      repo({ actionsPosture: posture({ pinning: { status: 'pass', reason: null, file: 'ci.yml' } }) }),
      'snapshot.repos[0].actionsPosture.pinning',
    ],
  ];
  for (const [row, expected] of cases) {
    const violations = validateSnapshot(valid({ repos: [row] }));
    assert.ok(
      violations.some((v) => v.startsWith(expected)),
      `${expected} should have been rejected, got: ${JSON.stringify(violations)}`,
    );
  }
});

test('a repo without actionsPosture is refused — the key is required, not optional', () => {
  const row = repo();
  delete row.actionsPosture;
  const violations = validateSnapshot(valid({ repos: [row] }));
  assert.ok(violations.some((v) => v.includes('actionsPosture')));
});

test('pillar status is a closed enum or null', () => {
  for (const good of ['pass', 'warn', 'fail', null]) {
    const reason =
      good === 'warn' ? 'unpinned-first-party' : good === 'fail' ? 'unpinned-third-party' : null;
    const row = repo({ actionsPosture: posture({ pinning: { status: good, reason } }) });
    assert.deepEqual(validateSnapshot(valid({ repos: [row] })), [], `${good} should pass`);
  }
  for (const bad of ['ok', 'PASS', true, 0, {}]) {
    const row = repo({ actionsPosture: posture({ pinning: { status: bad, reason: null } }) });
    assert.notDeepEqual(validateSnapshot(valid({ repos: [row] })), [], `${JSON.stringify(bad)} should fail`);
  }
});

test('a reasonless fail is unactionable and a reasoned pass smuggles data — both refused', () => {
  const reasonless = repo({ actionsPosture: posture({ triggers: { status: 'fail', reason: null } }) });
  assert.ok(
    validateSnapshot(valid({ repos: [reasonless] })).some((v) =>
      v.includes('reason must accompany'),
    ),
  );

  const smuggling = repo({
    actionsPosture: posture({ pinning: { status: 'pass', reason: 'unpinned-third-party' } }),
  });
  assert.ok(
    validateSnapshot(valid({ repos: [smuggling] })).some((v) => v.includes('reason must be null')),
  );
});

test('a reason outside the pillar vocabulary, or from another pillar, is refused', () => {
  const foreign = repo({
    // A real code — but pinning's, not triggers'. Vocabularies are per pillar.
    actionsPosture: posture({ triggers: { status: 'fail', reason: 'unpinned-third-party' } }),
  });
  assert.ok(
    validateSnapshot(valid({ repos: [foreign] })).some((v) => v.includes('not in the published vocabulary')),
  );

  const invented = repo({
    actionsPosture: posture({ pinning: { status: 'fail', reason: 'ci.yml line 14' } }),
  });
  assert.ok(
    validateSnapshot(valid({ repos: [invented] })).some((v) => v.includes('not in the published vocabulary')),
  );
});

test('a reason must match its bound severity — a warn wearing a fail code is refused', () => {
  const inflated = repo({
    actionsPosture: posture({ pinning: { status: 'warn', reason: 'unpinned-third-party' } }),
  });
  assert.ok(
    validateSnapshot(valid({ repos: [inflated] })).some((v) => v.includes('does not match its status severity')),
  );
});

test('none is repo-wide: it requires a zero count, and a zero count requires it everywhere', () => {
  const noneRow = repo({
    actionsPosture: {
      workflowCount: 0,
      pinning: { status: 'none', reason: null },
      permissions: { status: 'none', reason: null },
      triggers: { status: 'none', reason: null },
    },
  });
  assert.deepEqual(validateSnapshot(valid({ repos: [noneRow] })), []);

  const dressedAbsence = repo({ actionsPosture: posture({ pinning: { status: 'none', reason: null } }) });
  assert.ok(
    validateSnapshot(valid({ repos: [dressedAbsence] })).some((v) =>
      v.includes("status 'none' requires workflowCount 0"),
    ),
    'none beside a non-zero count dresses an unread pillar as owner-chosen absence',
  );

  const phantomFindings = repo({
    actionsPosture: posture({ workflowCount: 0 }),
  });
  assert.ok(
    validateSnapshot(valid({ repos: [phantomFindings] })).some((v) =>
      v.includes("must be 'none' when workflowCount is 0"),
    ),
    'a zero count beside an assessed status claims findings about files it says do not exist',
  );
});

test('the fully-unread posture — the degraded shape — validates', () => {
  const unread = repo({
    actionsPosture: {
      workflowCount: null,
      pinning: { status: null, reason: null },
      permissions: { status: null, reason: null },
      triggers: { status: null, reason: null },
    },
  });
  assert.deepEqual(validateSnapshot(valid({ repos: [unread] })), []);
});

test('an assessed verdict beside an unknown count is refused — nothing was enumerable', () => {
  // The collector can only emit all-null beside a null count; an artifact
  // claiming a pass (or any verdict) for files it could not list is trusted
  // in the flattering direction exactly once, here, and refused.
  for (const status of ['pass', 'warn', 'fail']) {
    const reason =
      status === 'warn' ? 'unpinned-first-party' : status === 'fail' ? 'unpinned-third-party' : null;
    const row = repo({
      actionsPosture: {
        workflowCount: null,
        pinning: { status, reason },
        permissions: { status: null, reason: null },
        triggers: { status: null, reason: null },
      },
    });
    assert.ok(
      validateSnapshot(valid({ repos: [row] })).some((v) =>
        v.includes('status must be null when workflowCount is null'),
      ),
      `${status} beside a null count should be refused`,
    );
  }
});
