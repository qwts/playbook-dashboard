import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deflateRawSync } from 'node:zlib';
import { validateSnapshot } from './snapshot-schema.mjs';
import {
  MAX_QUALIFICATION_RUNS,
  QUALIFICATIONS_SOURCE,
  collectQualifications,
  parseSelfTest,
  qualIdent,
  qualSha,
  qualText,
  routeFromTitle,
  unzip,
} from './collect-qualifications.mjs';

// --- zip fixtures ---------------------------------------------------------
// Handcrafted rather than produced by a library: the parser under test reads
// exactly the subset `actions/upload-artifact` emits, and building the bytes
// here keeps the test independent of any zip writer's opinions.

function zipOf(entries, { method = 8 } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const nameBuffer = Buffer.from(name, 'utf8');
    const data = Buffer.from(content, 'utf8');
    const stored = method === 0 ? data : deflateRawSync(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(stored.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    locals.push(local, nameBuffer, stored);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(stored.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuffer);
    offset += 30 + nameBuffer.length + stored.length;
  }
  const centralBuffer = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuffer.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuffer, eocd]);
}

const SELF_TEST = {
  promptVersion: 'context-footprint-v3',
  fixtureSuite: 'sha256:b2f308ffac838574',
  requiredLevel: 'field',
  achievedLevel: 'field',
  qualified: true,
  levels: [
    { id: 'foundation', status: 'passed' },
    { id: 'field', status: 'passed' },
  ],
  fixtures: [{ name: 'new-composed', status: 'ok', note: 'judge prose that must never publish' }],
  check: 'context-footprint',
  provider: 'qwen',
  model: 'qwen3.7-max',
};

// --- string hygiene -------------------------------------------------------

test('qualification text is capped and refuses control characters', () => {
  assert.equal(qualText('context-footprint'), 'context-footprint');
  assert.equal(qualText(''), null);
  assert.equal(qualText(42), null);
  assert.equal(qualText('a'.repeat(81)), null, 'over-cap is refused, not truncated');
  assert.equal(qualText('a\u0000b'), null);
  assert.equal(qualText('a\nb'), null);
});

test('judge-controlled tokens take the identifier grammar, not the text cap', () => {
  assert.equal(qualIdent('context-footprint'), 'context-footprint');
  assert.equal(qualIdent('sha256:b2f308ffac838574'), 'sha256:b2f308ffac838574');
  assert.equal(qualIdent('qwen3.7-max'), 'qwen3.7-max');
  assert.equal(qualIdent('a judged sentence'), null, 'prose has whitespace; refused');
  assert.equal(qualIdent('src/checks/index.ts'), null, 'a file path has slashes; refused');
  assert.equal(qualIdent('-leading-dash'), null);
  assert.equal(qualIdent('a'.repeat(80)), 'a'.repeat(80));
  assert.equal(qualIdent('a'.repeat(81)), null);
  assert.equal(qualIdent(''), null);
  assert.equal(qualIdent(42), null);
});

test('a head sha is hex or nothing, and always abbreviated', () => {
  assert.equal(qualSha('60be121a7b27c94c56f85ac61c20ea61ab1d5d0f'), '60be121a7b27');
  assert.equal(qualSha('60be121'), '60be121');
  assert.equal(qualSha('not-a-sha'), null);
  assert.equal(qualSha('ABCDEF1'), null, 'GitHub shas are lowercase; anything else is not one');
  assert.equal(qualSha(null), null);
});

test('the run-title parse states the route or nothing, never a guess', () => {
  assert.deepEqual(routeFromTitle('calibrate qwen/qwen3.7-max (context-footprint)'), {
    provider: 'qwen',
    model: 'qwen3.7-max',
  });
  assert.deepEqual(routeFromTitle('Merge pull request #7'), { provider: null, model: null });
  assert.deepEqual(routeFromTitle(undefined), { provider: null, model: null });
});

// --- zip ------------------------------------------------------------------

test('unzip reads deflated and stored entries produced by upload-artifact', () => {
  const deflated = unzip(zipOf([['context-footprint.json', JSON.stringify(SELF_TEST)]]));
  assert.deepEqual(JSON.parse(deflated.get('context-footprint.json').toString()), SELF_TEST);

  const stored = unzip(zipOf([['a.json', '{"check":"x"}']], { method: 0 }));
  assert.equal(stored.get('a.json').toString(), '{"check":"x"}');
});

test('unzip refuses garbage, truncation, and over-bound payloads', () => {
  assert.equal(unzip(Buffer.from('not a zip')), null);
  assert.equal(unzip('a string'), null);
  const zip = zipOf([['a.json', '{}']]);
  assert.equal(unzip(zip.subarray(0, zip.length - 4)), null, 'a lost EOCD is not a zip');
  // A declared size past the bound is refused before inflation is attempted.
  const big = zipOf([['a.json', 'x'.repeat(700 * 1024)]]);
  assert.equal(unzip(big), null);
});

// --- payload parsing ------------------------------------------------------

test('a graded self-test payload maps to structured facts and sheds judge prose', () => {
  const result = parseSelfTest(JSON.stringify(SELF_TEST));
  assert.deepEqual(result, {
    check: 'context-footprint',
    provider: 'qwen',
    model: 'qwen3.7-max',
    promptVersion: 'context-footprint-v3',
    fixtureSuite: 'sha256:b2f308ffac838574',
    requiredLevel: 'field',
    achievedLevel: 'field',
    qualified: true,
    levels: [
      { id: 'foundation', status: 'passed' },
      { id: 'field', status: 'passed' },
    ],
    fixtures: [
      {
        name: 'new-composed',
        level: null,
        status: 'ok',
        expected: { assessment: null, verdict: null },
        actual: null,
      },
    ],
  });
  assert.ok(!JSON.stringify(result).includes('judge prose'), 'fixture notes must not survive');
});

test('fixture grading maps expectation, judgment, and criteria — and the note dies here', () => {
  const payload = {
    check: 'context-footprint',
    qualified: false,
    fixtures: [
      {
        name: 'new-composed',
        level: 'foundation',
        status: 'miss',
        expected: { assessment: 'new-compliant', verdict: 'pass' },
        actual: {
          assessment: 'new-violating',
          verdict: 'fail',
          criteria: ['duplicated-context', 'mixed-responsibility'],
          residualCriteria: [],
          note: 'long judge prose',
        },
      },
      { name: 'legacy-improved-residual', level: 'field', status: 'skipped', expected: { verdict: 'pass' } },
    ],
  };
  const { fixtures } = parseSelfTest(JSON.stringify(payload));
  assert.deepEqual(fixtures, [
    {
      name: 'new-composed',
      level: 'foundation',
      status: 'miss',
      expected: { assessment: 'new-compliant', verdict: 'pass' },
      actual: {
        assessment: 'new-violating',
        verdict: 'fail',
        criteria: ['duplicated-context', 'mixed-responsibility'],
      },
    },
    {
      name: 'legacy-improved-residual',
      level: 'field',
      status: 'skipped',
      expected: { assessment: null, verdict: 'pass' },
      actual: null,
    },
  ]);
  assert.ok(!JSON.stringify(fixtures).includes('judge prose'));
});

test('malformed fixture detail is refused whole; the verdict stands alone', () => {
  const base = { check: 'x', qualified: true };
  const cases = [
    [{ name: 'a', status: 'exploded' }],
    [{ status: 'ok' }],
    [{ name: 'a', status: 'ok', actual: { criteria: ['bad\u0000code'] } }],
    [{ name: 'a', status: 'ok', actual: { criteria: ['prose criteria code'] } }],
    [{ name: 'a', status: 'ok', actual: { criteria: ['a/path'] } }],
    [{ name: 'a', status: 'ok', actual: { criteria: 'not-an-array' } }],
    [{ name: 'a', status: 'ok', level: 'two words' }],
    [{ name: 'a', status: 'ok', expected: { verdict: 'maybe' } }],
    [{ name: 'a', status: 'ok', actual: { assessment: 'prose with spaces' } }],
    Array.from({ length: 25 }, (_, i) => ({ name: `f${i}`, status: 'ok' })),
    'not an array',
  ];
  for (const fixtures of cases) {
    const result = parseSelfTest(JSON.stringify({ ...base, fixtures }));
    assert.equal(result.fixtures, null, `${JSON.stringify(fixtures).slice(0, 60)} should refuse detail`);
    assert.equal(result.qualified, true, 'the verdict survives the refused detail');
  }
  assert.equal(parseSelfTest(JSON.stringify(base)).fixtures, null, 'absent detail is null, not []');
});

test('an ungraded payload is pass/fail with null levels of requirement', () => {
  const result = parseSelfTest(JSON.stringify({ check: 'legacy', passed: true }));
  assert.equal(result.qualified, true);
  assert.equal(result.requiredLevel, null);
  assert.deepEqual(result.levels, []);
});

test('an unrecognizable payload is null, not a half-row', () => {
  assert.equal(parseSelfTest('not json'), null);
  assert.equal(parseSelfTest('[]'), null);
  assert.equal(parseSelfTest(JSON.stringify({ qualified: true })), null, 'no check name, no row');
  assert.equal(
    parseSelfTest(JSON.stringify({ ...SELF_TEST, levels: [{ id: 'x', status: 'exploded' }] })),
    null,
    'a status outside the vocabulary poisons the row rather than shipping as prose',
  );
});

test('a result-level token outside the grammar refuses the whole row', () => {
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x', qualified: true, promptVersion: 'v1 with spaces' })), null);
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x', qualified: true, model: 'a/model' })), null);
  assert.notEqual(parseSelfTest(JSON.stringify({ check: 'x', qualified: true })), null, 'absent tokens stay honest nulls');
});

test('a payload without a boolean verdict is refused, never defaulted to failed', () => {
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x' })), null, 'no verdict field at all');
  assert.equal(
    parseSelfTest(JSON.stringify({ check: 'x', qualified: 'true' })),
    null,
    'a string verdict is not a verdict',
  );
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x', passed: 1 })), null);
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x', qualified: null })), null);
  assert.equal(parseSelfTest(JSON.stringify({ check: 'x', passed: false })).qualified, false);
});

// --- collection -----------------------------------------------------------

function fakeRun(id, overrides = {}) {
  return {
    id,
    display_title: 'calibrate qwen/qwen3.7-max (context-footprint)',
    html_url: `https://github.com/qwts/agentic-code-analysis/actions/runs/${id}`,
    created_at: '2026-08-18T14:50:00Z',
    head_sha: '60be121a7b27c94c56f85ac61c20ea61ab1d5d0f',
    conclusion: 'success',
    ...overrides,
  };
}

function fakeApi({ runs, artifacts, zip, zipOk = true }) {
  const ghJson = async (pathname) => {
    if (pathname.includes('/workflows/')) {
      if (runs instanceof Error) throw runs;
      return { workflow_runs: runs };
    }
    if (pathname.includes('/artifacts?')) {
      if (artifacts instanceof Error) throw artifacts;
      return { artifacts };
    }
    throw new Error(`unexpected path ${pathname}`);
  };
  const gh = async () =>
    zipOk
      ? new Response(zip, { status: 200 })
      : new Response(null, { status: 403 });
  return { ghJson, gh };
}

function envelope(qualifications) {
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
    repos: [],
    qualifications,
  };
}

test('a readable run round-trips: collected, routed, and valid under the contract', async () => {
  const zip = zipOf([['context-footprint.json', JSON.stringify(SELF_TEST)]]);
  const api = fakeApi({
    runs: [fakeRun(1001)],
    artifacts: [{ id: 5, name: 'qualification-context-footprint', expired: false }],
    zip,
  });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.source.repo, QUALIFICATIONS_SOURCE.repo);
  assert.equal(qualifications.runs.length, 1);
  const [run] = qualifications.runs;
  assert.equal(run.artifacts, 'read');
  assert.equal(run.provider, 'qwen');
  assert.equal(run.model, 'qwen3.7-max');
  assert.equal(run.headSha, '60be121a7b27');
  assert.equal(run.results[0].check, 'context-footprint');
  assert.equal(run.results[0].qualified, true);
  assert.ok(!('provider' in run.results[0]), 'route lives on the run, not duplicated per result');
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('an expired run keeps its metadata and says expired, never a verdict', async () => {
  const api = fakeApi({
    runs: [fakeRun(1002)],
    artifacts: [{ id: 6, name: 'qualification-context-footprint', expired: true }],
    zip: null,
  });
  const qualifications = await collectQualifications(api);
  const [run] = qualifications.runs;
  assert.equal(run.artifacts, 'expired');
  assert.equal(run.results, null);
  assert.equal(run.provider, 'qwen', 'route survives via the run title');
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('a refused artifact download is unreadable, not expired and not empty-healthy', async () => {
  const api = fakeApi({
    runs: [fakeRun(1003)],
    artifacts: [{ id: 7, name: 'qualification-context-footprint', expired: false }],
    zip: null,
    zipOk: false,
  });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.runs[0].artifacts, 'unreadable');
  assert.equal(qualifications.runs[0].results, null);
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('a run listing failure fails the whole section closed to null', async () => {
  const api = fakeApi({ runs: new Error('qualification run listing failed → 403') });
  assert.equal(await collectQualifications(api), null);
});

test('an artifact listing failure downgrades one run, not the section', async () => {
  const api = fakeApi({ runs: [fakeRun(1004)], artifacts: new Error('listing failed → 500') });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.runs.length, 1);
  assert.equal(qualifications.runs[0].artifacts, 'unreadable');
});

test('the run window is bounded even when the API over-answers', async () => {
  const zip = zipOf([['context-footprint.json', JSON.stringify(SELF_TEST)]]);
  const runs = Array.from({ length: MAX_QUALIFICATION_RUNS + 10 }, (_, i) => fakeRun(2000 + i));
  const api = fakeApi({
    runs,
    artifacts: [{ id: 8, name: 'qualification-context-footprint', expired: false }],
    zip,
  });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.runs.length, MAX_QUALIFICATION_RUNS);
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('an exam past the result bound is unreadable, never a published prefix', async () => {
  const { MAX_RESULTS_PER_RUN } = await import('./collect-qualifications.mjs');
  const artifacts = Array.from({ length: MAX_RESULTS_PER_RUN + 1 }, (_, i) => ({
    id: 100 + i,
    name: `qualification-check-${i}`,
    expired: false,
  }));
  const zip = zipOf([['check.json', JSON.stringify(SELF_TEST)]]);
  const api = fakeApi({ runs: [fakeRun(1005)], artifacts, zip });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.runs[0].artifacts, 'unreadable');
  assert.equal(qualifications.runs[0].results, null);
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('one artifact fanning out past the result bound is refused the same way', async () => {
  const { MAX_RESULTS_PER_RUN } = await import('./collect-qualifications.mjs');
  const entries = Array.from({ length: MAX_RESULTS_PER_RUN + 1 }, (_, i) => [
    `check-${i}.json`,
    JSON.stringify({ ...SELF_TEST, check: `check-${i}` }),
  ]);
  const api = fakeApi({
    runs: [fakeRun(1006)],
    artifacts: [{ id: 9, name: 'qualification-all', expired: false }],
    zip: zipOf(entries),
  });
  const qualifications = await collectQualifications(api);
  assert.equal(qualifications.runs[0].artifacts, 'unreadable');
  assert.equal(qualifications.runs[0].results, null);
});

// --- the contract refuses what the collector can never emit ---------------

test('results beside a non-read artifact state are refused whole', () => {
  const qualifications = {
    source: { ...QUALIFICATIONS_SOURCE },
    runs: [
      {
        runId: 1,
        url: null,
        createdAt: '2026-08-18T14:50:00Z',
        headSha: null,
        conclusion: 'success',
        provider: 'qwen',
        model: 'qwen3.7-max',
        artifacts: 'expired',
        results: [],
      },
    ],
  };
  const violations = validateSnapshot(envelope(qualifications));
  assert.ok(violations.some((v) => v.includes("results must be null unless artifacts is 'read'")));
});

test("a 'read' state disclaiming results is refused too", () => {
  const qualifications = {
    source: { ...QUALIFICATIONS_SOURCE },
    runs: [
      {
        runId: 1,
        url: null,
        createdAt: '2026-08-18T14:50:00Z',
        headSha: null,
        conclusion: null,
        provider: null,
        model: null,
        artifacts: 'read',
        results: null,
      },
    ],
  };
  const violations = validateSnapshot(envelope(qualifications));
  assert.ok(violations.some((v) => v.includes('must be a non-empty array')));
});

test('a fixture entry smuggling a note key is refused by the contract', () => {
  const qualifications = {
    source: { ...QUALIFICATIONS_SOURCE },
    runs: [
      {
        runId: 1,
        url: null,
        createdAt: '2026-08-18T14:50:00Z',
        headSha: null,
        conclusion: null,
        provider: 'qwen',
        model: 'qwen3.7-max',
        artifacts: 'read',
        results: [
          {
            check: 'context-footprint',
            promptVersion: null,
            fixtureSuite: null,
            requiredLevel: null,
            achievedLevel: null,
            qualified: true,
            levels: [],
            fixtures: [
              {
                name: 'new-composed',
                level: null,
                status: 'ok',
                expected: { assessment: null, verdict: null },
                actual: { assessment: null, verdict: null, criteria: [], note: 'prose' },
              },
            ],
          },
        ],
      },
    ],
  };
  const violations = validateSnapshot(envelope(qualifications));
  assert.ok(violations.some((v) => v.includes('note is not in the published schema')));
  // The same shape without the note is exactly what the collector emits.
  delete qualifications.runs[0].results[0].fixtures[0].actual.note;
  assert.deepEqual(validateSnapshot(envelope(qualifications)), []);
});

test('an unknown key below qualifications is a field nobody decided to publish', () => {
  const qualifications = {
    source: { ...QUALIFICATIONS_SOURCE },
    runs: [],
    note: 'smuggled',
  };
  const violations = validateSnapshot(envelope(qualifications));
  assert.ok(violations.some((v) => v.includes('note is not in the published schema')));
});

test('a snapshot missing the qualifications key predates the contract and says so', () => {
  const snapshot = envelope(null);
  delete snapshot.qualifications;
  const violations = validateSnapshot(snapshot);
  assert.ok(violations.some((v) => v.includes('snapshot.qualifications is missing')));
});
