import assert from 'node:assert/strict';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  ALLOWED_URL_ORIGIN,
  MAX_BACKOFF_MS,
  MAX_DELTA_LENGTH,
  MAX_WORKFLOW_NAME_LENGTH,
  sanitizeWorkflowName,
  fetchRepoForGate,
  isObservedPublic,
  isPublishable,
  parseCodexSync,
  sanitizeDelta,
  sanitizeGithubUrl,
  isRateLimited,
  retryDelayMs,
  countOpenAlerts,
  publicationTally,
  degradedReasons,
  reportDegradation,
  collectionHealth,
  resetCollectionHealth,
  resetRateLimitWindow,
  rateLimitWindowIsOpen,
  MAX_ATTEMPTS,
} from './collect.mjs';

const SOURCE = readFileSync(new URL('./collect.mjs', import.meta.url), 'utf8');

test('a github https URL is published, in normalized form', () => {
  assert.equal(
    sanitizeGithubUrl('https://github.com/qwts/example'),
    'https://github.com/qwts/example',
  );
  assert.equal(sanitizeGithubUrl('https://github.com'), 'https://github.com/');
  // The default port is the same origin, not a different one.
  assert.equal(sanitizeGithubUrl('https://github.com:443/qwts/x'), 'https://github.com/qwts/x');
});

test('a non-https scheme never reaches an href', () => {
  // React escapes text but does not sanitize href schemes, so `javascript:` in
  // an href is script execution on click.
  const schemes = [
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    '  javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'http://github.com/qwts/example',
    '//github.com/qwts/example',
  ];

  for (const value of schemes) {
    assert.equal(sanitizeGithubUrl(value), null, `${JSON.stringify(value)} must not be published`);
  }
});

test('a lookalike or unrelated origin is rejected', () => {
  const origins = [
    'https://github.com.evil.example/qwts/x',
    'https://evil.example/github.com/qwts/x',
    'https://raw.githubusercontent.com/qwts/x',
    'https://gist.github.com/qwts/x',
    'https://notgithub.com/qwts/x',
    'https://github.co/qwts/x',
    // A path that merely starts with the allowed origin is not that origin.
    'https://evil.example/?u=https://github.com/qwts/x',
  ];

  for (const value of origins) {
    assert.equal(sanitizeGithubUrl(value), null, `${value} must not be published`);
  }
});

test('embedded credentials are rejected even though the origin matches', () => {
  // new URL('https://user:pass@github.com/x').origin === 'https://github.com',
  // so an origin check alone lets this through while the href still carries the
  // credentials — a phishing shape rendered by our own page.
  assert.equal(sanitizeGithubUrl('https://user:pass@github.com/qwts/x'), null);
  assert.equal(sanitizeGithubUrl('https://user@github.com/qwts/x'), null);
});

test('a malformed or absent URL becomes null rather than throwing', () => {
  for (const value of ['', 'not a url', '/qwts/example', undefined, null, 42, {}, [], true]) {
    assert.equal(sanitizeGithubUrl(value), null, `${JSON.stringify(value)} should be null`);
  }
});

// Dropping Administration: Read makes /rulesets return 403. Routed through
// `ghJson` that threw, aborting the whole collection over one boolean — a
// permission reduction should cost the field it reads, not the run.
test('an Administration-gated posture field degrades rather than aborting', () => {
  const floor = SOURCE.slice(
    SOURCE.indexOf('async function fetchSecurityFloor'),
    SOURCE.indexOf('async function fetchCi'),
  );

  assert.doesNotMatch(
    floor,
    /ghJson\(`\/repos\/\$\{ACCOUNT\}\/\$\{repo\}\/rulesets`\)/u,
    'rulesets must not read through ghJson — it throws on 403 and kills the run',
  );

  for (const call of ['private-vulnerability-reporting', 'default-setup', 'rulesets']) {
    const idx = floor.indexOf(call);
    assert.ok(idx !== -1, `${call} should still be collected`);
    assert.match(
      floor.slice(idx, idx + 260),
      /\.ok\b/u,
      `${call} must branch on response.ok so a denied read is unknown, not fatal`,
    );
  }
});

test('the allowed origin is exactly one host', () => {
  assert.equal(ALLOWED_URL_ORIGIN, 'https://github.com');
});

// A narrow slice of the #9 snapshot-contract check, covering the invariant this
// change introduces. The committed fixture is the artifact deployed whenever
// collection fails, so it is published HTML input in its own right and has to
// satisfy the same rule as a fresh collection. #9 will fold this into the full
// schema check; `sanitizeGithubUrl` is exported so there is one definition to
// fold in rather than a second copy of the rule.
test('every URL in the committed snapshot upholds the origin invariant', () => {
  const snapshot = JSON.parse(
    readFileSync(new URL('../public/data/snapshot.json', import.meta.url), 'utf8'),
  );

  for (const repo of snapshot.repos) {
    for (const [field, value] of [
      ['htmlUrl', repo.htmlUrl],
      ['ci.htmlUrl', repo.ci.htmlUrl],
    ]) {
      if (value === null) continue;
      assert.equal(
        sanitizeGithubUrl(value),
        value,
        `${repo.name}.${field} is published as ${JSON.stringify(value)}, which fails origin validation`,
      );
    }
  }
});

test('codex sync reports what the manifest explicitly states', () => {
  assert.equal(parseCodexSync({ codexSync: { enabled: true } }), true);
  assert.equal(parseCodexSync({ codexSync: { enabled: false } }), false);
});

test('a silent manifest publishes unknown, not managed', () => {
  // The reassuring default is the bug: a repo nobody configured and a repo
  // deliberately enabled must not look identical on a public posture page.
  for (const entry of [{}, { codexSync: undefined }, undefined, null]) {
    assert.equal(parseCodexSync(entry), null, `${JSON.stringify(entry)} should be unknown`);
  }
});

test('a malformed codexSync is unknown rather than assumed managed', () => {
  const malformed = [
    { codexSync: null },
    { codexSync: 'enabled' },
    { codexSync: true },
    { codexSync: 42 },
    { codexSync: [] },
    { codexSync: [{ enabled: true }] },
    { codexSync: {} },
    { codexSync: { enabled: 'true' } },
    { codexSync: { enabled: 1 } },
    { codexSync: { enabled: null } },
  ];

  for (const entry of malformed) {
    assert.equal(parseCodexSync(entry), null, `${JSON.stringify(entry)} should be unknown`);
  }
});

test('publication requires the manifest to opt a repo in explicitly', () => {
  assert.equal(isPublishable({ name: 'yes', publish: true }), true);
});

test('anything short of publish: true withholds the repo', () => {
  const notOptedIn = [
    {},
    { publish: false },
    { publish: null },
    { publish: 'true' },
    { publish: 1 },
    { publish: {} },
    { publish: 'yes' },
    undefined,
    null,
  ];

  for (const entry of notOptedIn) {
    assert.equal(isPublishable(entry), false, `${JSON.stringify(entry)} must not publish`);
  }
});

test('a repo is emitted only when GitHub itself reports it public', () => {
  assert.equal(isObservedPublic({ private: false, visibility: 'public' }), true);
});

test('an unreadable, partial, or non-public repo response fails closed', () => {
  const withheld = [
    null,
    undefined,
    {},
    { private: true, visibility: 'private' },
    { private: false, visibility: 'internal' },
    // The two fields disagreeing means we do not know; do not guess.
    { private: true, visibility: 'public' },
    { private: false },
    { visibility: 'public' },
    // Manifest-shaped input must not satisfy the observed-state gate.
    { name: 'repo', visibility: 'public' },
  ];

  for (const detail of withheld) {
    assert.equal(isObservedPublic(detail), false, `${JSON.stringify(detail)} must be withheld`);
  }
});

test('a delta within the contract passes through unchanged', () => {
  const delta = 'Coverage floor 71% lines / 80% branches.';
  assert.equal(sanitizeDelta(delta, 'example'), delta);
});

test('an over-long delta is dropped whole, not truncated', () => {
  const long = 'a'.repeat(MAX_DELTA_LENGTH + 1);
  assert.equal(sanitizeDelta(long, 'example'), '');
  assert.equal(sanitizeDelta('a'.repeat(MAX_DELTA_LENGTH), 'example').length, MAX_DELTA_LENGTH);
});

test('control characters disqualify a delta', () => {
  assert.equal(sanitizeDelta('line one\nline two', 'example'), '');
  assert.equal(sanitizeDelta('tab\there', 'example'), '');
  assert.equal(sanitizeDelta('null\u0000byte', 'example'), '');
  assert.equal(sanitizeDelta('esc\u001b[31m', 'example'), '');
  assert.equal(sanitizeDelta('del\u007f', 'example'), '');
});

test('a missing or non-string delta becomes an empty string', () => {
  for (const value of [undefined, null, 42, {}, [], true]) {
    assert.equal(sanitizeDelta(value, 'example'), '');
  }
});

// The schema rejects an over-cap or control-charactered workflow name — but it
// rejects the whole snapshot, fleet-wide. Sanitizing at collect time keeps one
// repo's hostile workflow name from blocking every other repo's publication.
test('a workflow name is truncated to the published cap, not shipped raw', () => {
  const long = 'w'.repeat(MAX_WORKFLOW_NAME_LENGTH + 40);
  assert.equal(sanitizeWorkflowName(long), 'w'.repeat(MAX_WORKFLOW_NAME_LENGTH));
  assert.equal(sanitizeWorkflowName('CI'), 'CI');
});

test('control characters are stripped from a workflow name, not published', () => {
  assert.equal(sanitizeWorkflowName('release\nnotes'), 'releasenotes');
  assert.equal(sanitizeWorkflowName('esc\u001b[31mCI'), 'esc[31mCI');
  assert.equal(sanitizeWorkflowName('\u0000\u007f'), null, 'nothing left is null, not an empty string');
});

test('a missing or non-string workflow name is null, matching the schema', () => {
  for (const value of [undefined, null, 42, {}, [], true, '']) {
    assert.equal(sanitizeWorkflowName(value), null);
  }
});

test('fetchCi routes the run name through the sanitizer', () => {
  // Source assertion for the wiring; the behaviour is tested above. An
  // unsanitized `run.name` here is exactly the fleet-wide publication block.
  const ci = SOURCE.slice(SOURCE.indexOf('async function fetchCi'), SOURCE.indexOf('export function parseCodexSync'));
  assert.match(ci, /workflowName: sanitizeWorkflowName\(run\.name\)/u);
  assert.doesNotMatch(ci, /workflowName: run\.name/u);
});

// A source assertion rather than a behavioural one: main() does network I/O, so
// capturing its stderr costs more than the property is worth. This pins the
// exact regression — a manifest entry's name reaching a log line before the
// observed-visibility gate has decided whether that repo may be named at all.
//
// `sanitizeDelta` logging its `repoName` is deliberately not matched: it only
// runs for repos that have already passed both gates, so their names are public.
/** Runs `fn` with fetch and stderr captured, so nothing escapes to the console. */
async function withCapturedIo(respond, fn) {
  const written = [];
  const realWrite = process.stderr.write.bind(process.stderr);
  const realFetch = globalThis.fetch;
  const realToken = process.env.GITHUB_TOKEN;

  process.stderr.write = (chunk) => (written.push(String(chunk)), true);
  globalThis.fetch = respond;
  process.env.GITHUB_TOKEN = 'test-token-not-a-real-credential';
  try {
    return { result: await fn(), stderr: written.join('') };
  } finally {
    process.stderr.write = realWrite;
    globalThis.fetch = realFetch;
    if (realToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = realToken;
  }
}

// The pre-gate lookup is the one call made before we know whether the repo may
// be named. `ghJson` would throw with the path and 200 bytes of GitHub's body,
// and main().catch() prints that to a public Actions log.
test('a pre-gate lookup failure never names the repo, its path, or the response body', async () => {
  for (const status of [403, 500, 502]) {
    const { result, stderr } = await withCapturedIo(
      async () =>
        new Response(JSON.stringify({ message: 'Must have admin rights to secret-repo' }), {
          status,
        }),
      () => fetchRepoForGate('secret-repo', []),
    );

    assert.equal(result, null, `HTTP ${status} must withhold rather than throw`);
    assert.doesNotMatch(stderr, /secret-repo/u, `HTTP ${status} leaked the repo name`);
    assert.doesNotMatch(stderr, /admin rights/u, `HTTP ${status} leaked the response body`);
  }
});

test('a pre-gate network failure withholds instead of propagating', async () => {
  const { result, stderr } = await withCapturedIo(
    async () => {
      throw new Error('getaddrinfo ENOTFOUND api.github.com while fetching secret-repo');
    },
    () => fetchRepoForGate('secret-repo', []),
  );

  assert.equal(result, null);
  assert.doesNotMatch(stderr, /secret-repo/u);
});

test('pre-gate failures are recorded as bare statuses, never as identities', async () => {
  const failures = [];
  await withCapturedIo(
    async () => new Response('{}', { status: 403 }),
    () => fetchRepoForGate('secret-repo', failures),
  );
  await withCapturedIo(
    async () => {
      throw new Error('offline');
    },
    () => fetchRepoForGate('another-secret', failures),
  );

  // A transport failure surfaces as a synthetic 503 rather than a throw, so no
  // call site has to catch to avoid aborting the run. Either way it is a bare
  // status: no repo name, no path.
  assert.deepEqual(failures, ['403', '503']);
});

test('no log line interpolates a manifest entry name', () => {
  const offenders = [...SOURCE.matchAll(/warn\([^;]*?\$\{entry\.name\}/gu)].map((m) => m[0]);

  assert.deepEqual(
    offenders,
    [],
    'a withheld repo must never be named in an Actions log — log position, not identity',
  );
});


// --- request deadlines and rate limits (#12) -----------------------------

function res(status, headers = {}) {
  return { status, headers: { get: (k) => headers[k.toLowerCase()] ?? null } };
}

test('a rate limit is distinguished from a plain refusal', () => {
  // Both arrive as 403 and used to collapse into the same null.
  assert.equal(isRateLimited(res(429)), true, '429 is always a limit');
  assert.equal(isRateLimited(res(403, { 'x-ratelimit-remaining': '0' })), true, 'primary limit');
  assert.equal(isRateLimited(res(403, { 'retry-after': '30' })), true, 'secondary limit');

  // A permission the token does not have: no limit headers.
  assert.equal(isRateLimited(res(403)), false, 'forbidden is not rate limited');
  assert.equal(isRateLimited(res(403, { 'x-ratelimit-remaining': '4821' })), false);
  assert.equal(isRateLimited(res(404)), false);
  assert.equal(isRateLimited(res(200)), false);
  assert.equal(isRateLimited(null), false);
});

test('retry delay honours the server before falling back to backoff', () => {
  const now = 1_000_000;
  assert.equal(retryDelayMs(res(403, { 'retry-after': '5' }), 0, now), 5000);
  // x-ratelimit-reset is epoch seconds, and only speaks for a *primary* limit.
  assert.equal(
    retryDelayMs(
      res(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(now / 1000 + 7) }),
      0,
      now,
    ),
    7000,
  );
  // Neither header: exponential.
  assert.equal(retryDelayMs(res(429), 0, now), 1000);
  assert.equal(retryDelayMs(res(429), 2, now), 4000);
});

// x-ratelimit-reset rides on every response. Unless the budget is actually
// spent it describes the hourly rollover, not this refusal — so it must not
// become the delay for a limit it says nothing about.
test('an unspent budget leaves the reset header out of the delay', () => {
  const now = 1_000_000;
  const hourlyRollover = String(now / 1000 + 3000);

  // Secondary limit: the server's own retry-after wins over the rollover.
  assert.equal(
    retryDelayMs(
      res(429, {
        'retry-after': '5',
        'x-ratelimit-remaining': '4837',
        'x-ratelimit-reset': hourlyRollover,
      }),
      0,
      now,
    ),
    5000,
  );

  // Bare 429: the server said nothing, so back off — do not read the rollover
  // as an instruction and sit out the cap on every attempt.
  assert.equal(
    retryDelayMs(res(429, { 'x-ratelimit-remaining': '4837', 'x-ratelimit-reset': hourlyRollover }), 0, now),
    1000,
  );
});

test('a hostile or absurd delay is capped, so a run cannot be parked forever', () => {
  const now = 1_000_000;
  assert.equal(retryDelayMs(res(403, { 'retry-after': '86400' }), 0, now), MAX_BACKOFF_MS);
  assert.equal(
    retryDelayMs(
      res(403, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(now / 1000 + 99999) }),
      0,
      now,
    ),
    MAX_BACKOFF_MS,
  );
  assert.equal(retryDelayMs(res(429), 20, now), MAX_BACKOFF_MS);
});

test('a past reset or malformed header does not produce a negative wait', () => {
  const now = 1_000_000;
  for (const h of [{ 'x-ratelimit-reset': String(now / 1000 - 60) }, { 'retry-after': 'soon' }, {}]) {
    const delay = retryDelayMs(res(429, h), 0, now);
    assert.ok(delay > 0 && delay <= MAX_BACKOFF_MS, `${JSON.stringify(h)} -> ${delay}`);
  }
});

test('every request carries a deadline', () => {
  assert.match(SOURCE, /AbortSignal\.timeout\(REQUEST_TIMEOUT_MS\)/u,
    'gh() must pass an abort signal — an unbounded fetch holds the job and queues every run behind it');
});

test('CI status degrades on a denied read rather than aborting', () => {
  const ci = SOURCE.slice(SOURCE.indexOf('async function fetchCi'), SOURCE.indexOf('export function parseCodexSync'));
  assert.doesNotMatch(ci, /ghJson\(/u, 'actions/runs must not read through ghJson — it throws on 403');
  assert.match(ci, /response\.ok/u);
});

test('the repo detail is fetched once, not once per consumer', () => {
  const floor = SOURCE.slice(SOURCE.indexOf('async function fetchSecurityFloor'), SOURCE.indexOf('async function fetchCi'));
  assert.doesNotMatch(floor, /await ghJson\(`\/repos\/\$\{ACCOUNT\}\/\$\{repo\}`\)/u,
    'the gate already holds this response; refetching is pressure against the rate limit');
});


// --- an exhausted rate limit must not kill the run -----------------------

function limited(status, headers = {}) {
  return new Response('{"message":"API rate limit exceeded for user"}', { status, headers });
}

async function withStubbedFetch(respond, fn) {
  const realFetch = globalThis.fetch;
  const realToken = process.env.GITHUB_TOKEN;
  const realWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  globalThis.fetch = respond;
  process.env.GITHUB_TOKEN = 'test-token-not-a-real-credential';
  resetCollectionHealth();
  resetRateLimitWindow();
  try {
    return await fn();
  } finally {
    globalThis.fetch = realFetch;
    process.stderr.write = realWrite;
    if (realToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = realToken;
    resetCollectionHealth();
    resetRateLimitWindow();
  }
}

// The scenario this PR exists for: a limit outlasting the bounded retry. It
// used to reach a `throw`, which killed the collection before writeFileSync —
// so `collection.rateLimited`, the field added to explain the failure, was
// incremented and then discarded in the same run.
test('a rate limit that outlasts retries yields an unknown count, not a dead run', async () => {
  for (const status of [429, 403]) {
    const count = await withStubbedFetch(
      async () => limited(status, { 'x-ratelimit-remaining': '0' }),
      () => countOpenAlerts('example', 'dependabot'),
    );
    assert.equal(count, null, `HTTP ${status} must be an unknown count`);
  }
});

test('a 5xx on an alert endpoint is unknown, not fatal', async () => {
  const count = await withStubbedFetch(
    async () => new Response('upstream exploded', { status: 500 }),
    () => countOpenAlerts('example', 'codeScanning'),
  );
  assert.equal(count, null);
});

test('an exhausted limit is still counted, so the reason survives', async () => {
  const health = await withStubbedFetch(
    async () => limited(429, { 'x-ratelimit-remaining': '0' }),
    async () => {
      await countOpenAlerts('example', 'secretScanning');
      return collectionHealth();
    },
  );
  assert.equal(health.rateLimited, 1, 'the run must be able to say why the count is unknown');
});

// --- the retry budget is bounded across the run, not just per request ----

test('a primary limit resetting beyond the run closes the window for everyone', () => {
  resetRateLimitWindow();
  assert.equal(rateLimitWindowIsOpen(), true, 'open before any limit is seen');
});

test('a far-future reset stops further retrying instead of re-spending the budget', async () => {
  const farFuture = Math.floor(Date.now() / 1000) + 3600;
  let calls = 0;
  await withStubbedFetch(
    async () => {
      calls += 1;
      return limited(429, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(farFuture) });
    },
    async () => {
      await countOpenAlerts('example', 'dependabot');
      const first = calls;
      // A second call in the same run must not spend another full budget:
      // a primary limit is account-wide, so the window is already known shut.
      await countOpenAlerts('example', 'codeScanning');
      assert.equal(calls - first, 1, 'the second request should not retry at all');
    },
  );
  assert.ok(calls <= MAX_ATTEMPTS + 1, `expected the budget to be spent once, saw ${calls} calls`);
});

// The mirror of the test above, and the realistic one. This workload runs
// roughly 73 requests an hour against a budget of 5,000, so the primary limit
// is effectively unreachable; a secondary limit from burst concurrency is what
// will actually fire. The window closed on `x-ratelimit-reset` unconditionally,
// and that header is present on every response — so the breaker was tripped by
// the shape it cannot reason about and never by the one it was built for.
test('a secondary limit is waited out, not treated as the budget running dry', async () => {
  const hourlyRollover = Math.floor(Date.now() / 1000) + 50 * 60;
  let calls = 0;
  const count = await withStubbedFetch(
    async () => {
      calls += 1;
      if (calls > 1) return new Response('[]', { status: 200 });
      // Budget nearly untouched; the server asked for one second.
      return limited(429, {
        'retry-after': '1',
        'x-ratelimit-remaining': '4837',
        'x-ratelimit-reset': String(hourlyRollover),
      });
    },
    async () => {
      const result = await countOpenAlerts('example', 'dependabot');
      assert.equal(rateLimitWindowIsOpen(), true, 'a five-second wait is not a spent budget');
      return result;
    },
  );

  assert.equal(calls, 2, 'the second attempt is the whole point of retry-after');
  assert.equal(count, 0, 'a waited-out limit yields a real count, not an unknown');
});

test('a wait longer than the run will sit out closes the window, whatever its shape', async () => {
  await withStubbedFetch(
    async () => limited(429, { 'retry-after': '900', 'x-ratelimit-remaining': '4837' }),
    async () => {
      await countOpenAlerts('example', 'dependabot');
      assert.equal(rateLimitWindowIsOpen(), false, 'fifteen minutes outlasts the run');
    },
  );
});

// --- a successful collection that knew less than it should have -----------
//
// The layer the earlier fixes left open. #3 stopped a null count rendering as a
// green zero, and #12's collector half stopped a rate limit killing the run —
// but the run itself stayed green through both, because `continue-on-error`
// only separates "collection failed" from "collection succeeded". A collection
// that succeeded while unable to read half the fleet is a third state, and it
// wore the good one's colours.

function snap(overrides = {}) {
  return {
    collection: { denied: 0, rateLimited: 0, failed: 0 },
    repos: [],
    ...overrides,
  };
}

function healthyRepo(overrides = {}) {
  return {
    name: 'example',
    codexSyncEnabled: null,
    security: { dependabotOpen: 0, codeScanningOpen: 1, secretScanningOpen: 0 },
    securityFloor: {
      secretScanning: true,
      pushProtection: true,
      dependabotAlerts: true,
      privateVulnerabilityReporting: true,
      codeqlConfigured: false,
      defaultBranchRuleset: true,
    },
    ...overrides,
  };
}

test('a collection that read everything it set out to read is not degraded', () => {
  assert.deepEqual(degradedReasons(snap({ repos: [healthyRepo(), healthyRepo()] })), []);
  assert.deepEqual(degradedReasons(snap()), [], 'an empty fleet is empty, not degraded');
});

test('each way a read can go missing is named separately', () => {
  assert.deepEqual(degradedReasons(snap({ collection: { denied: 2, rateLimited: 0, failed: 0 } })), [
    '2 denied',
  ]);
  assert.deepEqual(degradedReasons(snap({ collection: { denied: 0, rateLimited: 3, failed: 0 } })), [
    '3 rate-limited',
  ]);
  assert.deepEqual(degradedReasons(snap({ collection: { denied: 0, rateLimited: 0, failed: 1 } })), [
    '1 failed or timed out',
  ]);
  // Collapsed, they would say only "something went wrong" — which is the
  // difference between "fix the token" and "wait".
  assert.deepEqual(degradedReasons(snap({ collection: { denied: 1, rateLimited: 1, failed: 1 } })), [
    '1 denied',
    '1 rate-limited',
    '1 failed or timed out',
  ]);
});

// The artifact leg of the gate. A 404 yields a null count without touching a
// counter, so only the snapshot knows the page will show a `?` — the counters
// are the other leg, tested above, and they overlap by design.
test('an unreadable posture field is degradation even when no counter moved', () => {
  const reasons = degradedReasons(
    snap({ repos: [healthyRepo({ security: { dependabotOpen: null, codeScanningOpen: 0, secretScanningOpen: 0 } })] }),
  );
  assert.deepEqual(reasons, ['1 posture fields unreadable']);
});

// The gate-failure paths the counters miss entirely. A deleted repo left in
// the manifest with `publish: true` 404s at the gate: no health counter moves,
// no row publishes, `unreadable` becomes 1 — and before this check the run
// stayed green while the page reported a repo it could not evaluate.
test('a repo unreadable at the gate reddens the run even with clean counters', () => {
  const reasons = degradedReasons(snap({ unreadable: 1, repos: [healthyRepo()] }));
  assert.deepEqual(reasons, ['1 repos unreadable at the gate']);
});

test('a malformed unreadable count from an untrusted snapshot is not degradation evidence', () => {
  for (const bad of [null, undefined, -1, 1.5, Number.NaN, '2', {}, [], true]) {
    assert.deepEqual(
      degradedReasons(snap({ unreadable: bad, repos: [healthyRepo()] })),
      [],
      `unreadable ${JSON.stringify(bad)} is not a sane count`,
    );
  }
  assert.deepEqual(degradedReasons(snap({ unreadable: 0, repos: [healthyRepo()] })), []);
});

test('an unreadable floor boolean counts the same as an unreadable count', () => {
  const reasons = degradedReasons(
    snap({ repos: [healthyRepo({ securityFloor: { ...healthyRepo().securityFloor, codeqlConfigured: null } })] }),
  );
  assert.deepEqual(reasons, ['1 posture fields unreadable']);
});

// The distinction the gate lives or dies by. `codexSyncEnabled` is null on
// seven of the eight repos published today, because the manifest never asserts
// it (#8) — not because a read was refused. Counting it would redden every run
// from the first, and a gate that is always red is a gate nobody reads.
test('a fact the manifest never asserted is not a read that failed', () => {
  assert.deepEqual(degradedReasons(snap({ repos: [healthyRepo({ codexSyncEnabled: null })] })), []);
  assert.deepEqual(degradedReasons(snap({ repos: [healthyRepo({ codexSyncEnabled: true })] })), []);
});

test('a malformed count from an untrusted snapshot is unreadable, not zero', () => {
  for (const bad of [undefined, 'three', Number.NaN, -1, 1.5, {}, [], true, Infinity]) {
    const reasons = degradedReasons(
      snap({ repos: [healthyRepo({ security: { dependabotOpen: bad, codeScanningOpen: 0, secretScanningOpen: 0 } })] }),
    );
    assert.deepEqual(reasons, ['1 posture fields unreadable'], `${JSON.stringify(bad)} is unknown`);
  }
});

// GitHub answers 403 on `dependabot/alerts` when Dependabot alerts are
// disabled and 404 on `code-scanning/alerts` when code scanning was never
// enabled — permanent, owner-chosen states. A repo that has chosen not to run
// a scanner must not redden every hourly run forever; the missing number is
// already explained on the page by the floor flag itself.
test('a null count for a feature the owner disabled is a choice, not a failed read', () => {
  const base = healthyRepo();
  for (const [count, flag] of [
    ['dependabotOpen', 'dependabotAlerts'],
    ['codeScanningOpen', 'codeqlConfigured'],
    ['secretScanningOpen', 'secretScanning'],
  ]) {
    const repo = healthyRepo({
      security: { ...base.security, [count]: null },
      securityFloor: { ...base.securityFloor, [flag]: false },
    });
    assert.deepEqual(degradedReasons(snap({ repos: [repo] })), [], `${flag}: false explains ${count}: null`);
  }
});

test('a null count with the feature enabled is a read the collector lost', () => {
  const base = healthyRepo();
  const repo = healthyRepo({
    security: { ...base.security, codeScanningOpen: null },
    securityFloor: { ...base.securityFloor, codeqlConfigured: true },
  });
  assert.deepEqual(degradedReasons(snap({ repos: [repo] })), ['1 posture fields unreadable']);
});

// An unknown flag cannot vouch for anything: both the flag and the count went
// unread, and both are gaps the page will show.
test('an unknown flag does not excuse its count', () => {
  const base = healthyRepo();
  const repo = healthyRepo({
    security: { ...base.security, codeScanningOpen: null },
    securityFloor: { ...base.securityFloor, codeqlConfigured: null },
  });
  assert.deepEqual(degradedReasons(snap({ repos: [repo] })), ['2 posture fields unreadable']);
});

// The pairing is per-feature, and the excuse is only for `null`. One scanner
// being off says nothing about another scanner's missing count, and a
// malformed value is corruption whatever the owner chose.
test('a disabled feature excuses only its own null, nothing else', () => {
  const base = healthyRepo();
  const crossed = healthyRepo({
    security: { ...base.security, dependabotOpen: null },
    securityFloor: { ...base.securityFloor, codeqlConfigured: false, dependabotAlerts: true },
  });
  assert.deepEqual(degradedReasons(snap({ repos: [crossed] })), ['1 posture fields unreadable']);

  const malformed = healthyRepo({
    security: { ...base.security, codeScanningOpen: 'three' },
    securityFloor: { ...base.securityFloor, codeqlConfigured: false },
  });
  assert.deepEqual(degradedReasons(snap({ repos: [malformed] })), ['1 posture fields unreadable']);
});

test('nothing hostile in a snapshot reaches the reason string', () => {
  // The reason is echoed into a public Actions log and crosses a job boundary.
  const reasons = degradedReasons(
    snap({
      collection: { denied: 1, rateLimited: 0, failed: 0 },
      repos: [healthyRepo({ name: 'secret-internal-repo', security: { dependabotOpen: null, codeScanningOpen: 0, secretScanningOpen: 0 } })],
    }),
  );
  const joined = reasons.join(', ');
  assert.doesNotMatch(joined, /secret-internal-repo/u, 'counts only — never which repo');
  assert.match(joined, /^[\w ,.:;/()-]+$/u, 'no character that could forge a log command');
});

test('a degraded snapshot never silently keeps its shape', () => {
  assert.deepEqual(degradedReasons(undefined), [], 'no snapshot is not a claim about one');
  assert.deepEqual(degradedReasons({}), []);
});

test('the committed fallback fixture is not itself degraded', () => {
  const fixture = JSON.parse(
    readFileSync(new URL('../public/data/snapshot.json', import.meta.url), 'utf8'),
  );
  // The gate is guarded by `fresh == 'true'` so it never evaluates the fixture,
  // but a fixture that reads as degraded would mean the shipped fallback is
  // quietly publishing unknowns as posture.
  assert.deepEqual(degradedReasons(fixture), []);
});

test('the verdict is handed to the workflow in the format it reads', () => {
  const out = join(tmpdir(), `gh-output-${process.pid}.txt`);
  try {
    reportDegradation(['2 denied', '1 posture fields unreadable'], out);
    assert.equal(
      readFileSync(out, 'utf8'),
      'degraded=true\ndegraded_reason=2 denied, 1 posture fields unreadable\n',
    );
  } finally {
    rmSync(out, { force: true });
  }
});

test('a clean run says so explicitly rather than saying nothing', () => {
  const out = join(tmpdir(), `gh-output-clean-${process.pid}.txt`);
  try {
    reportDegradation([], out);
    // An absent output and a false one are the same to the gate's `if`, but not
    // to a reader of the log deciding whether the check ran at all.
    assert.equal(readFileSync(out, 'utf8'), 'degraded=false\ndegraded_reason=\n');
  } finally {
    rmSync(out, { force: true });
  }
});

test('a reason cannot forge a second output line', () => {
  const out = join(tmpdir(), `gh-output-forge-${process.pid}.txt`);
  try {
    // Not reachable from the current reasons, which are built from integers.
    // Asserted anyway: this is the one place a collector string crosses into
    // the workflow, and a forged `degraded=false` would switch the gate off.
    reportDegradation(['1 denied\ndegraded=false', '<img src=x>'], out);
    const written = readFileSync(out, 'utf8');
    assert.equal(written.split('\n').filter(Boolean).length, 2, 'exactly two output lines');
    assert.doesNotMatch(written, /degraded=false/u);
    assert.equal(written.split('\n')[0], 'degraded=true');
  } finally {
    rmSync(out, { force: true });
  }
});

test('outside Actions it writes nothing at all', () => {
  assert.doesNotThrow(() => reportDegradation(['1 denied'], undefined));
  assert.doesNotThrow(() => reportDegradation(['1 denied'], ''));
});

// --- a failed gate is not a decision (#12, finding 3) ---------------------

test('a gate that could not be evaluated is unreadable, not withheld', () => {
  // Nine governed, all opted in, one lookup rate-limited. The repo publishes no
  // row either way — but it was not a choice, and `withheld` claims it was.
  const tally = publicationTally({ governed: 9, candidates: 9, published: 8, unreadable: 1 });

  assert.equal(tally.unreadable, 1);
  assert.equal(tally.withheld, 0, 'nothing here was deliberately withheld');
});

test('the two kinds of withholding are counted separately', () => {
  const tally = publicationTally({ governed: 9, candidates: 6, published: 4, unreadable: 1 });

  assert.equal(tally.notOptedIn, 3, 'governed but no publish: true');
  assert.equal(tally.notObservedPublic, 1, 'opted in, observed non-public');
  assert.equal(tally.withheld, 4, 'both are decisions');
  assert.equal(tally.unreadable, 1, 'this one is a failure');
});

test('every governed repo lands in exactly one bucket', () => {
  for (let governed = 0; governed <= 6; governed += 1) {
    for (let candidates = 0; candidates <= governed; candidates += 1) {
      for (let unreadable = 0; unreadable <= candidates; unreadable += 1) {
        for (let published = 0; published <= candidates - unreadable; published += 1) {
          const t = publicationTally({ governed, candidates, published, unreadable });
          assert.equal(
            published + t.withheld + t.unreadable,
            governed,
            `${published}+${t.withheld}+${t.unreadable} != ${governed}`,
          );
        }
      }
    }
  }
});

// Publishing a denominator we cannot derive would state something untrue about
// the fleet, so an impossible tally is fatal rather than rounded into shape.
test('a tally that cannot add up refuses to produce a number', () => {
  const impossible = [
    { governed: 5, candidates: 6, published: 0, unreadable: 0 },
    { governed: 5, candidates: 5, published: 4, unreadable: 2 },
    { governed: 5, candidates: 5, published: 6, unreadable: 0 },
    { governed: -1, candidates: 0, published: 0, unreadable: 0 },
    { governed: 5, candidates: 5, published: 1.5, unreadable: 0 },
    { governed: 5, candidates: 5, published: Number.NaN, unreadable: 0 },
  ];

  for (const input of impossible) {
    assert.throws(
      () => publicationTally(input),
      /does not add up/u,
      `${JSON.stringify(input)} should not yield a count`,
    );
  }
});

test('the tally reaches the snapshot as two fields, never one', () => {
  const main = SOURCE.slice(SOURCE.indexOf('async function main()'));
  assert.match(main, /^\s*withheld,$/mu, 'withheld is published');
  assert.match(main, /^\s*unreadable,$/mu, 'unreadable is published alongside it');
  assert.doesNotMatch(
    main,
    /withheld:\s*withheld\s*\+\s*unreadable/u,
    'summing them restores the conflation this split exists to undo',
  );
});
