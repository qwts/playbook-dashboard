import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  ALLOWED_URL_ORIGIN,
  MAX_DELTA_LENGTH,
  fetchRepoForGate,
  isObservedPublic,
  isPublishable,
  parseCodexSync,
  sanitizeDelta,
  sanitizeGithubUrl,
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

  assert.deepEqual(failures, ['403', 'network']);
});

test('no log line interpolates a manifest entry name', () => {
  const offenders = [...SOURCE.matchAll(/warn\([^;]*?\$\{entry\.name\}/gu)].map((m) => m[0]);

  assert.deepEqual(
    offenders,
    [],
    'a withheld repo must never be named in an Actions log — log position, not identity',
  );
});
