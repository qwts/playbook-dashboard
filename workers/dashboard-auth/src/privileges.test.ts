import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Env } from './env.ts';
import {
  checkPrivilegedRequest,
  isAdminIdentity,
  isFreshEnoughToAct,
  isHeadSha,
  isIdempotencyKey,
  isReviewEvent,
  parseAdminSubjects,
  parsePullNumber,
  parseRepoRef,
  sanitizeGithubUrl,
  sanitizeReviewBody,
  sanitizeText,
} from './privileges.ts';

const ENV = {
  ADMIN_SUBJECTS: 'github:12345, google:98765',
  ALLOWED_OWNERS: 'qwts',
  PRIVILEGED_MAX_AGE_SECONDS: '3600',
} as Env;

const SHA = 'a'.repeat(40);

test('an unset allowlist privileges nobody', () => {
  // The failure this prevents is a deploy that forgets the secret and grants
  // the panel to everyone who can sign in — which is everyone.
  assert.equal(parseAdminSubjects(undefined).size, 0);
  assert.equal(parseAdminSubjects('').size, 0);
  assert.equal(isAdminIdentity({} as Env, 'github', '12345'), false);
});

test('allowlist entries are provider:subject, and malformed ones are dropped', () => {
  const admins = parseAdminSubjects('github:1 GOOGLE:2 twitter:3 github: :4 nocolon apple:5');

  assert.deepEqual([...admins].sort(), ['apple:5', 'github:1', 'google:2']);
});

test('an admin is matched on subject, never on login or email', () => {
  assert.equal(isAdminIdentity(ENV, 'github', '12345'), true);
  assert.equal(isAdminIdentity(ENV, 'google', '98765'), true);

  // Same subject, different provider: a Google account whose numeric id happens
  // to equal a GitHub user id is a different person.
  assert.equal(isAdminIdentity(ENV, 'google', '12345'), false);
  assert.equal(isAdminIdentity(ENV, 'github', '98765'), false);
  assert.equal(isAdminIdentity(ENV, 'github', ''), false);
});

test('a repo reference must name an allowed owner and survive no traversal', () => {
  assert.deepEqual(parseRepoRef(ENV, 'qwts/playbook-dashboard'), {
    owner: 'qwts',
    name: 'playbook-dashboard',
    fullName: 'qwts/playbook-dashboard',
  });

  assert.equal(parseRepoRef(ENV, 'someone-else/repo'), null);
  assert.equal(parseRepoRef(ENV, 'qwts/..'), null);
  assert.equal(parseRepoRef(ENV, 'qwts/repo/../../secrets'), null);
  assert.equal(parseRepoRef(ENV, 'qwts/repo?query=1'), null);
  assert.equal(parseRepoRef(ENV, '../qwts/repo'), null);
  assert.equal(parseRepoRef(ENV, 'qwts'), null);
  assert.equal(parseRepoRef(ENV, 42), null);
});

test('head shas, pull numbers, and idempotency keys are closed shapes', () => {
  assert.equal(isHeadSha(SHA), true);
  assert.equal(isHeadSha(SHA.toUpperCase()), false);
  assert.equal(isHeadSha('a'.repeat(39)), false);
  assert.equal(isHeadSha('main'), false);

  assert.equal(parsePullNumber(12), 12);
  assert.equal(parsePullNumber('12'), 12);
  assert.equal(parsePullNumber(0), null);
  assert.equal(parsePullNumber(-1), null);
  assert.equal(parsePullNumber(1.5), null);
  assert.equal(parsePullNumber('twelve'), null);

  assert.equal(isIdempotencyKey('4b1e0d2c-9f3a-4c11-8a77-1f2e3d4c5b6a'), true);
  assert.equal(isIdempotencyKey('short'), false);
  assert.equal(isIdempotencyKey("'; DROP TABLE audit_log;--"), false);
});

test('the review vocabulary is closed', () => {
  assert.equal(isReviewEvent('APPROVE'), true);
  assert.equal(isReviewEvent('REQUEST_CHANGES'), true);
  assert.equal(isReviewEvent('COMMENT'), true);

  // Not a review verb, and the one that would be worst to accept by accident.
  assert.equal(isReviewEvent('MERGE'), false);
  assert.equal(isReviewEvent('approve'), false);
  assert.equal(isReviewEvent(null), false);
});

test('a review body is refused whole, never truncated', () => {
  assert.equal(sanitizeReviewBody('looks good'), 'looks good');
  assert.equal(sanitizeReviewBody(undefined), '');
  assert.equal(sanitizeReviewBody('line one\nline two'), 'line one\nline two');

  assert.equal(sanitizeReviewBody('x'.repeat(2001)), null);
  assert.equal(sanitizeReviewBody(`bell${String.fromCharCode(7)}`), null);
  assert.equal(sanitizeReviewBody({ toString: () => 'nope' }), null);
});

test('text from GitHub is stripped of control characters and capped', () => {
  assert.equal(sanitizeText('Fix the thing', 200), 'Fix the thing');
  assert.equal(sanitizeText(`spoof${String.fromCharCode(13)}Approved by admin`, 200), 'spoof Approved by admin');
  assert.equal(sanitizeText('', 200), null);
  assert.equal(sanitizeText(null, 200), null);

  const long = sanitizeText('x'.repeat(50), 10);
  assert.equal(long?.length, 10);
  assert.ok(long?.endsWith('…'));
});

test('only github.com urls survive, and never their query strings', () => {
  assert.equal(
    sanitizeGithubUrl('https://github.com/qwts/playbook-dashboard/pull/7'),
    'https://github.com/qwts/playbook-dashboard/pull/7',
  );
  assert.equal(
    sanitizeGithubUrl('https://github.com/qwts/repo/pull/7?token=leak'),
    'https://github.com/qwts/repo/pull/7',
  );
  assert.equal(sanitizeGithubUrl('https://github.com.evil.test/qwts/repo'), null);
  assert.equal(sanitizeGithubUrl('http://github.com/qwts/repo'), null);
  assert.equal(sanitizeGithubUrl('javascript:alert(1)'), null);
  assert.equal(sanitizeGithubUrl('not a url'), null);
});

const URL_UNDER_TEST = new URL('https://dashboard.invalid/admin/review');

function privilegedRequest(headers: Record<string, string>): Request {
  return new Request(URL_UNDER_TEST, { method: 'POST', headers });
}

test('a privileged request must carry the custom header', () => {
  assert.equal(
    checkPrivilegedRequest(privilegedRequest({ Origin: 'https://dashboard.invalid' }), URL_UNDER_TEST, {
      mutating: true,
    }),
    'missing_action_header',
  );
});

test('a mutating request must come from this origin', () => {
  const headers = {
    'x-dashboard-action': '1',
    Origin: 'https://attacker.invalid',
  };
  assert.equal(
    checkPrivilegedRequest(privilegedRequest(headers), URL_UNDER_TEST, { mutating: true }),
    'origin_mismatch',
  );

  // A form post from another site arrives with no Origin match and no header;
  // either alone is enough to refuse it.
  assert.equal(
    checkPrivilegedRequest(privilegedRequest({ 'x-dashboard-action': '1' }), URL_UNDER_TEST, {
      mutating: true,
    }),
    'origin_mismatch',
  );
});

test('Sec-Fetch-Site refuses anything the browser calls cross-site', () => {
  const headers = {
    'x-dashboard-action': '1',
    Origin: 'https://dashboard.invalid',
    'Sec-Fetch-Site': 'cross-site',
  };
  assert.equal(
    checkPrivilegedRequest(privilegedRequest(headers), URL_UNDER_TEST, { mutating: true }),
    'cross_site_request',
  );
});

test('a well-formed request passes, and reads do not need an Origin', () => {
  assert.equal(
    checkPrivilegedRequest(
      privilegedRequest({
        'x-dashboard-action': '1',
        Origin: 'https://dashboard.invalid',
        'Sec-Fetch-Site': 'same-origin',
      }),
      URL_UNDER_TEST,
      { mutating: true },
    ),
    null,
  );

  // Browsers omit Origin on same-origin GETs; requiring it would fail every
  // read for no gain.
  assert.equal(
    checkPrivilegedRequest(
      new Request('https://dashboard.invalid/admin/repos', {
        headers: { 'x-dashboard-action': '1' },
      }),
      new URL('https://dashboard.invalid/admin/repos'),
      { mutating: false },
    ),
    null,
  );
});

test('a session old enough to read is not automatically fresh enough to act', () => {
  const now = 1_800_000_000;
  assert.equal(isFreshEnoughToAct(ENV, now - 60, now), true);
  assert.equal(isFreshEnoughToAct(ENV, now - 3_600, now), true);
  assert.equal(isFreshEnoughToAct(ENV, now - 3_601, now), false);

  // An eight-hour session is still valid for /data/* at this point.
  assert.equal(isFreshEnoughToAct(ENV, now - 28_000, now), false);
});
