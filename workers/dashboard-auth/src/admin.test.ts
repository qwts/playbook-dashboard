import assert from 'node:assert/strict';
import { test } from 'node:test';
import { routeAdmin } from './admin.ts';
import { seal, signClaims } from './crypto.ts';
import type { Database, PreparedStatement, SqlValue } from './d1.ts';
import type { Env } from './env.ts';
import { SESSION_COOKIE } from './session.ts';

/**
 * These tests exist for one property: nothing reaches GitHub that should not,
 * and nothing that reaches GitHub goes unrecorded. Every case therefore
 * asserts on the *calls made*, not only on the status returned — a 403 with a
 * pull request already approved behind it would pass a status-only test.
 */

const SHA = 'a'.repeat(40);
const MOVED_SHA = 'b'.repeat(40);
const KEY = '4b1e0d2c-9f3a-4c11-8a77-1f2e3d4c5b6a';
const ORIGIN = 'https://dashboard.invalid';

type AuditRow = {
  outcome: string;
  login: string | null;
  repo: string;
  target: string;
  headSha: string;
  verb: string;
};

type FakeDb = {
  db: Database;
  audit: Map<string, AuditRow>;
  tokens: Map<string, { secret: string; access: number | null; refresh: number | null }>;
};

function fakeDb(options: { failAuditInsert?: boolean; recentAttempts?: number } = {}): FakeDb {
  const audit = new Map<string, AuditRow>();
  const tokens = new Map<string, { secret: string; access: number | null; refresh: number | null }>();

  const db: Database = {
    prepare(sql: string): PreparedStatement {
      let args: SqlValue[] = [];
      const statement: PreparedStatement = {
        bind(...values: SqlValue[]) {
          args = values;
          return statement;
        },
        async first<T>(): Promise<T | null> {
          if (sql.includes('FROM actor_tokens')) {
            const row = tokens.get(String(args[0]));
            return row
              ? ({
                  secret: row.secret,
                  access_expires_at: row.access,
                  refresh_expires_at: row.refresh,
                } as T)
              : null;
          }
          if (sql.includes('COUNT(*)')) {
            return { attempts: options.recentAttempts ?? 0 } as T;
          }
          if (sql.includes('SELECT outcome')) {
            const row = audit.get(String(args[0]));
            // The full row, as the real query selects it: a fixture that
            // returns less makes the reuse check pass for the wrong reason.
            return row
              ? ({
                  outcome: row.outcome,
                  repo: row.repo,
                  target: row.target,
                  verb: row.verb,
                } as T)
              : null;
          }
          return null;
        },
        async run() {
          if (sql.includes('INSERT INTO audit_log')) {
            if (options.failAuditInsert) throw new Error('D1_ERROR: database unavailable');
            const id = String(args[0]);
            if (audit.has(id)) return { meta: { changes: 0 } };
            audit.set(id, {
              outcome: 'attempted',
              login: args[4] === null ? null : String(args[4]),
              repo: String(args[6]),
              target: String(args[7]),
              headSha: String(args[8]),
              verb: String(args[9]),
            });
            return { meta: { changes: 1 } };
          }
          if (sql.includes('UPDATE audit_log')) {
            const row = audit.get(String(args[2]));
            if (row && row.outcome === 'attempted') row.outcome = String(args[0]);
            return { meta: { changes: 1 } };
          }
          if (sql.includes('DELETE FROM actor_tokens')) {
            if (sql.includes('refresh_expires_at')) {
              // The reaper: expired refresh expiries go, NULL stays.
              const cutoff = Number(args[0]);
              for (const [sid, row] of [...tokens]) {
                if (row.refresh !== null && row.refresh < cutoff) tokens.delete(sid);
              }
            } else {
              tokens.delete(String(args[0]));
            }
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 1 } };
        },
        async all<T>() {
          return { results: [] as T[] };
        },
      };
      return statement;
    },
  };

  return { db, audit, tokens };
}

type Call = { method: string; url: string; body: unknown };

function stubFetch(handler: (call: Call) => Response): { calls: Call[]; restore: () => void } {
  const calls: Call[] = [];
  const original = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const call: Call = {
      method: init?.method ?? 'GET',
      url: String(input),
      body: init?.body ? JSON.parse(String(init.body)) : null,
    };
    calls.push(call);
    return handler(call);
  }) as typeof globalThis.fetch;

  return { calls, restore: () => void (globalThis.fetch = original) };
}

function githubJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function envWith(fake: FakeDb): Promise<Env> {
  const env = {
    SESSION_SECRET: 'test-secret-not-a-real-one',
    SESSION_TTL_SECONDS: '28800',
    TOKEN_ENCRYPTION_KEY: 'test-encryption-key-not-a-real-one',
    ADMIN_SUBJECTS: 'github:12345',
    ALLOWED_OWNERS: 'qwts',
    PRIVILEGED_MAX_AGE_SECONDS: '3600',
    PRIVILEGED_RATE_LIMIT: '10',
    DB: fake.db,
  } as unknown as Env;

  const now = Math.floor(Date.now() / 1000);
  fake.tokens.set('session-1', {
    secret: await seal(env.TOKEN_ENCRYPTION_KEY, {
      accessToken: 'gho_test_token',
      refreshToken: 'ghr_test_token',
      accessExpiresAt: now + 3_600,
      refreshExpiresAt: now + 1_000_000,
      // Sealed at sign-in alongside the token; the cookie carries no login.
      login: 'chris',
    }),
    access: now + 3_600,
    refresh: now + 1_000_000,
  });

  return env;
}

async function cookieFor(env: Env, overrides: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const token = await signClaims(env.SESSION_SECRET, 'session', {
    provider: 'github',
    subject: '12345',
    sid: 'session-1',
    iat: now,
    exp: now + 28_800,
    ...overrides,
  });
  return `${SESSION_COOKIE}=${token}`;
}

function reviewRequest(cookie: string | null, body: unknown, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    'x-dashboard-action': '1',
    Origin: ORIGIN,
    'Content-Type': 'application/json',
    ...extra,
  };
  if (cookie) headers.Cookie = cookie;

  return new Request(`${ORIGIN}/admin/review`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

const APPROVAL = {
  repo: 'qwts/playbook-dashboard',
  number: 7,
  head_sha: SHA,
  event: 'APPROVE',
  idempotency_key: KEY,
};

async function route(env: Env, request: Request) {
  const response = await routeAdmin(env, request, new URL(request.url));
  assert.ok(response, 'routeAdmin claimed the /admin path');
  return response;
}

test('an unauthenticated caller never reaches GitHub', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    const response = await route(env, reviewRequest(null, APPROVAL));

    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, 'authentication_required');
    assert.equal(stub.calls.length, 0);
    assert.equal(fake.audit.size, 0);
  } finally {
    stub.restore();
  }
});

test('a signed-in reader who is not on the allowlist is refused', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    const cookie = await cookieFor(env, { subject: '999' });
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, 'not_privileged');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test('a session old enough to read is not fresh enough to act', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    // Four hours old: still a valid session for /data/*, and still signed.
    const now = Math.floor(Date.now() / 1000);
    const cookie = await cookieFor(env, { iat: now - 14_400 });
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, 'reauth_required');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test('a cross-origin submit is refused before the session is even read', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    const cookie = await cookieFor(env);
    const response = await route(
      env,
      reviewRequest(cookie, APPROVAL, { Origin: 'https://attacker.invalid' }),
    );

    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, 'origin_mismatch');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test('merging is not in the vocabulary, whatever the caller asks for', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, { ...APPROVAL, event: 'MERGE' }));
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.error, 'invalid_review_request');
    assert.equal(body.field, 'event');
    assert.equal(stub.calls.length, 0);
    assert.equal(fake.audit.size, 0);
  } finally {
    stub.restore();
  }
});

test('an approval whose head moved is refused, and nothing is recorded', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() =>
    githubJson({ number: 7, title: 'Fix', head: { sha: MOVED_SHA }, user: { login: 'bot' } }),
  );

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, APPROVAL));
    const body = await response.json();

    assert.equal(response.status, 409);
    assert.equal(body.error, 'head_moved');
    assert.equal(body.headSha, MOVED_SHA, 'the caller is told what it moved to');

    // One read of the pull request, and no review submitted.
    assert.equal(stub.calls.length, 1);
    assert.equal(stub.calls[0]?.method, 'GET');
    assert.equal(fake.audit.size, 0);
  } finally {
    stub.restore();
  }
});

test('an approval binds commit_id and closes its audit row', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch((call) =>
    call.method === 'POST'
      ? githubJson({ id: 1, state: 'APPROVED' }, 200)
      : githubJson({ number: 7, title: 'Fix', head: { sha: SHA }, user: { login: 'bot' } }),
  );

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 200);
    assert.equal((await response.json()).ok, true);

    const submit = stub.calls.find((call) => call.method === 'POST');
    assert.ok(submit, 'a review was submitted');
    assert.match(submit.url, /\/repos\/qwts\/playbook-dashboard\/pulls\/7\/reviews$/);
    assert.deepEqual(submit.body, { commit_id: SHA, event: 'APPROVE' });

    const row = fake.audit.get(KEY);
    assert.equal(row?.outcome, 'succeeded');
    assert.equal(row?.login, 'chris', 'the audit row is named from the sealed bundle');
    assert.equal(row?.repo, 'qwts/playbook-dashboard');
    assert.equal(row?.headSha, SHA);
    assert.equal(row?.verb, 'APPROVE');
  } finally {
    stub.restore();
  }
});

test('a replayed submit acts once and reports the first outcome', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch((call) =>
    call.method === 'POST'
      ? githubJson({ id: 1 })
      : githubJson({ number: 7, title: 'Fix', head: { sha: SHA }, user: { login: 'bot' } }),
  );

  try {
    const cookie = await cookieFor(env);
    await route(env, reviewRequest(cookie, APPROVAL));
    const second = await route(env, reviewRequest(cookie, APPROVAL));
    const body = await second.json();

    assert.equal(body.replay, true);
    assert.equal(body.outcome, 'succeeded');
    assert.equal(
      stub.calls.filter((call) => call.method === 'POST').length,
      1,
      'the double submit approved once',
    );
  } finally {
    stub.restore();
  }
});

test('an idempotency key reused against another pull request is not a replay', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch((call) =>
    call.method === 'POST'
      ? githubJson({ id: 1 })
      : githubJson({ number: 8, title: 'Other', head: { sha: SHA }, user: { login: 'bot' } }),
  );

  try {
    const cookie = await cookieFor(env);
    await route(env, reviewRequest(cookie, APPROVAL));

    // Same key, different pull request. Reporting the first attempt's success
    // here would claim #8 was approved when only #7 ever was.
    const response = await route(env, reviewRequest(cookie, { ...APPROVAL, number: 8 }));

    assert.equal(response.status, 409);
    assert.equal((await response.json()).error, 'idempotency_key_reused');
    assert.equal(stub.calls.filter((call) => call.method === 'POST').length, 1);
  } finally {
    stub.restore();
  }
});

test('an audit log that cannot be written refuses the action', async () => {
  const fake = fakeDb({ failAuditInsert: true });
  const env = await envWith(fake);
  const stub = stubFetch(() =>
    githubJson({ number: 7, title: 'Fix', head: { sha: SHA }, user: { login: 'bot' } }),
  );

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'audit_unavailable');
    assert.equal(
      stub.calls.filter((call) => call.method === 'POST').length,
      0,
      'no review was submitted without a record of it',
    );
  } finally {
    stub.restore();
  }
});

test('the rate limit is counted from the audit log, before any GitHub call', async () => {
  const fake = fakeDb({ recentAttempts: 10 });
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson({}));

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 429);
    assert.equal((await response.json()).error, 'rate_limited');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test('an admin with no stored token is told to authenticate, not silently failed', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  fake.tokens.clear();
  const stub = stubFetch(() => githubJson({}));

  try {
    const cookie = await cookieFor(env);
    const response = await route(env, reviewRequest(cookie, APPROVAL));

    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, 'actor_token_unavailable');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});

test('a privileged response is private and uncacheable', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() =>
    githubJson([{ number: 7, title: 'Fix', head: { sha: SHA }, user: { login: 'bot' } }]),
  );

  try {
    const cookie = await cookieFor(env);
    const request = new Request(`${ORIGIN}/admin/pulls?repo=qwts/playbook-dashboard`, {
      headers: { Cookie: cookie, 'x-dashboard-action': '1' },
    });
    const response = await route(env, request);

    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
    assert.equal(response.headers.get('Vary'), 'Cookie');
  } finally {
    stub.restore();
  }
});

test('a privileged request reaps rows whose refresh expiry has passed', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const now = Math.floor(Date.now() / 1000);

  // A row an expired session left behind, and one from an App with token
  // expiry turned off — the first is dead, the second still works.
  fake.tokens.set('stale-session', { secret: 'sealed', access: now - 40_000, refresh: now - 60 });
  fake.tokens.set('no-expiry', { secret: 'sealed', access: null, refresh: null });

  const stub = stubFetch(() => githubJson([]));

  try {
    const cookie = await cookieFor(env);
    const request = new Request(`${ORIGIN}/admin/repos`, {
      headers: { Cookie: cookie, 'x-dashboard-action': '1' },
    });
    const response = await route(env, request);

    assert.equal(response.status, 200);
    assert.equal(fake.tokens.has('stale-session'), false, 'the dead row was reaped');
    assert.equal(fake.tokens.has('no-expiry'), true, 'NULL refresh expiry is not dead');
    assert.equal(fake.tokens.has('session-1'), true, 'the live session keeps its token');
  } finally {
    stub.restore();
  }
});

test('a repo outside the allowed owners is refused without a lookup', async () => {
  const fake = fakeDb();
  const env = await envWith(fake);
  const stub = stubFetch(() => githubJson([]));

  try {
    const cookie = await cookieFor(env);
    const request = new Request(`${ORIGIN}/admin/pulls?repo=someone-else/private-repo`, {
      headers: { Cookie: cookie, 'x-dashboard-action': '1' },
    });
    const response = await route(env, request);

    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, 'invalid_repo');
    assert.equal(stub.calls.length, 0);
  } finally {
    stub.restore();
  }
});
