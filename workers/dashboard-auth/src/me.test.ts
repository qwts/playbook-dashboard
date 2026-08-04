import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker from './index.ts';
import { seal, signClaims } from './crypto.ts';
import type { Database, PreparedStatement, SqlValue } from './d1.ts';
import type { Env } from './env.ts';
import { SESSION_COOKIE } from './session.ts';

/**
 * `/auth/me` is the SPA's whole picture of who is signed in, and `privileged`
 * is its promise that a click would reach GitHub. These tests pin the honesty
 * of that promise: a stored row whose seal does not open is a row that cannot
 * act, and must not render a panel whose every click fails.
 */

const ORIGIN = 'https://dashboard.invalid';

function dbWithToken(sid: string, secret: string): Database {
  const statement = (sql: string): PreparedStatement => {
    let args: SqlValue[] = [];
    const self: PreparedStatement = {
      bind(...values: SqlValue[]) {
        args = values;
        return self;
      },
      async first<T>(): Promise<T | null> {
        if (sql.includes('FROM actor_tokens') && String(args[0]) === sid) {
          return { secret, access_expires_at: null, refresh_expires_at: null } as T;
        }
        return null;
      },
      async run() {
        return { meta: { changes: 1 } };
      },
      async all<T>() {
        return { results: [] as T[] };
      },
    };
    return self;
  };
  return { prepare: statement };
}

function envWith(db: Database): Env {
  return {
    SESSION_SECRET: 'test-secret-not-a-real-one',
    SESSION_TTL_SECONDS: '28800',
    TOKEN_ENCRYPTION_KEY: 'test-encryption-key-not-a-real-one',
    ADMIN_SUBJECTS: 'github:12345',
    DB: db,
  } as unknown as Env;
}

async function cookieFor(env: Env, subject: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const token = await signClaims(env.SESSION_SECRET, 'session', {
    provider: 'github',
    subject,
    sid: 'session-1',
    iat: now,
    exp: now + 28_800,
  });
  return `${SESSION_COOKIE}=${token}`;
}

async function me(env: Env, cookie: string) {
  const response = await worker.fetch(
    new Request(`${ORIGIN}/auth/me`, { headers: { Cookie: cookie } }),
    env,
  );
  return { response, body: (await response.json()) as Record<string, unknown> };
}

test('a privileged admin gets privileged plus the sealed login, and nothing else identifying', async () => {
  const key = 'test-encryption-key-not-a-real-one';
  const sealed = await seal(key, {
    accessToken: 'gho_test_token',
    refreshToken: null,
    accessExpiresAt: null,
    refreshExpiresAt: null,
    login: 'chris',
  });
  const env = envWith(dbWithToken('session-1', sealed));

  const { response, body } = await me(env, await cookieFor(env, '12345'));

  assert.equal(response.status, 200);
  assert.equal(body.admin, true);
  assert.equal(body.privileged, true);
  assert.equal(body.login, 'chris');
  assert.equal('email' in body, false, 'no email field exists at all');
});

test('a stored row that does not decrypt is not a privilege', async () => {
  // Sealed under a different key — a rotated TOKEN_ENCRYPTION_KEY at rest.
  const sealed = await seal('an-older-rotated-key', {
    accessToken: 'gho_test_token',
    refreshToken: null,
    accessExpiresAt: null,
    refreshExpiresAt: null,
    login: 'chris',
  });
  const env = envWith(dbWithToken('session-1', sealed));

  const { body } = await me(env, await cookieFor(env, '12345'));

  assert.equal(body.admin, true, 'still on the allowlist');
  assert.equal(body.privileged, false, 'but no action would reach GitHub');
  assert.equal(body.login, null);
});

test('an ordinary reader is authenticated, unprivileged, and unnamed', async () => {
  const env = envWith(dbWithToken('session-1', 'irrelevant'));

  const { body } = await me(env, await cookieFor(env, '999'));

  assert.equal(body.authenticated, true);
  assert.equal(body.admin, false);
  assert.equal(body.privileged, false);
  assert.equal(body.login, null);
});
