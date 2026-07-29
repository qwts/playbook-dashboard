import assert from 'node:assert/strict';
import { test } from 'node:test';
import { signClaims } from './crypto.ts';
import type { Env, Provider } from './env.ts';
import {
  SESSION_COOKIE,
  TX_COOKIE,
  issueSession,
  issueTx,
  readSession,
  readTx,
} from './session.ts';

/**
 * Both cookies are signed with the same SESSION_SECRET, which is the whole
 * reason these tests exist.
 *
 * `/auth/login` hands a signed transaction token to any unauthenticated caller.
 * When the two token kinds were interchangeable, replaying that token under the
 * session cookie name was a complete bypass of the gate: HMAC valid, `exp` in
 * the future, `subject` merely absent — and `/data/*` served the snapshot.
 */
const ENV = {
  SESSION_SECRET: 'test-secret-not-a-real-one',
  SESSION_TTL_SECONDS: '28800',
} as Env;

function withCookie(name: string, value: string): Request {
  return new Request('https://dashboard.invalid/data/snapshot.json', {
    headers: { Cookie: `${name}=${value}` },
  });
}

const IDENTITY = {
  provider: 'github',
  subject: '12345',
  login: 'someone',
  email: null,
} as const;

test('a login transaction token is not a session', async () => {
  const tx = await issueTx(ENV, {
    provider: 'github',
    state: 'a'.repeat(32),
    codeChallenge: 'b'.repeat(43),
  });

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, tx.token)), null);
});

test('a session token is not a login transaction', async () => {
  const session = await issueSession(ENV, IDENTITY);

  assert.equal(await readTx(ENV, withCookie(TX_COOKIE, session.token)), null);
});

test('a real session still round-trips', async () => {
  const session = await issueSession(ENV, IDENTITY);
  const claims = await readSession(ENV, withCookie(SESSION_COOKIE, session.token));

  assert.equal(claims?.provider, 'github');
  assert.equal(claims?.subject, '12345');
  assert.equal(claims?.login, 'someone');
  assert.equal(claims?.email, null);
});

test('a real login transaction still round-trips', async () => {
  const tx = await issueTx(ENV, {
    provider: 'apple',
    state: 'a'.repeat(32),
    codeChallenge: 'b'.repeat(43),
  });
  const claims = await readTx(ENV, withCookie(TX_COOKIE, tx.token));

  assert.equal(claims?.provider, 'apple');
  assert.equal(claims?.state, 'a'.repeat(32));
});

// The purpose is mixed into the HMAC, so this is already dead — but a session
// missing `subject` used to read as `undefined` and pass every check.
test('a signed payload missing session claims is rejected', async () => {
  const forged = await issueSession(ENV, { ...IDENTITY, subject: '' });

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, forged.token)), null);
});

test('an unknown provider is rejected even when the signature is good', async () => {
  const forged = await issueSession(ENV, {
    ...IDENTITY,
    provider: 'gitlab' as unknown as Provider,
  });

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, forged.token)), null);
});

test('a token signed with another secret is rejected', async () => {
  const session = await issueSession({ ...ENV, SESSION_SECRET: 'a different secret' }, IDENTITY);

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, session.token)), null);
});

test('an expired session is rejected', async () => {
  const past = Math.floor(Date.now() / 1000) - 1;
  const expired = await signClaims(ENV.SESSION_SECRET, 'session', {
    ...IDENTITY,
    iat: past - 60,
    exp: past,
  });

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, expired)), null);
});

test('a tampered payload is rejected', async () => {
  const session = await issueSession(ENV, IDENTITY);
  const [payload, signature] = session.token.split('.');
  const swapped = `${payload.slice(0, -1)}${payload.at(-1) === 'A' ? 'B' : 'A'}.${signature}`;

  assert.equal(await readSession(ENV, withCookie(SESSION_COOKIE, swapped)), null);
});

test('no cookie is not a session', async () => {
  const bare = new Request('https://dashboard.invalid/data/snapshot.json');

  assert.equal(await readSession(ENV, bare), null);
});
