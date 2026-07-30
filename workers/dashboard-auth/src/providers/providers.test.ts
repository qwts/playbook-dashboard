import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import type { Env } from '../env.ts';
import { exchangeGitHubCode } from './github.ts';
import { exchangeGoogleCode } from './google.ts';
import { oauthErrorCode } from './oauth-error.ts';

/**
 * The providers call global `fetch` directly, so the token endpoint is stubbed
 * here. Only the token-exchange failure path is exercised — success paths need
 * live IdPs and are covered by the deployed flow.
 */

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

function stubTokenEndpoint(status: number, body: unknown) {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as typeof fetch;
}

const env = {
  GITHUB_CLIENT_ID: 'client-id',
  GITHUB_CLIENT_SECRET: 'client-secret',
  GOOGLE_CLIENT_ID: 'client-id',
  GOOGLE_CLIENT_SECRET: 'client-secret',
} as Env;

const options = { code: 'code', redirectUri: 'https://example.test/cb', codeVerifier: 'v' };

test('a 200 with an error body surfaces the OAuth error code, not success', async () => {
  // GitHub answers a bad client secret with HTTP 200 and an `error` field —
  // the exact shape that made the bad-client-secret incident slow to diagnose
  // when only the status was reported.
  stubTokenEndpoint(200, { error: 'incorrect_client_credentials' });

  await assert.rejects(
    exchangeGitHubCode(env, options),
    /github token exchange failed \(200, incorrect_client_credentials\)/,
  );
});

test('an unlisted error code is reported as unrecognized, never echoed', async () => {
  // `error` in an untrusted response body is free text until proven
  // otherwise: only allowlisted spec codes may reach a log line.
  const hostile = '<img src=x onerror=alert(1)>';
  stubTokenEndpoint(200, { error: hostile });

  await assert.rejects(exchangeGitHubCode(env, options), (error: Error) => {
    assert.match(error.message, /unrecognized_error/);
    assert.ok(!error.message.includes(hostile));
    return true;
  });
});

test('error_description never reaches the thrown message', async () => {
  stubTokenEndpoint(400, {
    error: 'invalid_grant',
    error_description: 'secret-adjacent prose that must not be logged',
  });

  await assert.rejects(exchangeGoogleCode(env, options), (error: Error) => {
    assert.match(error.message, /google token exchange failed \(400, invalid_grant\)/);
    assert.ok(!error.message.includes('prose'));
    return true;
  });
});

test('a failure without a parseable error body keeps the status-only message', async () => {
  stubTokenEndpoint(502, {});

  await assert.rejects(
    exchangeGitHubCode(env, options),
    /github token exchange failed \(502\)$/,
  );
});

test('the code helper is a closed enum with a null resting state', () => {
  assert.equal(oauthErrorCode({ error: 'bad_verification_code' }), 'bad_verification_code');
  assert.equal(oauthErrorCode({ error: 'anything else' }), 'unrecognized_error');
  assert.equal(oauthErrorCode({ error: '' }), null);
  assert.equal(oauthErrorCode({ error: 42 }), null);
  assert.equal(oauthErrorCode({}), null);
  assert.equal(oauthErrorCode(null), null);
});
