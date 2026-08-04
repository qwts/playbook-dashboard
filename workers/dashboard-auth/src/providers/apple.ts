/**
 * Sign in with Apple (web).
 *
 * Apple's web flow is authorization-code, not implicit. No scope is requested,
 * which lets us use `response_mode=query` and keeps the callback a plain GET.
 * Identity comes from the `sub` claim of the returned id_token.
 */

import { decodeJwtPayload, signEs256Jwt } from '../crypto.ts';
import type { Env } from '../env.ts';
import { oauthErrorCode } from './oauth-error.ts';

const AUTHORIZE_URL = 'https://appleid.apple.com/auth/authorize';
const TOKEN_URL = 'https://appleid.apple.com/auth/token';
const ISSUER = 'https://appleid.apple.com';

/** Apple caps client-secret lifetime at six months; stay far below it. */
const CLIENT_SECRET_TTL_SECONDS = 3_600;

type AppleIdTokenClaims = {
  iss?: string;
  aud?: string;
  sub?: string;
  exp?: number;
};

type AppleTokenResponse = {
  id_token?: string;
  error?: string;
  error_description?: string;
};

export function buildAppleAuthorizeUrl(
  env: Env,
  options: { state: string; codeChallenge: string; redirectUri: string },
): string {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('client_id', env.APPLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('response_mode', 'query');
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

async function createClientSecret(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signEs256Jwt(
    env.APPLE_PRIVATE_KEY,
    { alg: 'ES256', kid: env.APPLE_KEY_ID, typ: 'JWT' },
    {
      iss: env.APPLE_TEAM_ID,
      iat: now,
      exp: now + CLIENT_SECRET_TTL_SECONDS,
      aud: ISSUER,
      sub: env.APPLE_CLIENT_ID,
    },
  );
}

export async function exchangeAppleCode(
  env: Env,
  options: { code: string; redirectUri: string; codeVerifier: string },
): Promise<{ subject: string }> {
  const body = new URLSearchParams({
    client_id: env.APPLE_CLIENT_ID,
    client_secret: await createClientSecret(env),
    code: options.code,
    grant_type: 'authorization_code',
    redirect_uri: options.redirectUri,
    code_verifier: options.codeVerifier,
  });

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  const payload = (await response.json().catch(() => null)) as AppleTokenResponse | null;
  if (!response.ok || !payload?.id_token) {
    const code = oauthErrorCode(payload);
    throw new Error(`apple token exchange failed (${response.status}${code ? `, ${code}` : ''})`);
  }

  // The id_token arrived directly from Apple over TLS, so the transport plus
  // the claim checks below stand in for JWKS signature verification.
  const claims = decodeJwtPayload<AppleIdTokenClaims>(payload.id_token);
  if (!claims?.sub) {
    throw new Error('apple id_token missing sub');
  }
  if (claims.iss !== ISSUER) {
    throw new Error('apple id_token issuer mismatch');
  }
  if (claims.aud !== env.APPLE_CLIENT_ID) {
    throw new Error('apple id_token audience mismatch');
  }
  if (typeof claims.exp === 'number' && claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('apple id_token expired');
  }

  return { subject: claims.sub };
}
