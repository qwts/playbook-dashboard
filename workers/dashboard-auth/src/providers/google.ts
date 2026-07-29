/**
 * Google Sign-In (OAuth 2.0 / OpenID Connect web flow).
 *
 * Authorization code with PKCE — Google enforces the challenge/verifier binding
 * itself, and the Worker re-checks it before spending the code. Identity comes
 * from the `sub` claim of the returned id_token.
 */

import { decodeJwtPayload } from '../crypto.ts';
import type { Env } from '../env.ts';

const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
/** Google mints id_tokens under either spelling of its issuer. */
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

type GoogleIdTokenClaims = {
  iss?: string;
  aud?: string;
  sub?: string;
  exp?: number;
  email?: string;
};

type GoogleTokenResponse = {
  id_token?: string;
  error?: string;
  error_description?: string;
};

export function buildGoogleAuthorizeUrl(
  env: Env,
  options: { state: string; codeChallenge: string; redirectUri: string },
): string {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('response_type', 'code');
  // `openid email` is the smallest scope that yields a stable subject.
  url.searchParams.set('scope', 'openid email');
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('prompt', 'select_account');
  return url.toString();
}

export async function exchangeGoogleCode(
  env: Env,
  options: { code: string; redirectUri: string; codeVerifier: string },
): Promise<{ subject: string; email: string | null }> {
  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code: options.code,
      grant_type: 'authorization_code',
      redirect_uri: options.redirectUri,
      code_verifier: options.codeVerifier,
    }),
  });

  const payload = (await response.json().catch(() => null)) as GoogleTokenResponse | null;
  if (!response.ok || !payload?.id_token) {
    throw new Error(`google token exchange failed (${response.status})`);
  }

  // The id_token arrived directly from Google over TLS, so the transport plus
  // the claim checks below stand in for JWKS signature verification.
  const claims = decodeJwtPayload<GoogleIdTokenClaims>(payload.id_token);
  if (!claims?.sub) {
    throw new Error('google id_token missing sub');
  }
  if (!claims.iss || !ISSUERS.includes(claims.iss)) {
    throw new Error('google id_token issuer mismatch');
  }
  if (claims.aud !== env.GOOGLE_CLIENT_ID) {
    throw new Error('google id_token audience mismatch');
  }
  if (typeof claims.exp === 'number' && claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('google id_token expired');
  }

  return { subject: claims.sub, email: claims.email ?? null };
}
