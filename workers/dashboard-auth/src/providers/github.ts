/**
 * GitHub App user authorization ("user-to-server").
 *
 * Not an OAuth App, and the difference is the whole privileged design. There
 * is no `scope` parameter to request: what the returned token can do is the
 * intersection of the App's declared permissions, the repositories the App is
 * installed on, and what the signed-in person could already do themselves. It
 * expires in hours rather than never.
 *
 * For everyone who is not an allowlisted admin the token is still used exactly
 * once, here, to resolve a stable login, and then discarded.
 */

import type { Env } from '../env.ts';
import { oauthErrorCode } from './oauth-error.ts';

const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_URL = 'https://api.github.com/user';
export const USER_AGENT = 'playbook-dashboard-auth';

type GitHubTokenResponse = {
  access_token?: string;
  expires_in?: number;
  refresh_token?: string;
  refresh_token_expires_in?: number;
  error?: string;
  error_description?: string;
};

type GitHubUser = {
  id?: number;
  login?: string;
  email?: string | null;
};

/**
 * What the Worker keeps for an admin, and throws away for everyone else.
 *
 * Expiries are absolute seconds. Null means the App has "expire user
 * authorization tokens" turned off — the token still works, and the security
 * property that it stops working on its own is simply not there.
 */
export type UserToken = {
  accessToken: string;
  refreshToken: string | null;
  accessExpiresAt: number | null;
  refreshExpiresAt: number | null;
};

export function buildGitHubAuthorizeUrl(
  env: Env,
  options: { state: string; codeChallenge: string; redirectUri: string },
): string {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('allow_signup', 'true');
  return url.toString();
}

function expiryFrom(seconds: unknown, now: number): number | null {
  return typeof seconds === 'number' && Number.isFinite(seconds) && seconds > 0
    ? now + Math.floor(seconds)
    : null;
}

export function readUserToken(token: GitHubTokenResponse, now: number): UserToken | null {
  if (typeof token.access_token !== 'string' || !token.access_token) return null;
  return {
    accessToken: token.access_token,
    refreshToken: typeof token.refresh_token === 'string' ? token.refresh_token : null,
    accessExpiresAt: expiryFrom(token.expires_in, now),
    refreshExpiresAt: expiryFrom(token.refresh_token_expires_in, now),
  };
}

/**
 * `label` is a call-site constant, never a value from the request. Both grants
 * hit the same endpoint and fail the same way; without it a refresh failure is
 * indistinguishable from a sign-in failure in the only log that sees either.
 */
async function postToken(
  env: Env,
  label: 'exchange' | 'refresh',
  body: Record<string, string>,
): Promise<GitHubTokenResponse> {
  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': USER_AGENT,
    },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      ...body,
    }),
  });

  const token = (await response.json().catch(() => null)) as GitHubTokenResponse | null;
  if (!response.ok || !token?.access_token) {
    // GitHub reports a bad client_id/secret as HTTP 200 with an `error` body,
    // so the status alone can read as success. The allowlisted code is the
    // diagnosable part; error_description and token material never propagate.
    const code = oauthErrorCode(token);
    throw new Error(
      `github token ${label} failed (${response.status}${code ? `, ${code}` : ''})`,
    );
  }
  return token;
}

export async function exchangeGitHubCode(
  env: Env,
  options: { code: string; redirectUri: string; codeVerifier: string },
): Promise<{ subject: string; login: string; email: string | null; token: UserToken }> {
  const token = await postToken(env, 'exchange', {
    code: options.code,
    redirect_uri: options.redirectUri,
    code_verifier: options.codeVerifier,
  });

  const userToken = readUserToken(token, Math.floor(Date.now() / 1000));
  if (!userToken) throw new Error('github token response carried no access token');

  const userResponse = await fetch(USER_URL, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${userToken.accessToken}`,
      'User-Agent': USER_AGENT,
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  const user = (await userResponse.json().catch(() => null)) as GitHubUser | null;
  if (!userResponse.ok || !user?.login || typeof user.id !== 'number') {
    throw new Error(`github user lookup failed (${userResponse.status})`);
  }

  return {
    subject: String(user.id),
    login: user.login,
    email: user.email ?? null,
    token: userToken,
  };
}

/**
 * Spends the refresh token for a new pair.
 *
 * GitHub rotates the refresh token on every use, so the caller must persist
 * what comes back — a refresh whose result is dropped has spent a credential
 * and kept a stale one.
 */
export async function refreshGitHubToken(env: Env, refreshToken: string): Promise<UserToken> {
  const token = await postToken(env, 'refresh', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });

  const refreshed = readUserToken(token, Math.floor(Date.now() / 1000));
  if (!refreshed) throw new Error('github refresh response carried no access token');
  return refreshed;
}
