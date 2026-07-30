/**
 * GitHub OAuth App provider.
 *
 * `read:user` is the smallest scope that resolves a stable login to show in the
 * session. The access token is used once, here, and never stored.
 */

import type { Env } from '../env.ts';
import { oauthErrorCode } from './oauth-error.ts';

const AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const TOKEN_URL = 'https://github.com/login/oauth/access_token';
const USER_URL = 'https://api.github.com/user';
const USER_AGENT = 'playbook-dashboard-auth';

type GitHubTokenResponse = {
  access_token?: string;
  error?: string;
  error_description?: string;
};

type GitHubUser = {
  id?: number;
  login?: string;
  email?: string | null;
};

export function buildGitHubAuthorizeUrl(
  env: Env,
  options: { state: string; codeChallenge: string; redirectUri: string },
): string {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('scope', 'read:user');
  url.searchParams.set('state', options.state);
  url.searchParams.set('code_challenge', options.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('allow_signup', 'true');
  return url.toString();
}

export async function exchangeGitHubCode(
  env: Env,
  options: { code: string; redirectUri: string; codeVerifier: string },
): Promise<{ subject: string; login: string; email: string | null }> {
  const tokenResponse = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': USER_AGENT,
    },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code: options.code,
      redirect_uri: options.redirectUri,
      code_verifier: options.codeVerifier,
    }),
  });

  const token = (await tokenResponse.json().catch(() => null)) as GitHubTokenResponse | null;
  if (!tokenResponse.ok || !token?.access_token) {
    // GitHub reports a bad client_id/secret as HTTP 200 with an `error` body,
    // so the status alone can read as success. The allowlisted code is the
    // diagnosable part; error_description and token material never propagate.
    const code = oauthErrorCode(token);
    throw new Error(
      `github token exchange failed (${tokenResponse.status}${code ? `, ${code}` : ''})`,
    );
  }

  const userResponse = await fetch(USER_URL, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token.access_token}`,
      'User-Agent': USER_AGENT,
    },
  });

  const user = (await userResponse.json().catch(() => null)) as GitHubUser | null;
  if (!userResponse.ok || !user?.login || typeof user.id !== 'number') {
    throw new Error(`github user lookup failed (${userResponse.status})`);
  }

  return { subject: String(user.id), login: user.login, email: user.email ?? null };
}
