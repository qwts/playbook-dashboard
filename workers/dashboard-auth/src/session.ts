import { signClaims, verifyClaims } from './crypto';
import type { Env, Provider } from './env';
import { sessionTtlSeconds } from './env';

export const SESSION_COOKIE = 'dashboard_session';
export const TX_COOKIE = 'dashboard_oauth_tx';

/** Lifetime of an in-flight login (authorize redirect through code exchange). */
const TX_TTL_SECONDS = 600;

export type SessionClaims = {
  provider: Provider;
  subject: string;
  login: string | null;
  email: string | null;
  iat: number;
  exp: number;
};

/**
 * In-flight login state. The verifier itself never lands here — only its
 * challenge — so a stolen cookie cannot complete the exchange.
 */
export type OAuthTx = {
  provider: Provider;
  state: string;
  codeChallenge: string;
  exp: number;
};

type CookieOptions = {
  maxAge: number;
  secure: boolean;
};

export function parseCookies(header: string | null): Record<string, string> {
  const jar: Record<string, string> = {};
  if (!header) return jar;

  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) jar[name] = value;
  }
  return jar;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const attributes = [
    `${name}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${options.maxAge}`,
  ];
  if (options.secure) attributes.push('Secure');
  return attributes.join('; ');
}

export function clearCookie(name: string, secure: boolean): string {
  return serializeCookie(name, '', { maxAge: 0, secure });
}

export async function issueSession(
  env: Env,
  claims: Omit<SessionClaims, 'iat' | 'exp'>,
): Promise<{ token: string; maxAge: number }> {
  const now = Math.floor(Date.now() / 1000);
  const maxAge = sessionTtlSeconds(env);
  const token = await signClaims(env.SESSION_SECRET, {
    ...claims,
    iat: now,
    exp: now + maxAge,
  } satisfies SessionClaims);
  return { token, maxAge };
}

export async function readSession(env: Env, request: Request): Promise<SessionClaims | null> {
  const raw = parseCookies(request.headers.get('Cookie'))[SESSION_COOKIE];
  if (!raw) return null;

  const claims = await verifyClaims<SessionClaims>(env.SESSION_SECRET, raw);
  if (!claims) return null;
  if (typeof claims.exp !== 'number' || claims.exp <= Math.floor(Date.now() / 1000)) return null;
  return claims;
}

export async function issueTx(
  env: Env,
  tx: Omit<OAuthTx, 'exp'>,
): Promise<{ token: string; maxAge: number }> {
  const token = await signClaims(env.SESSION_SECRET, {
    ...tx,
    exp: Math.floor(Date.now() / 1000) + TX_TTL_SECONDS,
  } satisfies OAuthTx);
  return { token, maxAge: TX_TTL_SECONDS };
}

export async function readTx(env: Env, request: Request): Promise<OAuthTx | null> {
  const raw = parseCookies(request.headers.get('Cookie'))[TX_COOKIE];
  if (!raw) return null;

  const tx = await verifyClaims<OAuthTx>(env.SESSION_SECRET, raw);
  if (!tx) return null;
  if (typeof tx.exp !== 'number' || tx.exp <= Math.floor(Date.now() / 1000)) return null;
  return tx;
}
