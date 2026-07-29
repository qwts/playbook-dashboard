import { signClaims, verifyClaims } from './crypto.ts';
import type { Env, Provider } from './env.ts';
import { isProvider, sessionTtlSeconds } from './env.ts';

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === 'string';
}

function unexpired(exp: unknown): boolean {
  return typeof exp === 'number' && exp > Math.floor(Date.now() / 1000);
}

/**
 * A signed payload is only a session if it carries every session claim.
 *
 * The purpose mixed into the HMAC already rejects a transaction token here;
 * this rejects one whose shape merely resembles a session — an absent `subject`
 * used to read as `undefined` and pass.
 */
function isSessionClaims(value: unknown): value is SessionClaims {
  if (!isRecord(value)) return false;
  return (
    isProvider(value.provider) &&
    typeof value.subject === 'string' &&
    value.subject.length > 0 &&
    isNullableString(value.login) &&
    isNullableString(value.email) &&
    typeof value.iat === 'number' &&
    typeof value.exp === 'number'
  );
}

function isOAuthTx(value: unknown): value is OAuthTx {
  if (!isRecord(value)) return false;
  return (
    isProvider(value.provider) &&
    typeof value.state === 'string' &&
    value.state.length > 0 &&
    typeof value.codeChallenge === 'string' &&
    value.codeChallenge.length > 0 &&
    typeof value.exp === 'number'
  );
}

export async function issueSession(
  env: Env,
  claims: Omit<SessionClaims, 'iat' | 'exp'>,
): Promise<{ token: string; maxAge: number }> {
  const now = Math.floor(Date.now() / 1000);
  const maxAge = sessionTtlSeconds(env);
  const token = await signClaims(env.SESSION_SECRET, 'session', {
    ...claims,
    iat: now,
    exp: now + maxAge,
  } satisfies SessionClaims);
  return { token, maxAge };
}

export async function readSession(env: Env, request: Request): Promise<SessionClaims | null> {
  const raw = parseCookies(request.headers.get('Cookie'))[SESSION_COOKIE];
  if (!raw) return null;

  const claims = await verifyClaims<unknown>(env.SESSION_SECRET, 'session', raw);
  if (!isSessionClaims(claims)) return null;
  if (!unexpired(claims.exp)) return null;
  return claims;
}

export async function issueTx(
  env: Env,
  tx: Omit<OAuthTx, 'exp'>,
): Promise<{ token: string; maxAge: number }> {
  const token = await signClaims(env.SESSION_SECRET, 'oauth_tx', {
    ...tx,
    exp: Math.floor(Date.now() / 1000) + TX_TTL_SECONDS,
  } satisfies OAuthTx);
  return { token, maxAge: TX_TTL_SECONDS };
}

export async function readTx(env: Env, request: Request): Promise<OAuthTx | null> {
  const raw = parseCookies(request.headers.get('Cookie'))[TX_COOKIE];
  if (!raw) return null;

  const tx = await verifyClaims<unknown>(env.SESSION_SECRET, 'oauth_tx', raw);
  if (!isOAuthTx(tx)) return null;
  if (!unexpired(tx.exp)) return null;
  return tx;
}
