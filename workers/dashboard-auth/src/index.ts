/**
 * Edge auth gate for the playbook dashboard.
 *
 * Sits in front of the GitHub Pages origin on dashboard.dev.zts1.com and is the
 * only place that holds IdP secrets. The static shell stays public so the SPA
 * can render its own sign-in screen; the redacted snapshot under /data/* is
 * what actually requires a session. Any account that completes a sign-in with a
 * configured provider gets one — there are no roles or permissions.
 */

import { safeEqual, sha256Base64Url } from './crypto';
import type { Env, Provider } from './env';
import { isProvider } from './env';
import { buildAppleAuthorizeUrl, exchangeAppleCode } from './providers/apple';
import { buildGitHubAuthorizeUrl, exchangeGitHubCode } from './providers/github';
import { buildGoogleAuthorizeUrl, exchangeGoogleCode } from './providers/google';
import {
  SESSION_COOKIE,
  TX_COOKIE,
  clearCookie,
  issueSession,
  issueTx,
  readSession,
  readTx,
  serializeCookie,
} from './session';

type Identity = {
  subject: string;
  login: string | null;
  email: string | null;
};

type ExchangeBody = {
  code?: unknown;
  state?: unknown;
  code_verifier?: unknown;
};

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  for (const [name, value] of Object.entries(JSON_HEADERS)) {
    if (!headers.has(name)) headers.set(name, value);
  }
  return new Response(JSON.stringify(body), { ...init, headers });
}

function isSecure(url: URL): boolean {
  return url.protocol === 'https:';
}

function redirectUriFor(url: URL): string {
  return `${url.origin}/auth/callback`;
}

function isGatedPath(pathname: string): boolean {
  return pathname === '/data' || pathname.startsWith('/data/');
}

function originTarget(env: Env, url: URL, pathname = url.pathname): string {
  if (!env.PAGES_ORIGIN) {
    // Empty means "same hostname": the subrequest reaches the zone origin
    // (GitHub Pages) rather than re-entering this Worker.
    return `${url.origin}${pathname}${url.search}`;
  }
  const base = new URL(env.PAGES_ORIGIN);
  return new URL(`${pathname}${url.search}`, base).toString();
}

async function fetchOrigin(env: Env, request: Request, url: URL, pathname?: string) {
  const headers = new Headers(request.headers);
  // Never forward dashboard cookies to the static origin.
  headers.delete('Cookie');

  const upstream = await fetch(originTarget(env, url, pathname), {
    method: request.method === 'HEAD' ? 'HEAD' : 'GET',
    headers,
    redirect: 'manual',
  });

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: new Headers(upstream.headers),
  });
}

function providerConfigured(env: Env, provider: Provider): boolean {
  if (provider === 'apple') {
    return Boolean(
      env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID && env.APPLE_KEY_ID && env.APPLE_PRIVATE_KEY,
    );
  }
  if (provider === 'google') {
    return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
  }
  return Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

async function handleLogin(env: Env, url: URL): Promise<Response> {
  const provider = url.searchParams.get('provider');
  const state = url.searchParams.get('state');
  const codeChallenge = url.searchParams.get('code_challenge');

  if (!isProvider(provider)) {
    return json({ error: 'unsupported_provider' }, { status: 400 });
  }
  if (!state || state.length < 16 || !codeChallenge || codeChallenge.length < 16) {
    return json({ error: 'invalid_login_request' }, { status: 400 });
  }
  if (!providerConfigured(env, provider)) {
    return json({ error: 'provider_not_configured', provider }, { status: 503 });
  }

  const redirectUri = redirectUriFor(url);
  const authorizeOptions = { state, codeChallenge, redirectUri };
  const authorizeUrl =
    provider === 'apple'
      ? buildAppleAuthorizeUrl(env, authorizeOptions)
      : provider === 'google'
        ? buildGoogleAuthorizeUrl(env, authorizeOptions)
        : buildGitHubAuthorizeUrl(env, authorizeOptions);

  const tx = await issueTx(env, { provider, state, codeChallenge });

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl,
      'Cache-Control': 'no-store',
      'Set-Cookie': serializeCookie(TX_COOKIE, tx.token, {
        maxAge: tx.maxAge,
        secure: isSecure(url),
      }),
    },
  });
}

async function handleExchange(env: Env, request: Request, url: URL): Promise<Response> {
  const body = (await request.json().catch(() => null)) as ExchangeBody | null;
  const code = typeof body?.code === 'string' ? body.code : '';
  const state = typeof body?.state === 'string' ? body.state : '';
  const codeVerifier = typeof body?.code_verifier === 'string' ? body.code_verifier : '';

  if (!code || !state || !codeVerifier) {
    return json({ error: 'invalid_exchange_request' }, { status: 400 });
  }

  const tx = await readTx(env, request);
  if (!tx) {
    return json({ error: 'login_expired' }, { status: 400 });
  }
  if (!safeEqual(tx.state, state)) {
    return json({ error: 'state_mismatch' }, { status: 400 });
  }
  // Apple and GitHub OAuth Apps do not enforce PKCE themselves, so bind the
  // challenge to the verifier here before spending the code.
  if (!safeEqual(tx.codeChallenge, await sha256Base64Url(codeVerifier))) {
    return json({ error: 'pkce_mismatch' }, { status: 400 });
  }

  const secure = isSecure(url);
  const clearTx = clearCookie(TX_COOKIE, secure);
  const redirectUri = redirectUriFor(url);

  let identity: Identity;
  try {
    if (tx.provider === 'apple') {
      const result = await exchangeAppleCode(env, { code, redirectUri, codeVerifier });
      identity = { subject: result.subject, login: null, email: result.email };
    } else if (tx.provider === 'google') {
      const result = await exchangeGoogleCode(env, { code, redirectUri, codeVerifier });
      identity = { subject: result.subject, login: null, email: result.email };
    } else {
      const result = await exchangeGitHubCode(env, { code, redirectUri, codeVerifier });
      identity = { subject: result.subject, login: result.login, email: result.email };
    }
  } catch {
    return json({ error: 'exchange_failed' }, { status: 502, headers: { 'Set-Cookie': clearTx } });
  }

  const session = await issueSession(env, {
    provider: tx.provider,
    subject: identity.subject,
    login: identity.login,
    email: identity.email,
  });

  const headers = new Headers(JSON_HEADERS);
  headers.append('Set-Cookie', clearTx);
  headers.append(
    'Set-Cookie',
    serializeCookie(SESSION_COOKIE, session.token, { maxAge: session.maxAge, secure }),
  );

  return new Response(
    JSON.stringify({
      ok: true,
      provider: tx.provider,
      login: identity.login,
      email: identity.email,
    }),
    { status: 200, headers },
  );
}

async function handleMe(env: Env, request: Request): Promise<Response> {
  const session = await readSession(env, request);
  if (!session) {
    return json({ authenticated: false }, { status: 401, headers: { Vary: 'Cookie' } });
  }

  return json(
    {
      authenticated: true,
      provider: session.provider,
      login: session.login,
      email: session.email,
      expiresAt: session.exp,
    },
    { headers: { Vary: 'Cookie' } },
  );
}

function handleLogout(request: Request, url: URL): Response {
  const cookie = clearCookie(SESSION_COOKIE, isSecure(url));

  if ((request.headers.get('Accept') ?? '').includes('text/html')) {
    return new Response(null, {
      status: 302,
      headers: { Location: '/', 'Cache-Control': 'no-store', 'Set-Cookie': cookie },
    });
  }

  return json({ ok: true }, { headers: { 'Set-Cookie': cookie } });
}

async function handleGatedData(env: Env, request: Request, url: URL): Promise<Response> {
  const session = await readSession(env, request);
  if (!session) {
    return json({ error: 'authentication_required' }, { status: 401, headers: { Vary: 'Cookie' } });
  }

  const response = await fetchOrigin(env, request, url);
  response.headers.set('Cache-Control', 'private, no-store');
  response.headers.set('Vary', 'Cookie');
  return response;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (pathname === '/auth/login' && request.method === 'GET') {
      return handleLogin(env, url);
    }
    if (pathname === '/auth/exchange' && request.method === 'POST') {
      return handleExchange(env, request, url);
    }
    if (pathname === '/auth/me' && request.method === 'GET') {
      return handleMe(env, request);
    }
    if (pathname === '/auth/logout') {
      return handleLogout(request, url);
    }
    if (pathname.startsWith('/auth/')) {
      // /auth/callback and anything else under /auth render the SPA shell, which
      // finishes the exchange client-side.
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json({ error: 'method_not_allowed' }, { status: 405 });
      }
      const shell = await fetchOrigin(env, request, url, '/index.html');
      shell.headers.set('Cache-Control', 'no-store');
      return shell;
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return json({ error: 'method_not_allowed' }, { status: 405 });
    }

    if (isGatedPath(pathname)) {
      return handleGatedData(env, request, url);
    }

    return fetchOrigin(env, request, url);
  },
} satisfies ExportedHandler<Env>;
