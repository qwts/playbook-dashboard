/**
 * Page-side auth client.
 *
 * The service worker normally owns the OAuth return trip, but every path here
 * also works without it: IndexedDB is shared between page and worker, so the
 * page can create or spend a PKCE transaction on its own when no worker is
 * controlling the document.
 */

export type Provider = 'apple' | 'google' | 'github';

export type Session = {
  provider: Provider;
  /**
   * Only ever non-null for a privileged admin: the Worker keeps no display
   * fields for anyone else, so an ordinary session renders as just signed in.
   */
  login: string | null;
  expiresAt: number;
  /** On the Worker's allowlist, so the review panel may render at all. */
  admin: boolean;
  /**
   * An action would actually reach GitHub — admin, signed in with GitHub, and
   * holding a live actor token. Distinct from `admin` because an admin signed
   * in with Apple or Google is an admin who cannot act, and the panel should
   * say which of the two it is rather than fail on click.
   */
  privileged: boolean;
};

export type CallbackResult = {
  handled: boolean;
  error: string | null;
};

const DB_NAME = 'playbook-dashboard-auth';
const STORE_NAME = 'oauth';
const TX_KEY = 'pending';
const SW_REPLY_TIMEOUT_MS = 3_000;

type PendingTx = {
  provider: Provider;
  state: string;
  verifier: string;
  createdAt: number;
};

/** Local-only escape hatch so `npm run dev` works without the edge Worker. */
export const AUTH_DISABLED = import.meta.env.VITE_AUTH_DISABLED === '1';

export const PROVIDER_LABELS: Record<Provider, string> = {
  apple: 'Apple',
  google: 'Google',
  github: 'GitHub',
};

const ERROR_MESSAGES: Record<string, string> = {
  state_mismatch: 'Sign-in could not be verified. Try again.',
  pkce_mismatch: 'Sign-in could not be verified. Try again.',
  login_expired: 'Sign-in took too long. Try again.',
  exchange_failed: 'The identity provider rejected the sign-in.',
  provider_not_configured: 'That sign-in method is not configured yet.',
  missing_code: 'The identity provider did not return a sign-in code.',
  network_error: 'Network error during sign-in. Try again.',
  access_denied: 'Sign-in was cancelled.',
  user_cancelled_authorize: 'Sign-in was cancelled.',
};

export function describeAuthError(code: string | null): string | null {
  if (!code) return null;
  return ERROR_MESSAGES[code] ?? 'Sign-in failed. Try again.';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function writeTx(value: PendingTx): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).put(value, TX_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
}

async function takeTx(): Promise<PendingTx | null> {
  const db = await openDb();
  try {
    return await new Promise<PendingTx | null>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(TX_KEY);
      request.onsuccess = () => {
        store.delete(TX_KEY);
        resolve((request.result as PendingTx | undefined) ?? null);
      };
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

export async function registerAuthServiceWorker(): Promise<void> {
  if (AUTH_DISABLED || !('serviceWorker' in navigator)) return;
  try {
    await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  } catch {
    // Without a worker the page-side fallbacks still complete the flow.
  }
}

export async function fetchSession(): Promise<Session | null> {
  const response = await fetch('/auth/me', {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) return null;

  const payload = (await response.json().catch(() => null)) as
    | (Session & { authenticated?: boolean })
    | null;
  if (!payload?.authenticated) return null;

  return {
    provider: payload.provider,
    login: payload.login ?? null,
    expiresAt: payload.expiresAt,
    // Both default to false: a response that does not say you are privileged
    // is not a response that says you are.
    admin: payload.admin === true,
    privileged: payload.privileged === true,
  };
}

function requestLoginUrlFromWorker(
  controller: ServiceWorker,
  provider: Provider,
): Promise<string | null> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      cleanup();
      resolve(null);
    }, SW_REPLY_TIMEOUT_MS);

    function cleanup() {
      window.clearTimeout(timer);
      navigator.serviceWorker.removeEventListener('message', onMessage);
    }

    function onMessage(event: MessageEvent) {
      const data = event.data as { type?: string; url?: string } | null;
      if (data?.type === 'auth.redirect' && typeof data.url === 'string') {
        cleanup();
        resolve(data.url);
      }
    }

    navigator.serviceWorker.addEventListener('message', onMessage);
    controller.postMessage({ type: 'auth.start', provider });
  });
}

async function createLoginUrl(provider: Provider): Promise<string> {
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  const codeChallenge = await challengeFor(verifier);

  await writeTx({ provider, state, verifier, createdAt: Date.now() });

  const params = new URLSearchParams({
    provider,
    state,
    code_challenge: codeChallenge,
  });
  return `/auth/login?${params.toString()}`;
}

export async function beginLogin(provider: Provider): Promise<void> {
  const controller = navigator.serviceWorker?.controller ?? null;

  const url = controller
    ? ((await requestLoginUrlFromWorker(controller, provider)) ?? (await createLoginUrl(provider)))
    : await createLoginUrl(provider);

  window.location.assign(url);
}

async function exchangeOnPage(code: string, state: string): Promise<CallbackResult> {
  const pending = await takeTx().catch(() => null);
  if (!pending || pending.state !== state) {
    return { handled: true, error: 'state_mismatch' };
  }

  let response: Response;
  try {
    response = await fetch('/auth/exchange', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, state, code_verifier: pending.verifier }),
    });
  } catch {
    return { handled: true, error: 'network_error' };
  }

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    return { handled: true, error: payload?.error ?? 'exchange_failed' };
  }
  return { handled: true, error: null };
}

function readCallbackParams(): { code: string; state: string; error: string | null } | null {
  const fromQuery = new URLSearchParams(window.location.search);
  const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : '';
  const fromHash = new URLSearchParams(hash);

  const error = fromQuery.get('error') ?? fromHash.get('error');
  const code = fromQuery.get('code') ?? fromHash.get('code');
  const state = fromQuery.get('state') ?? fromHash.get('state');

  if (error) return { code: '', state: '', error };
  if (code && state) return { code, state, error: null };
  return null;
}

function clearCallbackUrl(): void {
  window.history.replaceState(null, '', '/');
}

/**
 * Completes a redirect back from the IdP. Normally the service worker has
 * already handled a query-mode callback, so this covers fragment responses,
 * uncontrolled first loads, and the `?auth_error=` landing.
 */
export async function consumeCallback(): Promise<CallbackResult> {
  if (AUTH_DISABLED) return { handled: false, error: null };

  const landingError = new URLSearchParams(window.location.search).get('auth_error');
  if (landingError) {
    clearCallbackUrl();
    return { handled: true, error: landingError };
  }

  const params = readCallbackParams();
  const onCallbackPath = window.location.pathname === '/auth/callback';
  if (!params || (!onCallbackPath && !window.location.hash.includes('code='))) {
    return { handled: false, error: null };
  }

  if (params.error) {
    clearCallbackUrl();
    return { handled: true, error: params.error };
  }

  const result = await exchangeOnPage(params.code, params.state);
  clearCallbackUrl();
  return result;
}

export async function logout(): Promise<void> {
  await fetch('/auth/logout', {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  }).catch(() => null);
}

export function onAuthRequired(handler: () => void): () => void {
  if (!('serviceWorker' in navigator)) return () => {};

  const onMessage = (event: MessageEvent) => {
    const data = event.data as { type?: string } | null;
    if (data?.type === 'auth.required') handler();
  };

  navigator.serviceWorker.addEventListener('message', onMessage);
  return () => navigator.serviceWorker.removeEventListener('message', onMessage);
}
