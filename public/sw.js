/**
 * Auth service worker.
 *
 * Owns the OAuth return trip and keeps snapshot fetches credentialed. It never
 * holds an IdP secret: the PKCE verifier lives in IndexedDB only between the
 * authorize redirect and the code exchange, and the session itself is an
 * HttpOnly cookie this script cannot read.
 *
 * Enforcement lives in the Worker. This script is UX plumbing and is assumed to
 * be bypassable.
 */

const DB_NAME = 'playbook-dashboard-auth';
const STORE_NAME = 'oauth';
const TX_KEY = 'pending';
/** Abandon a login that never came back. */
const TX_MAX_AGE_MS = 10 * 60 * 1000;

const PROVIDERS = ['apple', 'google', 'github'];

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function openDb() {
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

async function writeTx(value) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).put(value, TX_KEY);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
}

/** Reads and clears the pending transaction — a verifier is single-use. */
async function takeTx() {
  const db = await openDb();
  try {
    const value = await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(TX_KEY);
      request.onsuccess = () => {
        store.delete(TX_KEY);
        resolve(request.result ?? null);
      };
      request.onerror = () => reject(request.error);
    });
    return value;
  } finally {
    db.close();
  }
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase64Url(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

async function startLogin(provider, client) {
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(48);
  const codeChallenge = await challengeFor(verifier);

  await writeTx({ provider, state, verifier, createdAt: Date.now() });

  const url =
    `/auth/login?provider=${encodeURIComponent(provider)}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}`;

  if (client) {
    client.postMessage({ type: 'auth.redirect', url });
  }
}

async function exchange(code, state) {
  const pending = await takeTx().catch(() => null);

  if (!pending || pending.state !== state) {
    return { ok: false, error: 'state_mismatch' };
  }
  if (Date.now() - (pending.createdAt ?? 0) > TX_MAX_AGE_MS) {
    return { ok: false, error: 'login_expired' };
  }

  let response;
  try {
    response = await fetch('/auth/exchange', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, state, code_verifier: pending.verifier }),
    });
  } catch {
    return { ok: false, error: 'network_error' };
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    return { ok: false, error: payload?.error ?? `exchange_failed_${response.status}` };
  }
  return { ok: true, provider: payload?.provider ?? pending.provider };
}

function landingUrl(result) {
  return result.ok ? '/' : `/?auth_error=${encodeURIComponent(result.error)}`;
}

async function handleCallbackNavigation(url) {
  const denied = url.searchParams.get('error');
  if (denied) {
    return Response.redirect(`/?auth_error=${encodeURIComponent(denied)}`, 303);
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) {
    return Response.redirect('/?auth_error=missing_code', 303);
  }

  return Response.redirect(landingUrl(await exchange(code, state)), 303);
}

async function notifyClients(message) {
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const client of clients) {
    client.postMessage(message);
  }
}

function isGated(pathname) {
  return pathname === '/data' || pathname.startsWith('/data/');
}

async function gatedFetch(request) {
  const response = await fetch(new Request(request, { credentials: 'include' }));
  if (response.status === 401) {
    await notifyClients({ type: 'auth.required' });
  }
  return response;
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate' && url.pathname === '/auth/callback') {
    event.respondWith(handleCallbackNavigation(url));
    return;
  }

  if (isGated(url.pathname)) {
    event.respondWith(gatedFetch(request));
  }
});

self.addEventListener('message', (event) => {
  const data = event.data;
  if (!data || typeof data !== 'object') return;

  if (data.type === 'auth.start' && PROVIDERS.includes(data.provider)) {
    event.waitUntil(startLogin(data.provider, event.source));
    return;
  }

  // Fragment responses never reach the fetch handler, so the page forwards them.
  if (data.type === 'auth.callback' && data.code && data.state) {
    event.waitUntil(
      exchange(data.code, data.state).then((result) => {
        if (event.source) {
          event.source.postMessage({ type: 'auth.complete', ...result });
        }
      }),
    );
  }
});
