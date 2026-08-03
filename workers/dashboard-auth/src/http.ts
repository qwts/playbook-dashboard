/**
 * Response helpers shared by the auth routes and the privileged routes.
 *
 * `no-store` is the default rather than an option: every response this Worker
 * composes itself is either about a session or about live GitHub state, and
 * neither belongs in a cache.
 */

export const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

export function json(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  for (const [name, value] of Object.entries(JSON_HEADERS)) {
    if (!headers.has(name)) headers.set(name, value);
  }
  return new Response(JSON.stringify(body), { ...init, headers });
}

/** A privileged response: private to one session, never cached, never shared. */
export function privateJson(body: unknown, init: ResponseInit = {}): Response {
  const response = json(body, init);
  response.headers.set('Cache-Control', 'private, no-store');
  response.headers.set('Vary', 'Cookie');
  return response;
}
