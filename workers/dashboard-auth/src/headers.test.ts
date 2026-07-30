import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { applySecurityHeaders } from './index.ts';

test('every hardening header is present on a response that leaves the Worker', () => {
  const response = applySecurityHeaders(new Response('ok'));

  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(response.headers.get('Strict-Transport-Security'), 'max-age=31536000');

  const csp = response.headers.get('Content-Security-Policy');
  assert.ok(csp);
  // The one directive the index.html meta CSP cannot express — the reason the
  // header exists at all.
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /default-src 'self'/);
});

test('hardening preserves unrelated headers but overwrites a stale policy', () => {
  const response = applySecurityHeaders(
    new Response(null, {
      status: 302,
      headers: {
        Location: '/',
        'Cache-Control': 'no-store',
        'Set-Cookie': 'session=x; HttpOnly',
        // An origin-supplied policy must not survive: the Worker's is canonical.
        'Content-Security-Policy': 'default-src *',
      },
    }),
  );

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('Location'), '/');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('Set-Cookie'), 'session=x; HttpOnly');
  assert.notEqual(response.headers.get('Content-Security-Policy'), 'default-src *');
  assert.match(response.headers.get('Content-Security-Policy') ?? '', /frame-ancestors 'none'/);
});

test('the header CSP and the index.html meta CSP agree', () => {
  // Two copies of a policy drift; this pins them to each other. The header may
  // only add what a meta CSP cannot express (frame-ancestors).
  const html = readFileSync(new URL('../../../index.html', import.meta.url), 'utf8');
  const meta = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)?.[1];
  assert.ok(meta, 'index.html carries a meta CSP');

  const header = applySecurityHeaders(new Response('ok')).headers.get('Content-Security-Policy');
  assert.equal(header, `${meta}; frame-ancestors 'none'`);
});

test('the fetch export funnels every response through applySecurityHeaders', () => {
  // Source assertion, workflows.test.mjs style: the routing must stay behind
  // the single wrapped exit. Eighteen return sites is eighteen chances to
  // forget a header; this keeps it at one.
  const source = readFileSync(new URL('./index.ts', import.meta.url), 'utf8');
  assert.match(source, /return applySecurityHeaders\(\s*await route\(request,\s*env\)\s*,?\s*\)/);

  const fetchBody = source.match(/async fetch\s*\([^)]*\)[^{]*\{([\s\S]*?)\n\s*\},/)?.[1];
  assert.ok(fetchBody, 'fetch export found');
  const returns = fetchBody.match(/^\s*return /gm) ?? [];
  assert.equal(returns.length, 1, 'fetch has exactly one return statement, the wrapped one');
});
