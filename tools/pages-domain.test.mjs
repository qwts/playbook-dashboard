import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

/**
 * The custom domain, asserted rather than assumed.
 *
 * `public/CNAME` is the whole of what tells GitHub Pages this site answers on a
 * custom domain, and a Pages deploy rewrites the repository setting from it. Two
 * separate protections hang off that one line:
 *
 *   - Pages redirects `qwts.github.io/playbook-dashboard/*` to the custom domain,
 *     and that redirect is the only reason the origin cannot serve the snapshot
 *     anonymously. Lose the custom domain and the redirect goes with it — the
 *     gated host keeps returning a reassuring 401 while the origin hands
 *     `/data/*` to anyone who asks for it by its `github.io` name.
 *   - The Worker route has to name the same host, or the Worker is in front of
 *     nothing and `/data/*` is never gated at all.
 *
 * Neither failure shows up in the dashboard, `npm run build` is happy either
 * way, and a squash merge has already dropped a change to this file once.
 */
const HOST = 'dashboard.qwts.org';

const CNAME = readFileSync(new URL('../public/CNAME', import.meta.url), 'utf8');
const WRANGLER = readFileSync(
  new URL('../workers/dashboard-auth/wrangler.toml', import.meta.url),
  'utf8',
);

test('the published site claims exactly one custom domain', () => {
  // Deliberately not `CNAME.trim() === HOST`. Pages reads the first line, so a
  // file that merely *contains* the host on some later line is not the same as
  // one that publishes it — and `trim()` cannot tell those apart. Worse, a
  // follow-up assertion on `CNAME.trim()` inherits the same blind spot, so two
  // assertions become one. Compare the bytes, and allow nothing beyond a single
  // trailing newline.
  assert.ok(
    CNAME === HOST || CNAME === `${HOST}\n`,
    `public/CNAME must be exactly "${HOST}" with an optional trailing newline; ` +
      `got ${JSON.stringify(CNAME)}. Leading blank lines, extra hosts, or stray ` +
      `whitespace can cost the custom domain, and with it the redirect that keeps ` +
      `the github.io origin from serving /data/* anonymously.`,
  );
});

test('the custom domain stays inside free Universal SSL coverage', () => {
  // Cloudflare's Universal SSL covers the apex and one label below it. A deeper
  // host (dashboard.dev.qwts.org) needs paid Advanced Certificate Manager, and
  // the failure mode is a TLS error in the browser, not a build failure.
  assert.equal(
    HOST.split('.').length,
    3,
    'one subdomain level only; deeper hosts need paid ACM',
  );
});

test('the Worker route covers the host the site is published on', () => {
  const pattern = WRANGLER.match(/^pattern\s*=\s*"([^"]+)"/m)?.[1];
  const zone = WRANGLER.match(/^zone_name\s*=\s*"([^"]+)"/m)?.[1];

  assert.equal(
    pattern,
    `${HOST}/*`,
    'the Worker must sit in front of the same host public/CNAME publishes',
  );
  assert.equal(zone, HOST.split('.').slice(-2).join('.'), 'route zone must be the registrable domain');
});
