import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { test } from 'node:test';

/**
 * The page's trust boundary, asserted rather than reviewed.
 *
 * A third-party origin re-enters this page the same way it left: one `<link>`
 * in a diff that is about something else. Nothing about the build fails when
 * that happens — the page renders fine, which is the problem.
 */
const HTML = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const CSS = ['../src/styles.css', '../src/fonts.css']
  .map((rel) => readFileSync(new URL(rel, import.meta.url), 'utf8'))
  .join('\n');

/** Comments explain the policy and quote parts of it; they are not the policy. */
const MARKUP = HTML.replace(/<!--[\s\S]*?-->/gu, '');

function policy() {
  const match = MARKUP.match(
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/u,
  );
  assert.ok(match, 'no Content-Security-Policy meta element');
  return Object.fromEntries(
    match[1]
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const [name, ...values] = part.split(/\s+/u);
        return [name, values];
      }),
  );
}

test('the page carries a policy with no escape hatches', () => {
  const directives = policy();

  for (const escape of ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", '*']) {
    assert.doesNotMatch(
      JSON.stringify(directives),
      new RegExp(escape.replace(/[*]/u, '\\*'), 'u'),
      `${escape} defeats the policy`,
    );
  }
});

test('every directive that matters is stated, not left to fall back', () => {
  const directives = policy();

  // default-src covers most of these, but a later allowance to default-src
  // would silently widen everything that inherits from it.
  for (const [name, expected] of [
    ['default-src', ["'self'"]],
    ['script-src', ["'self'"]],
    ['style-src', ["'self'"]],
    ['font-src', ["'self'"]],
    ['connect-src', ["'self'"]],
    ['base-uri', ["'none'"]],
    ['form-action', ["'none'"]],
    ['object-src', ["'none'"]],
  ]) {
    assert.deepEqual(directives[name], expected, `${name} must be exactly ${expected.join(' ')}`);
  }
});

// The exit criterion — zero requests to non-self origins — verified in a real
// browser against the built page (four requests, all same-origin, no console
// output). This is the assertion that keeps it true afterwards.
test('the page loads nothing from another origin', () => {
  const external = [...MARKUP.matchAll(/(?:href|src)\s*=\s*"([^"]+)"/gu)]
    .map((m) => m[1])
    .filter((value) => /^(?:[a-z][\w+.-]*:)?\/\//iu.test(value));

  assert.deepEqual(external, [], 'a resource is loaded from outside this origin');
});

test('no preconnect or prefetch survives to leak a visit', () => {
  // preconnect discloses the reader to the third party before any resource is
  // requested, and outlives deleting the stylesheet it was added for.
  assert.doesNotMatch(MARKUP, /rel="(?:preconnect|dns-prefetch|prefetch|preload)"/u);
});

test('the stylesheet pulls in nothing external either', () => {
  const urls = [...CSS.matchAll(/url\(\s*['"]?([^'")]+)/gu)].map((m) => m[1]);
  for (const url of urls) {
    assert.doesNotMatch(url, /^(?:[a-z][\w+.-]*:)?\/\//iu, `${url} is an external stylesheet asset`);
  }
  assert.doesNotMatch(CSS, /@import/u, '@import can reach another origin without a <link>');
});

test('the page sends no referrer', () => {
  assert.match(MARKUP, /<meta\s+name="referrer"\s+content="no-referrer"\s*\/>/u);
});

// frame-ancestors is ignored in a meta-delivered policy, and Pages cannot set a
// response header. Stating it here would read as clickjacking protection while
// providing none — the failure mode this repo exists to avoid.
test('the policy does not claim protection a meta element cannot deliver', () => {
  const directives = policy();
  for (const inert of ['frame-ancestors', 'report-uri', 'sandbox']) {
    assert.equal(directives[inert], undefined, `${inert} is ignored in a meta policy`);
  }
});

// Self-hosting is the whole fix; a face that quietly points back at a CDN would
// restore the original defect while every other assertion here still passed.
test('every font face is served from this origin', () => {
  const faces = [...CSS.matchAll(/@font-face\s*\{([^}]*)\}/gu)].map((m) => m[1]);
  assert.ok(faces.length >= 7, `expected the vendored faces, found ${faces.length}`);

  for (const face of faces) {
    const src = face.match(/src:\s*url\(\s*['"]?([^'")]+)/u);
    assert.ok(src, `a @font-face has no src:\n${face}`);
    assert.match(src[1], /^\/fonts\//u, `${src[1]} is not served from this origin`);
    assert.match(face, /font-display:\s*swap/u, 'text must paint before the font arrives');
  }
});

test('every referenced font file is actually vendored', () => {
  const referenced = [...CSS.matchAll(/url\(\s*['"]?\/fonts\/([^'")]+)/gu)].map((m) => m[1]);
  assert.ok(referenced.length > 0, 'no font files are referenced');

  const present = new Set(readdirSync(new URL('../public/fonts/', import.meta.url)));
  for (const file of referenced) {
    assert.ok(present.has(file), `${file} is referenced but missing from public/fonts/`);
  }
});

// U+2265 is in the Pi subset, not Latin1, and `openSecurityLabel` renders "≥6"
// for a partially-read total. Shipping Latin1 alone renders that one glyph in a
// fallback face — in the security label, which is the worst place for
// typography to look broken. Verified in a browser: forcing an unknown count
// pulled exactly the two Pi files whose faces render it, and no others.
//
// Containment, not substring matching: U+2265 appears in the declarations only
// as part of `U+2264-2265`, and U+00B7 only inside `U+00A0-00FF`. Grepping for
// the codepoint reports both as missing, which is how the first version of this
// test failed against fonts that were perfectly correct.
function rangesOf(declaration) {
  const ranges = [];
  for (const [, list] of declaration.matchAll(/unicode-range:\s*([^;}]+)/gu)) {
    for (const entry of list.split(',')) {
      const range = entry.trim().match(/^U\+([0-9a-f]+)(?:-([0-9a-f]+))?$/iu);
      if (!range) continue;
      const from = Number.parseInt(range[1], 16);
      ranges.push([from, range[2] ? Number.parseInt(range[2], 16) : from]);
    }
  }
  return ranges;
}

/** Ranges unioned per family *and weight*, which is the granularity that renders. */
function coverageByFace() {
  const faces = new Map();
  for (const [, body] of CSS.matchAll(/@font-face\s*\{([^}]*)\}/gu)) {
    const family = body.match(/font-family:\s*'([^']+)'/u)?.[1];
    const weight = body.match(/font-weight:\s*(\d+)/u)?.[1];
    assert.ok(family && weight, `@font-face without a family and weight:\n${body}`);
    const key = `${family} ${weight}`;
    faces.set(key, (faces.get(key) ?? []).concat(rangesOf(body)));
  }
  return faces;
}

test('the subsets cover every character the page can render', () => {
  const faces = coverageByFace();
  assert.ok(faces.size >= 7, `expected the vendored faces, found ${faces.size}`);

  // Per face, not across all of them. A global check passes while one weight
  // renders the glyph and another falls back — which is precisely the bug,
  // since the headline total and the table cell are different weights.
  for (const [face, ranges] of faces) {
    for (const [char, label] of [
      ['\u2265', 'a partially-read security total, e.g. "\u22656"'],
      ['\u2014', 'the em dash used for an absent value'],
      ['\u00b7', 'the separator in the status line'],
      ['?', 'a total that could not be read at all'],
    ]) {
      const code = char.codePointAt(0);
      assert.ok(
        ranges.some(([from, to]) => code >= from && code <= to),
        `${face} does not cover U+${code.toString(16).toUpperCase().padStart(4, '0')} (${label}), so that glyph falls back to another face`,
      );
    }
  }
});
