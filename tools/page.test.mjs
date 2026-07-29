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

/**
 * The page's tags, with comments skipped. Comments explain the policy and quote
 * parts of it; they are not the policy.
 *
 * Deliberately not `HTML.replace(/<!--[\s\S]*?-->/g, '')`. Removing a matched
 * sequence can reintroduce the delimiter it removed — `<!--<!-- -->-->` leaves a
 * stray `-->` behind — so a crafted comment could hide a real <link> from every
 * assertion below, turning these guards off without touching them. CodeQL
 * flagged exactly that (js/incomplete-multi-character-sanitization), and it was
 * right: a security check that a comment can disable is not a check.
 *
 * A single left-to-right pass cannot be re-entered, because each character is
 * consumed once. Quoted attribute values are tracked so a `>` inside `content="…"`
 * does not end a tag early.
 */
function markupOnly(html) {
  const tags = [];
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt === -1) break;
    if (html.startsWith('<!--', lt)) {
      // HTML5 says `<!-->` and `<!--->` are complete, empty comments. Anything
      // that instead scans forward for a full `-->` swallows every tag until
      // the *next* comment closes — so `<!--><link href="https://elsewhere">`
      // followed by any ordinary comment hides a link the browser loads. That
      // is the bypass direction that matters here, and the naive regex and my
      // first scanner both had it.
      if (html.startsWith('<!-->', lt)) {
        i = lt + 5;
        continue;
      }
      if (html.startsWith('<!--->', lt)) {
        i = lt + 6;
        continue;
      }
      // Two closers, not one: the parser's comment-end-bang state means `--!>`
      // ends a comment exactly as `-->` does. A scan that only stops at `-->`
      // sails past `--!>` to the close of the *next* ordinary comment, and
      // everything in between — live markup, to the browser — is swallowed.
      // Same bypass shape as the empty comments above, one state further in.
      const closers = [
        [html.indexOf('-->', lt + 4), 3],
        [html.indexOf('--!>', lt + 4), 4],
      ].filter(([at]) => at !== -1);
      if (closers.length === 0) break;
      const [at, len] = closers.reduce((a, b) => (a[0] <= b[0] ? a : b));
      i = at + len;
      continue;
    }
    let j = lt + 1;
    let quote = null;
    while (j < html.length) {
      const ch = html[j];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '>') {
        break;
      }
      j += 1;
    }
    if (j >= html.length) break;
    tags.push(html.slice(lt, j + 1));
    i = j + 1;
  }
  return tags.join('\n');
}

const MARKUP = markupOnly(HTML);

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

  // Substring containment, not a constructed RegExp: escaping the metacharacters
  // of a value in order to search for it literally is a step with nothing to
  // gain and a way to be wrong (CodeQL: js/incomplete-sanitization, since
  // `.replace` without /g escaped only the first `*`).
  const stated = Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(' ')}`)
    .join('; ');

  for (const escape of ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", '*']) {
    assert.ok(!stated.includes(escape), `${escape} defeats the policy: ${stated}`);
  }

  // `data:` is a fetchable scheme, so it belongs nowhere a fetch could execute
  // or exfiltrate. It is allowed in img-src alone, where the worst case is a
  // rendered image, and where Vite may inline a small asset.
  for (const [name, values] of Object.entries(directives)) {
    if (name === 'img-src') continue;
    assert.ok(!values.includes('data:'), `data: in ${name} is a fetchable scheme`);
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

/**
 * Whether a URL value can leave this origin, decided by resolving it the way
 * the browser will — not by pattern-matching the way it was written.
 *
 * The `//`-based regex this replaces knew two spellings of "another origin"
 * and the parser knows more. `https:fonts.googleapis.com/…`, no slashes, is a
 * valid absolute URL to Chrome served over http, and `data:`/`javascript:`
 * never contained `//` at all. Enumerating spellings is the losing side of
 * that game; asking the URL parser where the request actually goes is the
 * winning one.
 *
 * Resolved against two bases, not one, because the parser has a special case
 * that a single base cannot see around: a special-scheme URL with no slashes
 * is *relative* when its scheme matches the base's, and an authority when it
 * does not. `https:evil.example/x` therefore stays same-origin against an
 * https base and becomes `https://evil.example/x` against an http one — and
 * which of those the reader gets depends on how the page happens to be
 * served. A value is same-origin only if it is same-origin both ways; a value
 * the parser rejects outright is a violation, not a pass.
 */
function leavesOrigin(value) {
  for (const base of ['https://self.invalid/', 'http://self.invalid/']) {
    let resolved;
    try {
      resolved = new URL(value, base);
    } catch {
      return true;
    }
    if (resolved.origin !== new URL(base).origin) return true;
  }
  return false;
}

/** Every href/src value in the markup, whichever quote style carries it. */
function urlAttributes(markup) {
  return [...markup.matchAll(/(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')/giu)].map(
    (m) => m[1] ?? m[2],
  );
}

// The exit criterion — zero requests to non-self origins — verified in a real
// browser against the built page (four requests, all same-origin, no console
// output). This is the assertion that keeps it true afterwards.
test('the page loads nothing from another origin', () => {
  const external = urlAttributes(MARKUP).filter(leavesOrigin);
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
    assert.ok(!leavesOrigin(url), `${url} is an external stylesheet asset`);
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

// The guard has to survive an attempt to switch it off. A check that a crafted
// comment can disable is not a check, and the failure is silent in the worst
// direction: the page loads the resource, the test reports clean.
test('a crafted comment cannot hide a resource from these assertions', () => {
  const evil = 'https://fonts.googleapis.com/css2?family=X';
  const pages = [
    // HTML5 empty comments: the browser ends them at `>`, so the link is live.
    `<head><!--><link rel="stylesheet" href="${evil}"><!-- ordinary --></head>`,
    `<head><!---><link rel="stylesheet" href="${evil}"><!-- ordinary --></head>`,
    // Delimiter reintroduction: stripping the inner match leaves `<!--` behind.
    `<head><!--<!-- --><link rel="stylesheet" href="${evil}">--></head>`,
    // Comment-end-bang: `--!>` closes the comment too, so the link is live and
    // the trailing ordinary comment is there to catch a scanner that missed it.
    `<head><!-- x --!><link rel="stylesheet" href="${evil}"><!-- ordinary --></head>`,
    // A `>` inside an attribute value must not end the tag early.
    `<head><meta content="a > b" /><link rel="stylesheet" href="${evil}"></head>`,
  ];

  for (const page of pages) {
    assert.match(markupOnly(page), /fonts\.googleapis\.com/u, `hidden by: ${page}`);
  }
});

// Same posture for the origin check itself: spellings that reach another
// origin without looking like the `https://` the old regex was written for.
test('an origin bypass in an unusual spelling is still caught', () => {
  const disguises = [
    // A special-scheme URL with no slashes at all: `https:host/path` is an
    // authority — and a live cross-origin request — whenever the page's own
    // scheme differs, which is not the page's decision to make.
    '<link rel="stylesheet" href="https:fonts.googleapis.com/css2?family=X">',
    // Single quotes are as legal as double, and were invisible to a
    // double-quote-only capture.
    "<link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=X'>",
    '<script src=\'//fonts.gstatic.com/x.js\'></script>',
  ];

  for (const tag of disguises) {
    const external = urlAttributes(markupOnly(`<head>${tag}</head>`)).filter(leavesOrigin);
    assert.notDeepEqual(external, [], `treated as same-origin: ${tag}`);
  }

  // And the values the page actually uses stay recognized as this origin.
  for (const honest of ['/src/main.tsx', '/fonts/x.woff2', 'fonts/x.woff2']) {
    assert.ok(!leavesOrigin(honest), `${honest} is this origin`);
  }
});

test('an actual comment is still not mistaken for markup', () => {
  const page = '<head><!-- <link rel="stylesheet" href="https://elsewhere.example/x"> --></head>';
  assert.doesNotMatch(markupOnly(page), /elsewhere\.example/u);
});
