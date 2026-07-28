import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { MAX_DELTA_LENGTH, isObservedPublic, isPublishable, sanitizeDelta } from './collect.mjs';

const SOURCE = readFileSync(new URL('./collect.mjs', import.meta.url), 'utf8');

test('publication requires the manifest to opt a repo in explicitly', () => {
  assert.equal(isPublishable({ name: 'yes', publish: true }), true);
});

test('anything short of publish: true withholds the repo', () => {
  const notOptedIn = [
    {},
    { publish: false },
    { publish: null },
    { publish: 'true' },
    { publish: 1 },
    { publish: {} },
    { publish: 'yes' },
    undefined,
    null,
  ];

  for (const entry of notOptedIn) {
    assert.equal(isPublishable(entry), false, `${JSON.stringify(entry)} must not publish`);
  }
});

test('a repo is emitted only when GitHub itself reports it public', () => {
  assert.equal(isObservedPublic({ private: false, visibility: 'public' }), true);
});

test('an unreadable, partial, or non-public repo response fails closed', () => {
  const withheld = [
    null,
    undefined,
    {},
    { private: true, visibility: 'private' },
    { private: false, visibility: 'internal' },
    // The two fields disagreeing means we do not know; do not guess.
    { private: true, visibility: 'public' },
    { private: false },
    { visibility: 'public' },
    // Manifest-shaped input must not satisfy the observed-state gate.
    { name: 'repo', visibility: 'public' },
  ];

  for (const detail of withheld) {
    assert.equal(isObservedPublic(detail), false, `${JSON.stringify(detail)} must be withheld`);
  }
});

test('a delta within the contract passes through unchanged', () => {
  const delta = 'Coverage floor 71% lines / 80% branches.';
  assert.equal(sanitizeDelta(delta, 'example'), delta);
});

test('an over-long delta is dropped whole, not truncated', () => {
  const long = 'a'.repeat(MAX_DELTA_LENGTH + 1);
  assert.equal(sanitizeDelta(long, 'example'), '');
  assert.equal(sanitizeDelta('a'.repeat(MAX_DELTA_LENGTH), 'example').length, MAX_DELTA_LENGTH);
});

test('control characters disqualify a delta', () => {
  assert.equal(sanitizeDelta('line one\nline two', 'example'), '');
  assert.equal(sanitizeDelta('tab\there', 'example'), '');
  assert.equal(sanitizeDelta('null\u0000byte', 'example'), '');
  assert.equal(sanitizeDelta('esc\u001b[31m', 'example'), '');
  assert.equal(sanitizeDelta('del\u007f', 'example'), '');
});

test('a missing or non-string delta becomes an empty string', () => {
  for (const value of [undefined, null, 42, {}, [], true]) {
    assert.equal(sanitizeDelta(value, 'example'), '');
  }
});

// A source assertion rather than a behavioural one: main() does network I/O, so
// capturing its stderr costs more than the property is worth. This pins the
// exact regression — a manifest entry's name reaching a log line before the
// observed-visibility gate has decided whether that repo may be named at all.
//
// `sanitizeDelta` logging its `repoName` is deliberately not matched: it only
// runs for repos that have already passed both gates, so their names are public.
test('no log line interpolates a manifest entry name', () => {
  const offenders = [...SOURCE.matchAll(/warn\([^;]*?\$\{entry\.name\}/gu)].map((m) => m[0]);

  assert.deepEqual(
    offenders,
    [],
    'a withheld repo must never be named in an Actions log — log position, not identity',
  );
});
