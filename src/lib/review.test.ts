import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeReviewError, submitReview } from './review.ts';

/**
 * The client is not enforcement — the Worker refuses on its own. What it owes
 * the person clicking is that every response is read as the outcome it
 * actually was: an unaccounted-for submit must never render as success, and a
 * moved head must not render as an error to dismiss.
 */

const SHA = 'a'.repeat(40);
const MOVED_SHA = 'b'.repeat(40);

type Captured = { headers: Headers; body: Record<string, unknown> };

function stubFetch(response: Response): { captured: Captured[]; restore: () => void } {
  const captured: Captured[] = [];
  const original = globalThis.fetch;

  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    captured.push({
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>,
    });
    return response;
  }) as typeof globalThis.fetch;

  return { captured, restore: () => void (globalThis.fetch = original) };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

const REQUEST = {
  repo: 'qwts/playbook-dashboard',
  number: 7,
  headSha: SHA,
  event: 'APPROVE' as const,
  body: '',
  idempotencyKey: '4b1e0d2c-9f3a-4c11-8a77-1f2e3d4c5b6a',
};

test('a submit carries the header the Worker requires and the sha it was shown', async () => {
  const stub = stubFetch(json({ ok: true }));

  try {
    await submitReview(REQUEST);

    const call = stub.captured[0];
    assert.ok(call);
    assert.equal(call.headers.get('X-Dashboard-Action'), '1');
    assert.equal(call.body.head_sha, SHA);
    assert.equal(call.body.event, 'APPROVE');
    assert.equal(call.body.idempotency_key, REQUEST.idempotencyKey);
  } finally {
    stub.restore();
  }
});

test('a moved head is an outcome to act on, not an error to dismiss', async () => {
  const stub = stubFetch(json({ error: 'head_moved', headSha: MOVED_SHA }, 409));

  try {
    const outcome = await submitReview(REQUEST);

    assert.deepEqual(outcome, { status: 'head_moved', headSha: MOVED_SHA });
  } finally {
    stub.restore();
  }
});

test('a replay reports success without claiming a second review was submitted', async () => {
  const stub = stubFetch(json({ ok: true, replay: true, outcome: 'succeeded' }));

  try {
    assert.deepEqual(await submitReview(REQUEST), { status: 'ok', replay: true });
  } finally {
    stub.restore();
  }
});

test('an unaccounted-for submit never renders as success', async () => {
  // The row is still 'attempted': the first request left the Worker and
  // nothing came back to say what GitHub did with it. Resolving that as "fine,
  // try again" is the one direction that can approve twice.
  const stub = stubFetch(json({ ok: false, replay: true, outcome: 'attempted' }));

  try {
    const outcome = await submitReview(REQUEST);

    assert.equal(outcome.status, 'error');
    assert.match(
      outcome.status === 'error' ? outcome.message : '',
      /unaccounted for. Check GitHub/,
    );
  } finally {
    stub.restore();
  }
});

test('a lapsed authorization asks for re-authentication rather than reporting a failure', async () => {
  for (const code of ['reauth_required', 'actor_token_unavailable']) {
    const stub = stubFetch(json({ error: code }, 401));
    try {
      assert.deepEqual(await submitReview(REQUEST), { status: 'reauth' }, code);
    } finally {
      stub.restore();
    }
  }
});

test('a GitHub refusal keeps its own message, and an unknown code does not leak', async () => {
  const stub = stubFetch(json({ error: 'github_rejected' }, 422));

  try {
    const outcome = await submitReview(REQUEST);
    assert.equal(outcome.status, 'error');
    assert.match(outcome.status === 'error' ? outcome.message : '', /cannot approve your own/);
  } finally {
    stub.restore();
  }

  // An error code this page has never heard of becomes a generic message
  // rather than being rendered verbatim.
  assert.equal(
    describeReviewError('some_new_worker_code'),
    'Something went wrong. Nothing was submitted.',
  );
});

test('a network failure states that nothing was submitted', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (() => Promise.reject(new Error('offline'))) as typeof globalThis.fetch;

  try {
    const outcome = await submitReview(REQUEST);
    assert.equal(outcome.status, 'error');
    assert.match(outcome.status === 'error' ? outcome.message : '', /Nothing was submitted/);
  } finally {
    globalThis.fetch = original;
  }
});
