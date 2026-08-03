/**
 * Page-side client for the privileged endpoints.
 *
 * Nothing here is enforcement — the Worker refuses on its own, and this file
 * is assumed bypassable in exactly the way `public/sw.js` is. What it owes the
 * person clicking is that the request carries what the Worker requires, that a
 * double submit cannot approve twice, and that a failure says which failure it
 * was.
 *
 * None of this data is cached anywhere. It is live GitHub state, fetched per
 * session, and it never enters the snapshot the collector publishes.
 */

/** Matches the Worker's `ACTION_HEADER`; a cross-origin page cannot set it. */
const ACTION_HEADER = 'X-Dashboard-Action';

export type ActorRepo = {
  owner: string;
  name: string;
  fullName: string;
  private: boolean;
};

export type PullSummary = {
  number: number;
  title: string;
  author: string | null;
  headSha: string;
  headRef: string | null;
  draft: boolean;
  updatedAt: string | null;
  htmlUrl: string | null;
};

export type ReviewEvent = 'APPROVE' | 'REQUEST_CHANGES' | 'COMMENT';

export const REVIEW_LABELS: Record<ReviewEvent, string> = {
  APPROVE: 'Approve',
  REQUEST_CHANGES: 'Request changes',
  COMMENT: 'Comment',
};

export type ReviewOutcome =
  | { status: 'ok'; replay: boolean }
  /** The branch moved between render and click. `headSha` is where it moved to. */
  | { status: 'head_moved'; headSha: string }
  /** The session can no longer act; the page should send them back to sign-in. */
  | { status: 'reauth' }
  | { status: 'error'; message: string };

const ERROR_MESSAGES: Record<string, string> = {
  not_privileged: 'This account is not permitted to act on the fleet.',
  privileges_unavailable: 'Privileged actions are not configured on this deployment.',
  actor_token_unavailable: 'Your GitHub authorization has lapsed. Sign in with GitHub again.',
  reauth_required: 'Sign in again to act — this session authenticated too long ago.',
  audit_unavailable: 'The audit log is unreachable, so no action was taken.',
  rate_limited: 'Too many actions in the last minute. Wait a moment.',
  github_forbidden: 'GitHub refused: this account cannot act on that repository.',
  github_not_found: 'GitHub could not find that pull request.',
  github_rejected:
    'GitHub rejected the review — you cannot approve your own pull request, or it is no longer open.',
  github_rate_limited: 'GitHub is rate limiting this account. Wait a moment.',
  github_unavailable: 'GitHub is unavailable. Nothing was submitted.',
  invalid_repo: 'That repository is not one this dashboard may act on.',
  invalid_review_request: 'The dashboard sent something the Worker refused. Reload and retry.',
  missing_action_header: 'The dashboard sent something the Worker refused. Reload and retry.',
  origin_mismatch: 'The dashboard sent something the Worker refused. Reload and retry.',
  cross_site_request: 'The dashboard sent something the Worker refused. Reload and retry.',
  network_error: 'Network error. Nothing was submitted.',
};

export function describeReviewError(code: string | null): string {
  if (!code) return 'Something went wrong. Nothing was submitted.';
  return ERROR_MESSAGES[code] ?? 'Something went wrong. Nothing was submitted.';
}

export class PrivilegedError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(describeReviewError(code));
    this.name = 'PrivilegedError';
    this.code = code;
  }
}

async function privilegedFetch(path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: 'include',
      headers: { Accept: 'application/json', [ACTION_HEADER]: '1', ...init.headers },
    });
  } catch {
    throw new PrivilegedError('network_error');
  }

  const payload = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  if (!response.ok) {
    throw new PrivilegedError(typeof payload?.error === 'string' ? payload.error : 'network_error');
  }
  return payload;
}

export async function fetchActorRepos(): Promise<ActorRepo[]> {
  const payload = (await privilegedFetch('/admin/repos')) as { repos?: ActorRepo[] } | null;
  return payload?.repos ?? [];
}

export async function fetchOpenPulls(fullName: string): Promise<PullSummary[]> {
  const payload = (await privilegedFetch(
    `/admin/pulls?repo=${encodeURIComponent(fullName)}`,
  )) as { pulls?: PullSummary[] } | null;
  return payload?.pulls ?? [];
}

/**
 * One key per armed action, not per attempt.
 *
 * The Worker keys its audit row on this, so a retried fetch or an impatient
 * second click lands on the row the first one wrote and returns its outcome
 * instead of submitting a second review.
 */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

/**
 * Submits, and reads the outcomes the page has to tell apart.
 *
 * This one does not go through `privilegedFetch`: a 409 is not a failure to
 * report, it is a body to read — the sha the branch moved to, which the page
 * needs in order to show what it now is.
 */
export async function submitReview(request: {
  repo: string;
  number: number;
  headSha: string;
  event: ReviewEvent;
  body: string;
  idempotencyKey: string;
}): Promise<ReviewOutcome> {
  try {
    const response = await fetch('/admin/review', {
      method: 'POST',
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        [ACTION_HEADER]: '1',
      },
      body: JSON.stringify({
        repo: request.repo,
        number: request.number,
        head_sha: request.headSha,
        event: request.event,
        body: request.body,
        idempotency_key: request.idempotencyKey,
      }),
    });

    const payload = (await response.json().catch(() => null)) as Record<string, unknown> | null;

    if (response.status === 409 && typeof payload?.headSha === 'string') {
      return { status: 'head_moved', headSha: payload.headSha };
    }
    if (response.ok && payload?.ok === true) {
      return { status: 'ok', replay: payload.replay === true };
    }

    const code = typeof payload?.error === 'string' ? payload.error : null;
    if (code === 'reauth_required' || code === 'actor_token_unavailable') {
      return { status: 'reauth' };
    }
    if (payload?.outcome === 'attempted') {
      return {
        status: 'error',
        message: 'A previous submit is unaccounted for. Check GitHub before retrying.',
      };
    }
    return { status: 'error', message: describeReviewError(code) };
  } catch {
    return { status: 'error', message: describeReviewError('network_error') };
  }
}
