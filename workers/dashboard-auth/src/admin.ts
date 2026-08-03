/**
 * The privileged surface: `/admin/*`.
 *
 * Three routes, one of which writes. Every one of them passes the same four
 * gates before it reaches GitHub — request shape, session, allowlist, and (for
 * the write) how recently that session authenticated — and the write adds two
 * more that only it needs: an audit row that must exist first, and a head sha
 * that must still be current.
 *
 * None of what this returns is publishable. Pull request titles are on the
 * redaction list the snapshot is validated against, which is exactly why they
 * are served from here — live, per session, `private, no-store` — and never
 * written into the artifact.
 */

import { forgetActorToken, loadActorToken } from './actor.ts';
import { safeEqual } from './crypto.ts';
import type { Env } from './env.ts';
import { privilegedRateLimit } from './env.ts';
import { ActorError, getPull, listActorRepos, listOpenPulls, submitReview } from './github-actor.ts';
import { privateJson } from './http.ts';
import type { RepoRef, ReviewEvent } from './privileges.ts';
import {
  allowedOwners,
  checkPrivilegedRequest,
  isAdminIdentity,
  isFreshEnoughToAct,
  isHeadSha,
  isIdempotencyKey,
  isReviewEvent,
  parsePullNumber,
  parseRepoRef,
  sanitizeReviewBody,
} from './privileges.ts';
import type { SessionClaims } from './session.ts';
import { readSession } from './session.ts';
import type { Identity } from './store.ts';
import { beginAudit, completeAudit, countRecentActions } from './store.ts';

/** Attempts per identity per minute, counted from the audit log itself. */
const RATE_WINDOW_SECONDS = 60;

type Actor = { session: SessionClaims; identity: Identity };

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function identityOf(session: SessionClaims): Identity {
  return {
    provider: session.provider,
    subject: session.subject,
    login: session.login,
    email: session.email,
  };
}

/**
 * The gates, in the order that leaks least.
 *
 * Request shape first, because it needs no session and no database. The
 * allowlist before the freshness check, so an ordinary signed-in reader
 * learns "not for you" rather than "authenticate again and then not for you".
 */
async function authorize(
  env: Env,
  request: Request,
  url: URL,
  options: { mutating: boolean },
): Promise<Actor | Response> {
  const malformed = checkPrivilegedRequest(request, url, options);
  if (malformed) return privateJson({ error: malformed }, { status: 403 });

  const session = await readSession(env, request);
  if (!session) return privateJson({ error: 'authentication_required' }, { status: 401 });

  if (!isAdminIdentity(env, session.provider, session.subject)) {
    return privateJson({ error: 'not_privileged' }, { status: 403 });
  }

  if (!env.DB) return privateJson({ error: 'privileges_unavailable' }, { status: 503 });

  if (options.mutating && !isFreshEnoughToAct(env, session.iat, nowSeconds())) {
    return privateJson({ error: 'reauth_required' }, { status: 401 });
  }

  return { session, identity: identityOf(session) };
}

/**
 * GitHub said no. Which no it was matters to the person clicking, so the code
 * survives; the response body never does.
 */
async function actorFailure(env: Env, session: SessionClaims, error: unknown): Promise<Response> {
  const code = error instanceof ActorError ? error.code : 'upstream_error';
  console.error('privileged github call failed:', code);

  switch (code) {
    case 'unauthorized':
      // The token is dead in a way a retry will not fix. Drop it so the next
      // request asks for a sign-in instead of failing the same way.
      await forgetActorToken(env, session.sid);
      return privateJson({ error: 'actor_token_unavailable' }, { status: 401 });
    case 'forbidden':
      return privateJson({ error: 'github_forbidden' }, { status: 403 });
    case 'not_found':
      return privateJson({ error: 'github_not_found' }, { status: 404 });
    case 'rejected':
      return privateJson({ error: 'github_rejected' }, { status: 422 });
    case 'rate_limited':
      return privateJson({ error: 'github_rate_limited' }, { status: 429 });
    default:
      return privateJson({ error: 'github_unavailable' }, { status: 502 });
  }
}

async function handleRepos(env: Env, actor: Actor): Promise<Response> {
  const token = await loadActorToken(env, actor.session, nowSeconds());
  if (token.status !== 'ready') return privateJson({ error: token.error }, { status: 401 });

  const owners = allowedOwners(env);
  try {
    const repos = (await listActorRepos(token.accessToken)).filter((repo) =>
      owners.has(repo.owner.toLowerCase()),
    );
    return privateJson({ repos });
  } catch (error) {
    return actorFailure(env, actor.session, error);
  }
}

async function handlePulls(env: Env, actor: Actor, url: URL): Promise<Response> {
  const repo = parseRepoRef(env, url.searchParams.get('repo'));
  if (!repo) return privateJson({ error: 'invalid_repo' }, { status: 400 });

  const token = await loadActorToken(env, actor.session, nowSeconds());
  if (token.status !== 'ready') return privateJson({ error: token.error }, { status: 401 });

  try {
    return privateJson({ repo: repo.fullName, pulls: await listOpenPulls(token.accessToken, repo) });
  } catch (error) {
    return actorFailure(env, actor.session, error);
  }
}

type ReviewRequest = {
  repo: RepoRef;
  number: number;
  headSha: string;
  event: ReviewEvent;
  body: string;
  idempotencyKey: string;
};

type ReviewBody = {
  repo?: unknown;
  number?: unknown;
  head_sha?: unknown;
  event?: unknown;
  body?: unknown;
  idempotency_key?: unknown;
};

/** Validates in full and names the field that failed. Never coerces. */
function readReviewRequest(env: Env, body: ReviewBody | null): ReviewRequest | string {
  const repo = parseRepoRef(env, body?.repo);
  if (!repo) return 'repo';

  const number = parsePullNumber(body?.number);
  if (number === null) return 'number';

  if (!isHeadSha(body?.head_sha)) return 'head_sha';
  if (!isReviewEvent(body?.event)) return 'event';
  if (!isIdempotencyKey(body?.idempotency_key)) return 'idempotency_key';

  const reviewBody = sanitizeReviewBody(body?.body);
  if (reviewBody === null) return 'body';
  // GitHub rejects these two without a comment anyway; refusing here means the
  // audit row is never written for a request that was never going to land.
  if (!reviewBody && body?.event !== 'APPROVE') return 'body';

  return {
    repo,
    number,
    headSha: body.head_sha,
    event: body.event,
    body: reviewBody,
    idempotencyKey: body.idempotency_key,
  };
}

async function handleReview(env: Env, actor: Actor, request: Request): Promise<Response> {
  const db = env.DB;
  if (!db) return privateJson({ error: 'privileges_unavailable' }, { status: 503 });

  const parsed = readReviewRequest(
    env,
    (await request.json().catch(() => null)) as ReviewBody | null,
  );
  if (typeof parsed === 'string') {
    return privateJson({ error: 'invalid_review_request', field: parsed }, { status: 400 });
  }

  const now = nowSeconds();

  // Read the audit log before writing to it: if the count cannot be taken, the
  // row that follows could not have been written either, and acting without
  // one is the thing this design does not do.
  let recent: number;
  try {
    recent = await countRecentActions(db, actor.identity, now - RATE_WINDOW_SECONDS);
  } catch {
    return privateJson({ error: 'audit_unavailable' }, { status: 503 });
  }
  if (recent >= privilegedRateLimit(env)) {
    return privateJson({ error: 'rate_limited' }, { status: 429 });
  }

  const token = await loadActorToken(env, actor.session, now);
  if (token.status !== 'ready') return privateJson({ error: token.error }, { status: 401 });

  let pull;
  try {
    pull = await getPull(token.accessToken, parsed.repo, parsed.number);
  } catch (error) {
    return actorFailure(env, actor.session, error);
  }
  if (!pull) return privateJson({ error: 'github_not_found' }, { status: 404 });

  // The approval is for the commit that was on screen. A push between render
  // and click makes this a different pull request wearing the same number.
  if (!safeEqual(pull.headSha, parsed.headSha)) {
    return privateJson({ error: 'head_moved', headSha: pull.headSha }, { status: 409 });
  }

  let attempt;
  try {
    attempt = await beginAudit(
      db,
      {
        id: parsed.idempotencyKey,
        identity: actor.identity,
        action: 'pull_request_review',
        repo: parsed.repo.fullName,
        target: String(parsed.number),
        headSha: parsed.headSha,
        verb: parsed.event,
      },
      now,
    );
  } catch (error) {
    console.error(
      'audit write failed, refusing action:',
      error instanceof Error ? error.message : 'unknown error',
    );
    return privateJson({ error: 'audit_unavailable' }, { status: 503 });
  }

  if (attempt.status === 'replay') {
    // A key reused against a different pull request is not a replay. Reporting
    // the first attempt's outcome would say "already approved" about something
    // this request never touched.
    const sameTarget =
      attempt.repo === parsed.repo.fullName &&
      attempt.target === String(parsed.number) &&
      attempt.verb === parsed.event;

    if (!sameTarget) {
      return privateJson({ error: 'idempotency_key_reused' }, { status: 409 });
    }

    return privateJson({
      ok: attempt.outcome === 'succeeded',
      replay: true,
      outcome: attempt.outcome,
      repo: parsed.repo.fullName,
      number: parsed.number,
    });
  }

  try {
    await submitReview(token.accessToken, parsed.repo, parsed.number, {
      commitId: parsed.headSha,
      event: parsed.event,
      body: parsed.body,
    });
  } catch (error) {
    const code = error instanceof ActorError ? error.code : 'upstream_error';
    await completeAudit(db, parsed.idempotencyKey, `failed:${code}`, nowSeconds()).catch(
      () => undefined,
    );
    return actorFailure(env, actor.session, error);
  }

  // A row left at 'attempted' after a successful call is a false alarm rather
  // than a false all-clear, which is the direction this repository errs in.
  await completeAudit(db, parsed.idempotencyKey, 'succeeded', nowSeconds()).catch(() => undefined);

  return privateJson({
    ok: true,
    repo: parsed.repo.fullName,
    number: parsed.number,
    headSha: parsed.headSha,
    event: parsed.event,
  });
}

/** Null when the path is not privileged, so the caller keeps routing. */
export async function routeAdmin(env: Env, request: Request, url: URL): Promise<Response | null> {
  const { pathname } = url;
  if (pathname !== '/admin' && !pathname.startsWith('/admin/')) return null;

  const mutating = pathname === '/admin/review';
  const method = mutating ? 'POST' : 'GET';
  if (request.method !== method) {
    return privateJson({ error: 'method_not_allowed' }, { status: 405 });
  }

  const actor = await authorize(env, request, url, { mutating });
  if (actor instanceof Response) return actor;

  if (pathname === '/admin/repos') return handleRepos(env, actor);
  if (pathname === '/admin/pulls') return handlePulls(env, actor, url);
  if (pathname === '/admin/review') return handleReview(env, actor, request);

  return privateJson({ error: 'not_found' }, { status: 404 });
}
