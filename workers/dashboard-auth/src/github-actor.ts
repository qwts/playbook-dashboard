/**
 * GitHub calls made as the signed-in person.
 *
 * Every request here carries a user-to-server token, so the answer to "may
 * this happen?" comes from GitHub rather than from anything this Worker
 * believes. The functions are a closed set, not a proxy: there is no path that
 * forwards an arbitrary method and URL, because a generic proxy has whatever
 * permissions the token has, and this token can write.
 *
 * Nothing returned here is passed through untouched. Titles, logins, and
 * branch names are authored by whoever opened the pull request.
 */

import { USER_AGENT } from './providers/github.ts';
import { sanitizeGithubUrl, sanitizeText } from './privileges.ts';
import type { RepoRef } from './privileges.ts';

const API = 'https://api.github.com';

/** Failure codes the SPA is allowed to see. Never a response body. */
export type ActorErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rejected'
  | 'rate_limited'
  | 'upstream_error';

export class ActorError extends Error {
  readonly code: ActorErrorCode;
  readonly status: number;

  constructor(code: ActorErrorCode, status: number) {
    super(`github request failed (${status}, ${code})`);
    this.name = 'ActorError';
    this.code = code;
    this.status = status;
  }
}

function classify(status: number, remaining: string | null): ActorErrorCode {
  if (status === 401) return 'unauthorized';
  if (status === 429) return 'rate_limited';
  if (status === 403) return remaining === '0' ? 'rate_limited' : 'forbidden';
  if (status === 404) return 'not_found';
  // 422 is GitHub refusing the action on its merits — approving your own pull
  // request, reviewing a closed one. The distinction matters to the person
  // clicking: it is the one failure that retrying will never fix.
  if (status === 422) return 'rejected';
  return 'upstream_error';
}

async function call<T>(
  accessToken: string,
  path: string,
  init: { method?: string; body?: unknown } = {},
): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    method: init.method ?? 'GET',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': USER_AGENT,
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });

  if (!response.ok) {
    throw new ActorError(
      classify(response.status, response.headers.get('X-RateLimit-Remaining')),
      response.status,
    );
  }

  return (await response.json().catch(() => null)) as T;
}

export type ActorRepo = { owner: string; name: string; fullName: string; private: boolean };

type InstallationsResponse = { installations?: Array<{ id?: number }> };
type RepositoriesResponse = {
  repositories?: Array<{ name?: string; owner?: { login?: string }; private?: boolean }>;
};

/**
 * The repositories this person can reach *through the App*.
 *
 * This is the closed set, and GitHub owns it: adding a repository to the
 * dashboard's privileged surface is an installation change, reviewed where
 * installations are reviewed, not an edit to a list in this repository.
 */
export async function listActorRepos(accessToken: string): Promise<ActorRepo[]> {
  const installations = await call<InstallationsResponse>(accessToken, '/user/installations');
  const repos: ActorRepo[] = [];

  for (const installation of installations?.installations ?? []) {
    if (typeof installation.id !== 'number') continue;

    const page = await call<RepositoriesResponse>(
      accessToken,
      `/user/installations/${installation.id}/repositories?per_page=100`,
    );

    for (const repo of page?.repositories ?? []) {
      const owner = sanitizeText(repo.owner?.login, 39);
      const name = sanitizeText(repo.name, 100);
      if (!owner || !name) continue;
      repos.push({ owner, name, fullName: `${owner}/${name}`, private: repo.private === true });
    }
  }

  return repos.sort((a, b) => a.fullName.localeCompare(b.fullName));
}

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

type PullResponse = {
  number?: number;
  title?: string;
  draft?: boolean;
  updated_at?: string;
  html_url?: string;
  user?: { login?: string };
  head?: { sha?: string; ref?: string };
};

function isoOrNull(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

function toSummary(pull: PullResponse): PullSummary | null {
  const number = pull.number;
  const headSha = pull.head?.sha;
  // Without a number there is nothing to act on, and without a head sha there
  // is nothing to bind an approval to. Both are refusals, not defaults.
  if (typeof number !== 'number' || typeof headSha !== 'string' || !/^[0-9a-f]{40}$/.test(headSha)) {
    return null;
  }

  return {
    number,
    title: sanitizeText(pull.title, 200) ?? '(no title)',
    author: sanitizeText(pull.user?.login, 39),
    headSha,
    headRef: sanitizeText(pull.head?.ref, 255),
    draft: pull.draft === true,
    updatedAt: isoOrNull(pull.updated_at),
    htmlUrl: sanitizeGithubUrl(pull.html_url),
  };
}

export async function listOpenPulls(accessToken: string, repo: RepoRef): Promise<PullSummary[]> {
  const pulls = await call<PullResponse[]>(
    accessToken,
    `/repos/${repo.owner}/${repo.name}/pulls?state=open&sort=updated&direction=desc&per_page=50`,
  );

  return (Array.isArray(pulls) ? pulls : [])
    .map(toSummary)
    .filter((pull): pull is PullSummary => pull !== null);
}

export async function getPull(
  accessToken: string,
  repo: RepoRef,
  number: number,
): Promise<PullSummary | null> {
  const pull = await call<PullResponse>(
    accessToken,
    `/repos/${repo.owner}/${repo.name}/pulls/${number}`,
  );
  return pull ? toSummary(pull) : null;
}

/**
 * Submits a review against one commit.
 *
 * `commit_id` is the point of this function. The Worker has already compared
 * the caller's head sha against the pull request's, but that comparison and
 * this call are two round trips, and a push can land between them. Passing the
 * sha makes GitHub itself refuse a review aimed at bytes that have moved.
 */
export async function submitReview(
  accessToken: string,
  repo: RepoRef,
  number: number,
  review: { commitId: string; event: string; body: string },
): Promise<void> {
  await call(accessToken, `/repos/${repo.owner}/${repo.name}/pulls/${number}/reviews`, {
    method: 'POST',
    body: {
      commit_id: review.commitId,
      event: review.event,
      ...(review.body ? { body: review.body } : {}),
    },
  });
}
