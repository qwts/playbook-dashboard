/**
 * Who may act, on what, and what a privileged request must look like.
 *
 * Everything here is pure and closed: an allowlist that is empty until someone
 * fills it, an owner set, a fixed vocabulary of review verbs, and argument
 * validation that rejects rather than coerces. The Worker's own gate decides
 * who reaches privileged UI; GitHub decides whether the action succeeds. This
 * file is the first of those two, and it is deliberately the smaller one.
 */

import type { Env, Provider } from './env.ts';
import { privilegedMaxAgeSeconds } from './env.ts';

/**
 * Present on every privileged request.
 *
 * A cross-origin page cannot set a custom header without a CORS preflight, and
 * this Worker answers no preflight — `OPTIONS` is not a method it routes. The
 * `SameSite=Lax` session cookie already refuses to ride along on a cross-site
 * POST; this is the layer that still holds if that ever changes.
 */
export const ACTION_HEADER = 'x-dashboard-action';

/** The complete set of things a privileged session may do. */
export const REVIEW_EVENTS = ['APPROVE', 'REQUEST_CHANGES', 'COMMENT'] as const;

export type ReviewEvent = (typeof REVIEW_EVENTS)[number];

export function isReviewEvent(value: unknown): value is ReviewEvent {
  return REVIEW_EVENTS.includes(value as ReviewEvent);
}

export type RepoRef = { owner: string; name: string; fullName: string };

function splitList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/**
 * `provider:subject` pairs. Anything that is not exactly that shape is dropped
 * rather than repaired — a malformed entry must not silently widen or narrow
 * the list, and a list of two where the operator wrote three is the kind of
 * difference that goes unnoticed until it matters.
 */
export function parseAdminSubjects(raw: string | undefined): Set<string> {
  const admins = new Set<string>();
  for (const entry of splitList(raw)) {
    const separator = entry.indexOf(':');
    if (separator <= 0) continue;
    const provider = entry.slice(0, separator).toLowerCase();
    const subject = entry.slice(separator + 1);
    if (provider !== 'apple' && provider !== 'google' && provider !== 'github') continue;
    if (!subject) continue;
    admins.add(`${provider}:${subject}`);
  }
  return admins;
}

export function isAdminIdentity(env: Env, provider: Provider, subject: string): boolean {
  if (!subject) return false;
  return parseAdminSubjects(env.ADMIN_SUBJECTS).has(`${provider}:${subject}`);
}

export function allowedOwners(env: Env): Set<string> {
  return new Set(splitList(env.ALLOWED_OWNERS).map((owner) => owner.toLowerCase()));
}

/**
 * `owner/name`, where the owner is one this deployment names.
 *
 * The App installation is the real boundary — GitHub refuses a repository it
 * was never installed on — so this is the cheap check in front of it, and it
 * exists mostly so a malformed argument cannot become a request path.
 */
export function parseRepoRef(env: Env, value: unknown): RepoRef | null {
  if (typeof value !== 'string') return null;
  const match = /^([A-Za-z0-9][A-Za-z0-9-]{0,38})\/([A-Za-z0-9._-]{1,100})$/.exec(value);
  if (!match) return null;

  const owner = match[1] as string;
  const name = match[2] as string;
  if (name === '.' || name === '..') return null;
  if (!allowedOwners(env).has(owner.toLowerCase())) return null;

  return { owner, name, fullName: `${owner}/${name}` };
}

export function isHeadSha(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

export function parsePullNumber(value: unknown): number | null {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return parsed;
}

/** An idempotency key is opaque to us, but it becomes a primary key. */
export function isIdempotencyKey(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{8,128}$/.test(value);
}

const DEL = 0x7f;
const FIRST_PRINTABLE = 0x20;
const TAB = 9;
const NEWLINE = 10;
const CARRIAGE_RETURN = 13;

/**
 * Character codes rather than a regex: the alternative is a class of escaped
 * control characters, which is unreadable in review and one stray literal byte
 * away from being wrong in a way nobody sees.
 */
function isControlCode(code: number, allowLineBreaks: boolean): boolean {
  if (allowLineBreaks && (code === TAB || code === NEWLINE || code === CARRIAGE_RETURN)) {
    return false;
  }
  return code < FIRST_PRINTABLE || code === DEL;
}

/**
 * The comment an admin is about to publish under their own name.
 *
 * Capped and refused whole rather than truncated, for the reason `delta` is:
 * a half-sentence reads as authored copy. `APPROVE` may carry no body at all,
 * which is why the empty string is a valid answer and `null` means invalid.
 */
export function sanitizeReviewBody(value: unknown): string | null {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') return null;

  const body = value.trim();
  if (body.length > 2_000) return null;
  for (let index = 0; index < body.length; index += 1) {
    if (isControlCode(body.charCodeAt(index), true)) return null;
  }
  return body;
}

/**
 * Free text arriving *from* GitHub on its way to the page — a PR title, a
 * login, a branch name. Untrusted in the same way the manifest is: it is
 * authored by whoever opened the pull request.
 */
export function sanitizeText(value: unknown, limit: number): string | null {
  if (typeof value !== 'string') return null;

  let collapsed = '';
  for (let index = 0; index < value.length; index += 1) {
    collapsed += isControlCode(value.charCodeAt(index), false) ? ' ' : value[index];
  }

  const text = collapsed.trim();
  if (!text) return null;
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

/** Only github.com, and only a path — never a URL that points somewhere else. */
export function sanitizeGithubUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.hostname !== 'github.com') return null;
  return `https://github.com${url.pathname}`;
}

/**
 * Shape checks that run before the session is even looked at.
 *
 * Returns an error code, or null when the request may proceed.
 */
export function checkPrivilegedRequest(
  request: Request,
  url: URL,
  options: { mutating: boolean },
): string | null {
  if (request.headers.get(ACTION_HEADER) !== '1') return 'missing_action_header';

  // Absent on older browsers; wrong only when the request did not come from
  // the dashboard itself.
  const site = request.headers.get('Sec-Fetch-Site');
  if (site && site !== 'same-origin') return 'cross_site_request';

  // Browsers omit Origin on same-origin GETs and always send it on POSTs, so
  // requiring it unconditionally would fail the reads for no benefit.
  if (options.mutating && request.headers.get('Origin') !== url.origin) {
    return 'origin_mismatch';
  }

  return null;
}

/** Whether a session authenticated recently enough to act, not merely to read. */
export function isFreshEnoughToAct(env: Env, issuedAt: number, now: number): boolean {
  return now - issuedAt <= privilegedMaxAgeSeconds(env);
}
