/**
 * The Worker's only persistent state.
 *
 * Two of these three tables are conveniences and one is load-bearing. Sign-in
 * tracking is best effort — a database hiccup must not be able to lock every
 * account out of a read-only dashboard — and the actor token is a cache of
 * something GitHub would re-issue anyway. The audit log is neither: a
 * privileged action that cannot be recorded does not happen, so every function
 * here that touches it lets its errors propagate to a caller that refuses.
 */

import type { Database } from './d1.ts';
import type { Provider } from './env.ts';

export type Identity = {
  provider: Provider;
  subject: string;
};

/**
 * Upsert on sign-in. The subject is the whole record on purpose: it is
 * provider-attested, sufficient to identify the account to the provider later,
 * and everything richer is evidence the provider already holds better.
 */
export async function recordSignIn(db: Database, identity: Identity, now: number): Promise<void> {
  await db
    .prepare(
      `INSERT INTO identities
         (provider, subject, first_seen_at, last_seen_at, sign_in_count)
       VALUES (?, ?, ?, ?, 1)
       ON CONFLICT(provider, subject) DO UPDATE SET
         last_seen_at  = excluded.last_seen_at,
         sign_in_count = identities.sign_in_count + 1`,
    )
    .bind(identity.provider, identity.subject, now, now)
    .run();
}

export type StoredToken = {
  secret: string;
  accessExpiresAt: number | null;
  refreshExpiresAt: number | null;
};

type TokenRow = {
  secret: string;
  access_expires_at: number | null;
  refresh_expires_at: number | null;
};

export async function putActorToken(
  db: Database,
  sid: string,
  identity: Identity,
  token: StoredToken,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO actor_tokens
         (sid, provider, subject, secret, access_expires_at, refresh_expires_at,
          created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET
         secret             = excluded.secret,
         access_expires_at  = excluded.access_expires_at,
         refresh_expires_at = excluded.refresh_expires_at,
         updated_at         = excluded.updated_at`,
    )
    .bind(
      sid,
      identity.provider,
      identity.subject,
      token.secret,
      token.accessExpiresAt,
      token.refreshExpiresAt,
      now,
      now,
    )
    .run();
}

export async function getActorToken(db: Database, sid: string): Promise<StoredToken | null> {
  const row = await db
    .prepare(
      `SELECT secret, access_expires_at, refresh_expires_at
         FROM actor_tokens WHERE sid = ?`,
    )
    .bind(sid)
    .first<TokenRow>();

  if (!row) return null;
  return {
    secret: row.secret,
    accessExpiresAt: row.access_expires_at,
    refreshExpiresAt: row.refresh_expires_at,
  };
}

export async function deleteActorToken(db: Database, sid: string): Promise<void> {
  await db.prepare('DELETE FROM actor_tokens WHERE sid = ?').bind(sid).run();
}

/**
 * Deletes the row only if it still holds the ciphertext the caller read.
 *
 * GitHub rotates the refresh token on use, so two overlapping requests can
 * race a refresh: the loser's failure must not destroy the winner's freshly
 * stored pair. Comparing the sealed secret is the compare-and-swap — if the
 * row changed since this request read it, someone else won, and their
 * credential stays.
 */
export async function deleteActorTokenIfUnchanged(
  db: Database,
  sid: string,
  secret: string,
): Promise<void> {
  await db.prepare('DELETE FROM actor_tokens WHERE sid = ? AND secret = ?').bind(sid, secret).run();
}

/**
 * Reaps rows whose refresh token has expired — nothing can ever use them
 * again, so holding them is pure liability. A NULL refresh expiry is left
 * alone: it means the App has token expiry turned off and the token still
 * works, not that the row is dead.
 */
export async function reapExpiredActorTokens(db: Database, now: number): Promise<void> {
  await db
    .prepare(
      `DELETE FROM actor_tokens
        WHERE refresh_expires_at IS NOT NULL AND refresh_expires_at < ?`,
    )
    .bind(now)
    .run();
}

/**
 * Deletes every row for this identity except the one just written. A fresh
 * sign-in stores a fresh token; whatever an earlier session left behind is a
 * credential that session can no longer reach, kept alive for nobody.
 */
export async function deleteSupersededActorTokens(
  db: Database,
  identity: Identity,
  keepSid: string,
): Promise<void> {
  await db
    .prepare('DELETE FROM actor_tokens WHERE provider = ? AND subject = ? AND sid <> ?')
    .bind(identity.provider, identity.subject, keepSid)
    .run();
}

export type AuditAttempt = {
  /** The client's idempotency key, which is also the primary key. */
  id: string;
  identity: Identity;
  /**
   * Kept in the audit row even though the identities table no longer stores
   * it: this row records what an account *did*, not that it existed, and it
   * must stay readable on its own during an incident.
   */
  login: string | null;
  action: string;
  repo: string;
  target: string;
  headSha: string;
  verb: string;
};

export type AuditBegin =
  | { status: 'recorded' }
  /** The reservation found no headroom — the action must not proceed. */
  | { status: 'rate_limited' }
  /**
   * This key already acted. The first attempt's outcome comes back with what
   * it was aimed at, because a key reused against a *different* pull request
   * is not a replay — it is a client bug that would otherwise report success
   * for something that never happened.
   */
  | { status: 'replay'; outcome: string; repo: string; target: string; verb: string };

/**
 * Write-ahead: the row exists before the request leaves for GitHub.
 *
 * The alternative — record what happened after it happened — cannot record the
 * case that matters most, which is a call that left here and never came back.
 *
 * The rate limit is enforced *inside* the insert: the count and the write are
 * one statement, executed atomically, so overlapping requests cannot each
 * observe headroom and all proceed. A count taken separately is advisory only
 * — every await between it and the insert is a window to race through.
 */
export async function beginAudit(
  db: Database,
  attempt: AuditAttempt,
  now: number,
  rate: { since: number; limit: number },
): Promise<AuditBegin> {
  const insert = await db
    .prepare(
      `INSERT INTO audit_log
         (id, started_at, provider, subject, login, action, repo, target, head_sha, verb, outcome)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'attempted'
        WHERE (SELECT COUNT(*) FROM audit_log
                WHERE provider = ? AND subject = ? AND started_at >= ?) < ?
       ON CONFLICT(id) DO NOTHING`,
    )
    .bind(
      attempt.id,
      now,
      attempt.identity.provider,
      attempt.identity.subject,
      attempt.login,
      attempt.action,
      attempt.repo,
      attempt.target,
      attempt.headSha,
      attempt.verb,
      attempt.identity.provider,
      attempt.identity.subject,
      rate.since,
      rate.limit,
    )
    .run();

  if ((insert.meta.changes ?? 0) > 0) return { status: 'recorded' };

  const existing = await db
    .prepare('SELECT outcome, repo, target, verb FROM audit_log WHERE id = ?')
    .bind(attempt.id)
    .first<{ outcome: string; repo: string; target: string; verb: string }>();

  // Nothing was written and no row holds this key: the guard refused, not
  // the primary key.
  if (!existing) return { status: 'rate_limited' };

  return {
    status: 'replay',
    outcome: existing.outcome,
    repo: existing.repo,
    target: existing.target,
    verb: existing.verb,
  };
}

/** Only ever closes an open attempt, so a replay cannot rewrite history. */
export async function completeAudit(
  db: Database,
  id: string,
  outcome: string,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE audit_log SET outcome = ?, completed_at = ?
        WHERE id = ? AND outcome = 'attempted'`,
    )
    .bind(outcome, now, id)
    .run();
}

/** Counts attempts, not successes — a burst of failures is still a burst. */
export async function countRecentActions(
  db: Database,
  identity: Identity,
  since: number,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS attempts FROM audit_log
        WHERE provider = ? AND subject = ? AND started_at >= ?`,
    )
    .bind(identity.provider, identity.subject, since)
    .first<{ attempts: number }>();

  return row?.attempts ?? 0;
}
