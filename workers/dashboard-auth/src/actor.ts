/**
 * The life of a stored GitHub actor token.
 *
 * Stored for allowlisted admins and nobody else, sealed with AES-GCM, keyed by
 * session id. Every failure in this file resolves the same way — delete the
 * row and report that there is no usable token — because the alternative is a
 * privileged surface that half works and cannot say why.
 */

import { open, seal } from './crypto.ts';
import type { Env } from './env.ts';
import type { UserToken } from './providers/github.ts';
import { refreshGitHubToken } from './providers/github.ts';
import type { SessionClaims } from './session.ts';
import { deleteActorToken, getActorToken, putActorToken } from './store.ts';
import type { Identity } from './store.ts';

/** Refresh this long before expiry, so a slow request cannot straddle it. */
const REFRESH_SKEW_SECONDS = 120;

export type ActorTokenResult =
  | { status: 'ready'; accessToken: string }
  | { status: 'unavailable'; error: 'privileges_unavailable' | 'actor_token_unavailable' };

export async function storeActorToken(
  env: Env,
  sid: string,
  identity: Identity,
  token: UserToken,
  now: number,
): Promise<void> {
  if (!env.DB) return;
  await putActorToken(
    env.DB,
    sid,
    identity,
    {
      secret: await seal(env.TOKEN_ENCRYPTION_KEY, token),
      accessExpiresAt: token.accessExpiresAt,
      refreshExpiresAt: token.refreshExpiresAt,
    },
    now,
  );
}

export async function forgetActorToken(env: Env, sid: string): Promise<void> {
  if (!env.DB) return;
  await deleteActorToken(env.DB, sid).catch(() => undefined);
}

function expired(at: number | null, now: number, skew = 0): boolean {
  return at !== null && now + skew >= at;
}

/**
 * Returns an access token for this session, refreshing it if it is close to
 * expiry.
 *
 * GitHub rotates the refresh token on use, so the refreshed pair is persisted
 * before it is returned: a refresh whose result is dropped has spent a
 * credential and kept a dead one.
 */
export async function loadActorToken(
  env: Env,
  session: SessionClaims,
  now: number,
): Promise<ActorTokenResult> {
  if (!env.DB || !env.TOKEN_ENCRYPTION_KEY) {
    return { status: 'unavailable', error: 'privileges_unavailable' };
  }
  // Only the GitHub identity carries an actor token. An admin signed in with
  // Apple or Google is an admin who cannot act, which is the correct answer
  // rather than a gap to paper over.
  if (session.provider !== 'github') {
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  const row = await getActorToken(env.DB, session.sid);
  if (!row) return { status: 'unavailable', error: 'actor_token_unavailable' };

  const token = await open<UserToken>(env.TOKEN_ENCRYPTION_KEY, row.secret);
  if (!token?.accessToken) {
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  if (!expired(token.accessExpiresAt, now, REFRESH_SKEW_SECONDS)) {
    return { status: 'ready', accessToken: token.accessToken };
  }

  if (!token.refreshToken || expired(token.refreshExpiresAt, now)) {
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  let refreshed: UserToken;
  try {
    refreshed = await refreshGitHubToken(env, token.refreshToken);
  } catch (error) {
    console.error(
      'github token refresh failed:',
      error instanceof Error ? error.message : 'unknown error',
    );
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  const identity: Identity = { provider: session.provider, subject: session.subject };

  try {
    await storeActorToken(env, session.sid, identity, refreshed, now);
  } catch {
    // The new pair could not be persisted, so the old one is already dead and
    // this one is unreachable next request. Fail now rather than act on a
    // credential nothing recorded.
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  return { status: 'ready', accessToken: refreshed.accessToken };
}
