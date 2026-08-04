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
import {
  deleteActorToken,
  deleteSupersededActorTokens,
  getActorToken,
  putActorToken,
} from './store.ts';
import type { Identity } from './store.ts';

/** Refresh this long before expiry, so a slow request cannot straddle it. */
const REFRESH_SKEW_SECONDS = 120;

export type ActorTokenResult =
  | { status: 'ready'; accessToken: string; login: string | null }
  | { status: 'unavailable'; error: 'privileges_unavailable' | 'actor_token_unavailable' };

/**
 * What actually gets sealed: the token bundle plus the login it acts as.
 *
 * The login rides here, not in the session cookie — the cookie is signed but
 * readable, while this blob is read back only on the privileged path, which
 * is exactly where the audit row needs a name.
 */
export type SealedActorToken = UserToken & { login: string | null };

export async function storeActorToken(
  env: Env,
  sid: string,
  identity: Identity,
  token: UserToken,
  login: string | null,
  now: number,
): Promise<void> {
  if (!env.DB) return;
  await putActorToken(
    env.DB,
    sid,
    identity,
    {
      secret: await seal(env.TOKEN_ENCRYPTION_KEY, { ...token, login } satisfies SealedActorToken),
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

/**
 * After a fresh sign-in stores its token, drop any row an earlier session
 * left for the same identity — that session can no longer reach it. Best
 * effort: the fresh token is already stored, and a failed cleanup must not
 * fail the sign-in.
 */
export async function forgetSupersededActorTokens(
  env: Env,
  identity: Identity,
  keepSid: string,
): Promise<void> {
  if (!env.DB) return;
  await deleteSupersededActorTokens(env.DB, identity, keepSid).catch(() => undefined);
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

  const token = await open<SealedActorToken>(env.TOKEN_ENCRYPTION_KEY, row.secret);
  if (!token?.accessToken) {
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }
  const login = token.login ?? null;

  if (!expired(token.accessExpiresAt, now, REFRESH_SKEW_SECONDS)) {
    return { status: 'ready', accessToken: token.accessToken, login };
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
    // The login sealed at sign-in survives every refresh.
    await storeActorToken(env, session.sid, identity, refreshed, login, now);
  } catch {
    // The new pair could not be persisted, so the old one is already dead and
    // this one is unreachable next request. Fail now rather than act on a
    // credential nothing recorded.
    await forgetActorToken(env, session.sid);
    return { status: 'unavailable', error: 'actor_token_unavailable' };
  }

  return { status: 'ready', accessToken: refreshed.accessToken, login };
}
