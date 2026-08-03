import type { Database } from './d1.ts';

export type Env = {
  /** HMAC key for session and oauth-transaction cookies. */
  SESSION_SECRET: string;

  /**
   * GitHub **App** client credentials — not an OAuth App.
   *
   * Sign-in and privileged actions share one credential on purpose: the token
   * this exchange returns is the same token that later approves a pull
   * request, so what the dashboard can do is bounded by what the signed-in
   * person can already do and by which repositories the App is installed on.
   * An OAuth App's token is bounded by neither — it carries whatever scope was
   * requested, across every repository the user can reach, and never expires.
   */
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;

  /** Apple Services ID — the web client_id, not the app bundle id. */
  APPLE_CLIENT_ID: string;
  APPLE_TEAM_ID: string;
  APPLE_KEY_ID: string;
  /** PKCS8 PEM contents of the Sign in with Apple .p8 key. */
  APPLE_PRIVATE_KEY: string;

  /** Google OAuth 2.0 web client credentials. */
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;

  /**
   * Who may reach privileged UI at all, as `provider:subject` pairs.
   *
   * Unset means nobody. Subjects, not logins or emails: a GitHub login can be
   * renamed and then claimed by someone else, an email can be reassigned, and
   * Apple's relay address is per-app. The subject is the only identifier the
   * providers promise is stable.
   */
  ADMIN_SUBJECTS: string;

  /** AES-GCM key material for actor tokens at rest. */
  TOKEN_ENCRYPTION_KEY: string;

  /** Comma/space separated owners a privileged action may name. */
  ALLOWED_OWNERS: string;

  /** How recently a session must have authenticated to act. */
  PRIVILEGED_MAX_AGE_SECONDS: string;

  /** Privileged actions per identity per minute. */
  PRIVILEGED_RATE_LIMIT: string;

  /** Absent = no identity tracking, no audit log, and no privileged actions. */
  DB?: Database;

  /** Empty = pass through to the zone origin. Set for `wrangler dev`. */
  PAGES_ORIGIN: string;
  SESSION_TTL_SECONDS: string;
};

export type Provider = 'apple' | 'google' | 'github';

export function isProvider(value: unknown): value is Provider {
  return value === 'apple' || value === 'google' || value === 'github';
}

function positiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function sessionTtlSeconds(env: Env): number {
  return positiveInt(env.SESSION_TTL_SECONDS, 28_800);
}

/**
 * A session older than this may read, but may not act.
 *
 * The session lasts eight hours because re-authenticating to read a dashboard
 * every hour is theatre. Acting is different: the window is short enough that
 * a cookie lifted from a walked-away laptop is usually already too old to
 * approve anything, and re-authenticating costs an allowlisted admin a silent
 * redirect — GitHub does not re-prompt for an App it has already authorized.
 */
export function privilegedMaxAgeSeconds(env: Env): number {
  return positiveInt(env.PRIVILEGED_MAX_AGE_SECONDS, 3_600);
}

export function privilegedRateLimit(env: Env): number {
  return positiveInt(env.PRIVILEGED_RATE_LIMIT, 10);
}
