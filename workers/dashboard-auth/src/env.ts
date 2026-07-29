export type Env = {
  /** HMAC key for session and oauth-transaction cookies. */
  SESSION_SECRET: string;

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

  /** Empty = pass through to the zone origin. Set for `wrangler dev`. */
  PAGES_ORIGIN: string;
  SESSION_TTL_SECONDS: string;
};

export type Provider = 'apple' | 'google' | 'github';

export function isProvider(value: string | null): value is Provider {
  return value === 'apple' || value === 'google' || value === 'github';
}

export function sessionTtlSeconds(env: Env): number {
  const parsed = Number.parseInt(env.SESSION_TTL_SECONDS ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 28_800;
}
