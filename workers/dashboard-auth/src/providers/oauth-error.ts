/**
 * The spec-defined OAuth error code from a token-endpoint response body.
 *
 * GitHub answers a bad client secret with HTTP 200 and an `error` field, so
 * the HTTP status alone reads as success — exactly what made the July 2026
 * bad-client-secret incident slow to diagnose. The code is worth logging; the
 * rest of the body is not.
 *
 * Only codes on this closed list may propagate: the allowlist is what makes
 * the value loggable. `error` in an untrusted response body is free text until
 * proven otherwise, and `error_description` stays out entirely — it is prose,
 * not an enum, and prose from the wire does not belong in logs.
 */
const OAUTH_ERROR_CODES = new Set([
  // RFC 6749 §5.2 token-endpoint errors.
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unauthorized_client',
  'unsupported_grant_type',
  'invalid_scope',
  // GitHub's documented additions.
  'incorrect_client_credentials',
  'bad_verification_code',
  'redirect_uri_mismatch',
]);

/**
 * The allowlisted error code carried by `payload`, `'unrecognized_error'` when
 * a code is present but not on the list, and `null` when there is none.
 */
export function oauthErrorCode(payload: { error?: unknown } | null | undefined): string | null {
  const error = payload?.error;
  if (typeof error !== 'string' || error.length === 0) return null;
  return OAUTH_ERROR_CODES.has(error) ? error : 'unrecognized_error';
}
