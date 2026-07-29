/**
 * Signing and encoding primitives.
 *
 * Cookies are signed (HMAC-SHA256), not encrypted: claims are readable by the
 * client but cannot be forged without SESSION_SECRET. Nothing privileged is
 * ever placed in a cookie payload.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  return base64ToBytes(normalized + '='.repeat((4 - (normalized.length % 4)) % 4));
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function hmacKey(secret: string, usages: Array<'sign' | 'verify'>): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usages,
  );
}

/** Returns `<base64url(json)>.<base64url(hmac)>`. */
export async function signClaims(secret: string, claims: unknown): Promise<string> {
  const payload = bytesToBase64Url(encoder.encode(JSON.stringify(claims)));
  const key = await hmacKey(secret, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return `${payload}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

export async function verifyClaims<T>(secret: string, token: string): Promise<T | null> {
  const separator = token.indexOf('.');
  if (separator <= 0) return null;

  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!payload || !signature) return null;

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlToBytes(signature);
  } catch {
    return null;
  }

  const key = await hmacKey(secret, ['verify']);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    signatureBytes as unknown as ArrayBuffer,
    encoder.encode(payload),
  );
  if (!valid) return null;

  try {
    return JSON.parse(decoder.decode(base64UrlToBytes(payload))) as T;
  } catch {
    return null;
  }
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

export function randomBase64Url(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

/** Constant-time comparison for short ASCII tokens. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}

/** Decodes a JWT payload without verifying its signature. */
export function decodeJwtPayload<T>(jwt: string): T | null {
  const parts = jwt.split('.');
  if (parts.length !== 3 || !parts[1]) return null;
  try {
    return JSON.parse(decoder.decode(base64UrlToBytes(parts[1]))) as T;
  } catch {
    return null;
  }
}

/** Signs an ES256 JWT with a PKCS8 PEM private key (Apple client secret). */
export async function signEs256Jwt(
  privateKeyPem: string,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const der = base64ToBytes(
    privateKeyPem
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, ''),
  );

  const key = await crypto.subtle.importKey(
    'pkcs8',
    der as unknown as ArrayBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );

  const signingInput = `${bytesToBase64Url(encoder.encode(JSON.stringify(header)))}.${bytesToBase64Url(
    encoder.encode(JSON.stringify(payload)),
  )}`;

  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    encoder.encode(signingInput),
  );

  return `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`;
}
