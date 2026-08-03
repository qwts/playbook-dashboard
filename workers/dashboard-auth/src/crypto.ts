/**
 * Signing and encoding primitives.
 *
 * Cookies are signed (HMAC-SHA256), not encrypted: claims are readable by the
 * client but cannot be forged without SESSION_SECRET. Nothing privileged is
 * ever placed in a cookie payload.
 *
 * `seal`/`open` are the exception to that sentence, and they exist for the one
 * thing that is never a cookie: the GitHub actor token, which sits in D1 under
 * AES-GCM. A database read — a mis-scoped API token, a backup, a query
 * console — should yield ciphertext rather than a live credential.
 */

/**
 * What a token is *for*, mixed into the signed message.
 *
 * Both cookies are signed with the same SESSION_SECRET, so without this a
 * transaction token — which /auth/login hands to any unauthenticated caller —
 * verifies perfectly well as a session token. Domain separation lives in the
 * HMAC rather than only in a claim, so a shape check is the second line of
 * defence and not the only one.
 */
export type TokenPurpose = 'session' | 'oauth_tx';

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

// Return type left to inference: `CryptoKey` is a type under workerd's types
// but only a value under node's, and this module is typechecked as both.
async function hmacKey(secret: string, usages: Array<'sign' | 'verify'>) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usages,
  );
}

/** Returns `<base64url(json)>.<base64url(hmac)>`, signed for one purpose only. */
export async function signClaims(
  secret: string,
  purpose: TokenPurpose,
  claims: unknown,
): Promise<string> {
  const payload = bytesToBase64Url(encoder.encode(JSON.stringify(claims)));
  const key = await hmacKey(secret, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`${purpose}.${payload}`));
  return `${payload}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

export async function verifyClaims<T>(
  secret: string,
  purpose: TokenPurpose,
  token: string,
): Promise<T | null> {
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
    encoder.encode(`${purpose}.${payload}`),
  );
  if (!valid) return null;

  try {
    return JSON.parse(decoder.decode(base64UrlToBytes(payload))) as T;
  } catch {
    return null;
  }
}

const GCM_IV_BYTES = 12;

async function aesKey(secret: string, usages: Array<'encrypt' | 'decrypt'>) {
  // The secret is key *material*, not a key: hashing it to 32 bytes means the
  // configured value can be any length without the import silently failing.
  const material = await crypto.subtle.digest('SHA-256', encoder.encode(secret));
  return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, usages);
}

/** Returns `base64url(iv || ciphertext)`. A fresh IV per call, never reused. */
export async function seal(secret: string, value: unknown): Promise<string> {
  const key = await aesKey(secret, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as unknown as ArrayBuffer },
      key,
      encoder.encode(JSON.stringify(value)),
    ),
  );

  const packed = new Uint8Array(iv.length + ciphertext.length);
  packed.set(iv);
  packed.set(ciphertext, iv.length);
  return bytesToBase64Url(packed);
}

/** Null for anything that does not decrypt and parse — tampering included. */
export async function open<T>(secret: string, sealed: string): Promise<T | null> {
  let packed: Uint8Array;
  try {
    packed = base64UrlToBytes(sealed);
  } catch {
    return null;
  }
  if (packed.length <= GCM_IV_BYTES) return null;

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: packed.slice(0, GCM_IV_BYTES) as unknown as ArrayBuffer },
      await aesKey(secret, ['decrypt']),
      packed.slice(GCM_IV_BYTES) as unknown as ArrayBuffer,
    );
    return JSON.parse(decoder.decode(new Uint8Array(plaintext))) as T;
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
