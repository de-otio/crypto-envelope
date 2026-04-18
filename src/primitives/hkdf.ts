import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const DEFAULT_KEY_LENGTH = 32;
const MAX_OKM_LENGTH = 255 * 32; // RFC 5869 caps L at 255 * HashLen for SHA-256

const ENCODER = new TextEncoder();

/** HKDF `info` string for the content-encryption key. */
const CONTENT_INFO = 'crypto-envelope/v1/content';
/** HKDF `info` string for the key-commitment key. */
const COMMIT_INFO = 'crypto-envelope/v1/commit';

/**
 * HKDF-SHA256 Extract+Expand per RFC 5869.
 *
 * The `info` parameter provides domain separation — distinct info strings
 * derive cryptographically independent keys from the same input keying
 * material. Callers that derive multiple keys from one IKM must use
 * different info strings for each, and the info strings must not be
 * prefixes of one another (domain confusion).
 *
 * Prefer the named `deriveContentKey` / `deriveCommitKey` helpers when
 * the two canonical envelope keys are what you need — they bake in
 * stable info strings so a mistake in composition can't collapse the
 * content and commitment keys into the same bytes.
 *
 * @param ikm Input keying material (must be a high-entropy secret).
 * @param info Domain-separation string. Becomes the HKDF info field.
 * @param salt Optional; defaults to empty.
 * @param length Output length in bytes; defaults to 32.
 */
export function deriveKey(
  ikm: Uint8Array,
  info: string,
  salt?: Uint8Array,
  length?: number,
): Uint8Array {
  const outLen = length ?? DEFAULT_KEY_LENGTH;
  if (outLen < 1 || outLen > MAX_OKM_LENGTH) {
    throw new RangeError(`HKDF output length must be in [1, ${MAX_OKM_LENGTH}], got ${outLen}`);
  }
  return hkdf(sha256, ikm, salt ?? new Uint8Array(0), ENCODER.encode(info), outLen);
}

/**
 * Derive the 32-byte content-encryption key (CEK) from a master key.
 * Uses the stable info string `"crypto-envelope/v1/content"`; consumers
 * that need a different schedule must call {@link deriveKey} directly.
 */
export function deriveContentKey(ikm: Uint8Array, salt?: Uint8Array): Uint8Array {
  return deriveKey(ikm, CONTENT_INFO, salt, DEFAULT_KEY_LENGTH);
}

/**
 * Derive the 32-byte key-commitment key from a master key.
 * Uses the stable info string `"crypto-envelope/v1/commit"`.
 */
export function deriveCommitKey(ikm: Uint8Array, salt?: Uint8Array): Uint8Array {
  return deriveKey(ikm, COMMIT_INFO, salt, DEFAULT_KEY_LENGTH);
}
