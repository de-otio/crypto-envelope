import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

const DEFAULT_KEY_LENGTH = 32;

/**
 * HKDF-SHA256 Extract+Expand per RFC 5869.
 *
 * The `info` parameter provides domain separation — distinct info strings
 * derive cryptographically independent keys from the same input keying
 * material. Callers that derive multiple keys from one IKM must use
 * different info strings for each, and the info strings must not be
 * prefixes of one another (domain confusion).
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
  const infoBytes = new TextEncoder().encode(info);
  return hkdf(sha256, ikm, salt ?? new Uint8Array(0), infoBytes, length ?? DEFAULT_KEY_LENGTH);
}
