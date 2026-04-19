import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { constantTimeEqual } from '../internal/runtime.js';

const ENCODER = new TextEncoder();

/**
 * Compute a key-commitment tag over a binding identifier and the raw
 * ciphertext. The commitment is HMAC-SHA256(commitKey, idBytes || rawCt)
 * where idBytes is the UTF-8 encoding of the identifier string.
 *
 * The HMAC is computed incrementally (`update` twice, then `digest`) so
 * large ciphertexts are not copied into a single contiguous buffer.
 *
 * Key commitment defeats partitioning-oracle attacks
 * (Len–Grubbs–Ristenpart, USENIX 2021; Bellare–Hoang, EUROCRYPT 2022):
 * without it, an AEAD ciphertext can be decrypted to different
 * plaintexts under different keys, so an oracle that reveals whether
 * decryption succeeded can efficiently test keys from a candidate set.
 *
 * The commitKey must be HKDF-derived with a distinct info string from
 * the content encryption key. Reusing the content key for commitment
 * breaks the security argument.
 */
export function computeCommitment(
  commitKey: Uint8Array,
  id: string,
  rawCt: Uint8Array,
): Uint8Array {
  return hmac.create(sha256, commitKey).update(ENCODER.encode(id)).update(rawCt).digest();
}

/**
 * Verify a commitment using a constant-time comparison. The tag length
 * itself is public information (it's on the envelope), so a length-based
 * short-circuit leaks nothing secret — `constantTimeEqual` performs the
 * length check before entering the XOR-accumulate loop.
 */
export function verifyCommitment(
  commitKey: Uint8Array,
  id: string,
  rawCt: Uint8Array,
  expected: Uint8Array,
): boolean {
  return constantTimeEqual(computeCommitment(commitKey, id, rawCt), expected);
}
