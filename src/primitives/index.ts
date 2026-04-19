/**
 * @de-otio/crypto-envelope/primitives
 *
 * Low-level primitives for callers who want envelope-style discipline
 * on a non-default shape. Stability contract is weaker than the main
 * entry: breaking changes still require a major bump, but the surface
 * may be reshaped more aggressively as we learn from consumers.
 */

export {
  aeadEncrypt,
  aeadDecrypt,
  AES_GCM_NONCE_LENGTH,
  KEY_LENGTH,
  NONCE_LENGTH,
  nonceLengthFor,
  TAG_LENGTH,
  XCHACHA_NONCE_LENGTH,
  type AeadResult,
} from './aead.js';
export { deriveKey, deriveContentKey, deriveCommitKey } from './hkdf.js';
export { computeCommitment, verifyCommitment } from './commitment.js';
export { deriveFromPassphrase } from './argon2.js';
export { pbkdf2Sha256, PBKDF2_DEFAULT_OUTPUT_LENGTH, type Pbkdf2Params } from './pbkdf2.js';

export type { ISecureBuffer } from '../types.js';
