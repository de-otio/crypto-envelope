/**
 * @de-otio/crypto-envelope/primitives
 *
 * Low-level primitives for callers who want envelope-style discipline
 * on a non-default shape. Stability contract is weaker than the main
 * entry: breaking changes still require a major bump, but the surface
 * may be reshaped more aggressively as we learn from consumers.
 */

export type { ISecureBuffer } from '../types.js';
export {
  AES_GCM_NONCE_LENGTH,
  type AeadResult,
  aeadDecrypt,
  aeadEncrypt,
  KEY_LENGTH,
  NONCE_LENGTH,
  nonceLengthFor,
  TAG_LENGTH,
  XCHACHA_NONCE_LENGTH,
} from './aead.js';
export { deriveFromPassphrase } from './argon2.js';
export { computeCommitment, verifyCommitment } from './commitment.js';
export { deriveCommitKey, deriveContentKey, deriveKey } from './hkdf.js';
export { PBKDF2_DEFAULT_OUTPUT_LENGTH, type Pbkdf2Params, pbkdf2Sha256 } from './pbkdf2.js';
