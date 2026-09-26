/**
 * @de-otio/crypto-envelope
 *
 * Opinionated authenticated-encryption envelopes for TypeScript.
 */

export { constructAAD } from './aad.js';
export { generateBlobId } from './blob-id.js';
export { canonicalJson } from './canonical-json.js';
export {
  decryptV1,
  deserialize,
  deserializeV1,
  deserializeV2,
  downgradeToV1,
  type EncryptV1Args,
  encryptV1,
  rewrapEnvelope,
  serializeV1,
  serializeV2,
  upgradeToV2,
} from './envelope/index.js';
export {
  AES_GCM_HARD_CAP,
  EnvelopeClient,
  type EnvelopeClientOptions,
  NonceBudgetExceeded,
  type WireFormat,
} from './envelope-client.js';
export {
  AuthenticationFailedError,
  EnvelopeError,
  MalformedEnvelopeError,
  TruncatedCiphertextError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from './errors.js';
export {
  InMemoryMessageCounter,
  keyFingerprint,
  type MessageCounter,
} from './message-counter.js';
export {
  asMasterKey,
  type DeriveMasterKeyOptions,
  deriveMasterKeyFromPassphrase,
  type PassphraseKdfParams,
  PBKDF2_SHA256_MIN_ITERATIONS,
} from './passphrase.js';
export { deriveCommitKey, deriveContentKey } from './primitives/hkdf.js';
export { SecureBuffer } from './secure-buffer.js';
export type {
  Algorithm,
  AnyEnvelope,
  EnvelopeV1,
  EnvelopeV2,
  ISecureBuffer,
  MasterKey,
} from './types.js';
