/**
 * @de-otio/crypto-envelope
 *
 * Opinionated authenticated-encryption envelopes for TypeScript.
 */

export { canonicalJson } from './canonical-json.js';
export { generateBlobId } from './blob-id.js';
export { SecureBuffer } from './secure-buffer.js';
export { constructAAD } from './aad.js';
export {
  EnvelopeClient,
  type EnvelopeClientOptions,
  type WireFormat,
} from './envelope-client.js';
export {
  encryptV1,
  decryptV1,
  serializeV1,
  deserializeV1,
  serializeV2,
  deserializeV2,
  deserialize,
  upgradeToV2,
  downgradeToV1,
  type EncryptV1Args,
} from './envelope/index.js';
export {
  asMasterKey,
  deriveMasterKeyFromPassphrase,
  PBKDF2_SHA256_MIN_ITERATIONS,
  type DeriveMasterKeyOptions,
  type PassphraseKdfParams,
} from './passphrase.js';
export type {
  Algorithm,
  AnyEnvelope,
  EnvelopeV1,
  EnvelopeV2,
  ISecureBuffer,
  MasterKey,
} from './types.js';
