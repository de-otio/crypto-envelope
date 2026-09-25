/**
 * Envelope layer — encrypt/decrypt to versioned wire formats.
 *
 * v1 is JSON with base64 binary fields (human-readable, ~33 % larger).
 * v2 is CBOR with raw binary fields (compact). Both describe the same
 * cryptographic object; v1 and v2 round-trip losslessly via
 * {@link upgradeToV2} / {@link downgradeToV1}.
 */

export { rewrapEnvelope } from './rewrap.js';
export {
  decryptV1,
  deserializeV1,
  type EncryptV1Args,
  encryptV1,
  serializeV1,
} from './v1.js';
export {
  deserialize,
  deserializeV2,
  downgradeToV1,
  serializeV2,
  upgradeToV2,
} from './v2.js';
