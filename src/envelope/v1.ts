import { timingSafeEqual } from 'node:crypto';

import { constructAAD } from '../aad.js';
import { generateBlobId } from '../blob-id.js';
import { canonicalJson } from '../canonical-json.js';
import { NONCE_LENGTH, TAG_LENGTH, aeadDecrypt, aeadEncrypt } from '../primitives/aead.js';
import { computeCommitment, verifyCommitment } from '../primitives/commitment.js';
import type { Algorithm, EnvelopeV1 } from '../types.js';

const ALG: Algorithm = 'XChaCha20-Poly1305';
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

export interface EncryptV1Args {
  /** Plaintext object. Must be canonicalisable JSON. */
  payload: Record<string, unknown>;
  /** 32-byte content-encryption key. HKDF-derived via `deriveContentKey`. */
  cek: Uint8Array;
  /** 32-byte key-commitment key. HKDF-derived via `deriveCommitKey`. */
  commitKey: Uint8Array;
  /** Opaque key identifier; bound into AAD. */
  kid: string;
  /** ISO 8601 timestamp; defaults to `new Date().toISOString()`. */
  ts?: string;
  /** Blob identifier; defaults to {@link generateBlobId}. */
  id?: string;
}

/**
 * Encrypt a canonicalisable JSON payload into a v1 envelope.
 *
 * Steps performed:
 *   1. Canonicalise the payload to UTF-8 bytes (RFC 8785).
 *   2. Generate or accept a blob id.
 *   3. Construct AAD = canonicalJson({alg, id, kid, v: 1}).
 *   4. AEAD-encrypt plaintext under `cek` with a fresh 192-bit nonce.
 *   5. Concatenate rawCt = nonce ‖ ciphertext ‖ tag.
 *   6. Compute key commitment HMAC-SHA256(commitKey, id ‖ rawCt).
 *   7. Verify-after-encrypt: decrypt rawCt and compare byte-for-byte
 *      (constant-time) to the original plaintext. Catches bugs in the
 *      AEAD primitive — if we ever release a ciphertext whose decrypt
 *      doesn't reproduce the input, it's an immediate throw.
 *   8. Base64-encode the binary fields and assemble the envelope.
 *
 * Throws if any step fails, including verify-after-encrypt.
 */
export function encryptV1(args: EncryptV1Args): EnvelopeV1 {
  const { payload, cek, commitKey, kid } = args;
  const id = args.id ?? generateBlobId();
  const ts = args.ts ?? new Date().toISOString();

  const plaintext = ENCODER.encode(canonicalJson(payload));
  const aad = constructAAD(ALG, id, kid, 1);

  const { nonce, ciphertext, tag } = aeadEncrypt(cek, plaintext, aad);

  const rawCt = new Uint8Array(nonce.length + ciphertext.length + tag.length);
  rawCt.set(nonce, 0);
  rawCt.set(ciphertext, nonce.length);
  rawCt.set(tag, nonce.length + ciphertext.length);

  const commitment = computeCommitment(commitKey, id, rawCt);

  // Verify-after-encrypt — guards against a bug in the AEAD primitive.
  const recovered = aeadDecrypt(cek, nonce, ciphertext, tag, aad);
  if (recovered.length !== plaintext.length || !timingSafeEqual(recovered, plaintext)) {
    throw new Error('verify-after-encrypt failed: decrypted plaintext does not match input');
  }

  return {
    v: 1,
    id,
    ts,
    enc: {
      alg: ALG,
      kid,
      ct: Buffer.from(rawCt).toString('base64'),
      'ct.len': rawCt.length,
      commit: Buffer.from(commitment).toString('base64'),
    },
  };
}

/**
 * Decrypt a v1 envelope and return the plaintext object.
 *
 * Steps performed:
 *   1. Reject unsupported wire-format versions.
 *   2. Base64-decode `ct` and validate `ct.len` + minimum width.
 *   3. Verify the key commitment HMAC (constant-time).
 *   4. Reconstruct AAD from the envelope's metadata and verify the AEAD
 *      tag — this is where `kid`, `id`, `alg`, and wire version tampering
 *      are caught.
 *   5. Parse the plaintext as JSON and return it.
 *
 * Throws on any mismatch. No silent failures; the return value is always
 * a successfully decrypted object.
 */
export function decryptV1(
  envelope: EnvelopeV1,
  cek: Uint8Array,
  commitKey: Uint8Array,
): Record<string, unknown> {
  if (envelope.v !== 1) {
    throw new Error(`unsupported envelope version: ${envelope.v}`);
  }
  if (envelope.enc.alg !== ALG) {
    throw new Error(`unsupported algorithm: ${envelope.enc.alg}`);
  }

  const rawCt = new Uint8Array(Buffer.from(envelope.enc.ct, 'base64'));

  const minLen = NONCE_LENGTH + TAG_LENGTH;
  if (rawCt.length < minLen) {
    throw new Error(`truncated ciphertext: expected at least ${minLen} bytes, got ${rawCt.length}`);
  }
  if (rawCt.length !== envelope.enc['ct.len']) {
    throw new Error(
      `ciphertext length mismatch: ct.len=${envelope.enc['ct.len']}, actual=${rawCt.length}`,
    );
  }

  const expectedCommit = new Uint8Array(Buffer.from(envelope.enc.commit, 'base64'));
  if (!verifyCommitment(commitKey, envelope.id, rawCt, expectedCommit)) {
    throw new Error('key commitment verification failed');
  }

  const aad = constructAAD(envelope.enc.alg, envelope.id, envelope.enc.kid, 1);
  const nonce = rawCt.subarray(0, NONCE_LENGTH);
  const ciphertext = rawCt.subarray(NONCE_LENGTH, rawCt.length - TAG_LENGTH);
  const tag = rawCt.subarray(rawCt.length - TAG_LENGTH);

  const plaintext = aeadDecrypt(cek, nonce, ciphertext, tag, aad);

  return JSON.parse(DECODER.decode(plaintext)) as Record<string, unknown>;
}

/** Serialise a v1 envelope to wire bytes (UTF-8 JSON). */
export function serializeV1(envelope: EnvelopeV1): Uint8Array {
  return ENCODER.encode(JSON.stringify(envelope));
}

/** Parse UTF-8 JSON bytes as a v1 envelope. Does not decrypt. */
export function deserializeV1(bytes: Uint8Array): EnvelopeV1 {
  const parsed = JSON.parse(DECODER.decode(bytes)) as EnvelopeV1;
  if (parsed.v !== 1) {
    throw new Error(`JSON envelope has unexpected version: ${parsed.v}`);
  }
  return parsed;
}
