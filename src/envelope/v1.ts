import { constructAAD } from '../aad.js';
import { generateBlobId } from '../blob-id.js';
import { canonicalJson } from '../canonical-json.js';
import {
  AuthenticationFailedError,
  MalformedEnvelopeError,
  TruncatedCiphertextError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from '../errors.js';
import { b64decode, b64encode } from '../internal/base64.js';
import { constantTimeEqual } from '../internal/constant-time.js';
import { TAG_LENGTH, aeadDecrypt, aeadEncrypt, nonceLengthFor } from '../primitives/aead.js';
import { computeCommitment, verifyCommitment } from '../primitives/commitment.js';
import type { Algorithm, EnvelopeV1 } from '../types.js';

const DEFAULT_ALG: Algorithm = 'XChaCha20-Poly1305';
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
  /**
   * AEAD algorithm. Defaults to `'XChaCha20-Poly1305'`. AES-256-GCM is
   * available for interop with external systems; the envelope client
   * (Phase IV) enforces the 2³² per-key message cap on the GCM path.
   * Callers using this function directly are responsible for honouring
   * the cap themselves — see `src/message-counter.ts`.
   */
  algorithm?: Algorithm;
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
  const alg: Algorithm = args.algorithm ?? DEFAULT_ALG;
  const id = args.id ?? generateBlobId();
  const ts = args.ts ?? new Date().toISOString();

  const plaintext = ENCODER.encode(canonicalJson(payload));
  const aad = constructAAD(alg, id, kid, 1);

  const { nonce, ciphertext, tag } = aeadEncrypt(alg, cek, plaintext, aad);

  const rawCt = new Uint8Array(nonce.length + ciphertext.length + tag.length);
  rawCt.set(nonce, 0);
  rawCt.set(ciphertext, nonce.length);
  rawCt.set(tag, nonce.length + ciphertext.length);

  const commitment = computeCommitment(commitKey, id, rawCt);

  // Verify-after-encrypt — guards against a bug in the AEAD primitive.
  const recovered = aeadDecrypt(alg, cek, nonce, ciphertext, tag, aad);
  if (!constantTimeEqual(recovered, plaintext)) {
    throw new MalformedEnvelopeError(
      'verify-after-encrypt failed: decrypted plaintext does not match input',
    );
  }

  return {
    v: 1,
    id,
    ts,
    enc: {
      alg,
      kid,
      ct: b64encode(rawCt),
      'ct.len': rawCt.length,
      commit: b64encode(commitment),
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
    throw new UnsupportedVersionError(envelope.v);
  }
  if (envelope.enc.alg !== 'XChaCha20-Poly1305' && envelope.enc.alg !== 'AES-256-GCM') {
    throw new UnsupportedAlgorithmError(envelope.enc.alg);
  }

  const rawCt = b64decode(envelope.enc.ct);

  const nonceLen = nonceLengthFor(envelope.enc.alg);
  const minLen = nonceLen + TAG_LENGTH;
  if (rawCt.length < minLen) {
    throw new TruncatedCiphertextError(minLen, rawCt.length);
  }
  if (rawCt.length !== envelope.enc['ct.len']) {
    throw new MalformedEnvelopeError(
      `ciphertext length mismatch: ct.len=${envelope.enc['ct.len']}, actual=${rawCt.length}`,
    );
  }

  const expectedCommit = b64decode(envelope.enc.commit);
  if (!verifyCommitment(commitKey, envelope.id, rawCt, expectedCommit)) {
    throw new AuthenticationFailedError();
  }

  const aad = constructAAD(envelope.enc.alg, envelope.id, envelope.enc.kid, 1);
  const nonce = rawCt.subarray(0, nonceLen);
  const ciphertext = rawCt.subarray(nonceLen, rawCt.length - TAG_LENGTH);
  const tag = rawCt.subarray(rawCt.length - TAG_LENGTH);

  const plaintext = aeadDecrypt(envelope.enc.alg, cek, nonce, ciphertext, tag, aad);

  return JSON.parse(DECODER.decode(plaintext)) as Record<string, unknown>;
}

/** Serialise a v1 envelope to wire bytes (UTF-8 JSON). */
export function serializeV1(envelope: EnvelopeV1): Uint8Array {
  return ENCODER.encode(JSON.stringify(envelope));
}

/** Parse UTF-8 JSON bytes as a v1 envelope. Does not decrypt. */
export function deserializeV1(bytes: Uint8Array): EnvelopeV1 {
  let parsed: EnvelopeV1;
  try {
    parsed = JSON.parse(DECODER.decode(bytes)) as EnvelopeV1;
  } catch (e) {
    throw new MalformedEnvelopeError(`JSON parse error: ${String(e)}`);
  }
  if (parsed.v !== 1) {
    throw new MalformedEnvelopeError(`JSON envelope has unexpected version: ${parsed.v}`);
  }
  return parsed;
}
