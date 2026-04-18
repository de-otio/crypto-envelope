/**
 * Memory-locked buffer for sensitive key material.
 * Implementations must zero the buffer on dispose. The concrete
 * `SecureBuffer` class also implements `Symbol.dispose` so callers can use
 * TC39 Explicit Resource Management (`using sb = SecureBuffer.alloc(...)`);
 * the dispose protocol is a class-level contract rather than part of the
 * interface, so third-party implementations can opt into it or not.
 */
export interface ISecureBuffer {
  readonly buffer: Buffer;
  readonly length: number;
  readonly isDisposed: boolean;
  dispose(): void;
}

/** Supported AEAD algorithms. v0.1 ships XChaCha20-Poly1305 only. */
export type Algorithm = 'XChaCha20-Poly1305';

/**
 * v1 envelope — JSON wire format with base64-encoded binary fields.
 *
 *   v       — wire-format version (always 1 here; v2 is a CBOR variant)
 *   id      — opaque blob identifier (typically `b_` + base62)
 *   ts      — ISO 8601 timestamp set at encrypt time
 *   enc.alg — AEAD algorithm (XChaCha20-Poly1305 in v0.1)
 *   enc.kid — key identifier, an opaque string the caller picked; bound
 *             into the AAD so a different `kid` at decrypt time fails
 *             authentication
 *   enc.ct  — base64 of (nonce ‖ ciphertext ‖ tag)
 *   enc['ct.len'] — byte length of the decoded ct, defensively validated
 *             on decrypt to catch truncation before AEAD verify
 *   enc.commit — base64 of the HMAC-SHA256 key commitment
 */
export interface EnvelopeV1 {
  v: 1;
  id: string;
  ts: string;
  enc: {
    alg: Algorithm;
    kid: string;
    ct: string;
    'ct.len': number;
    commit: string;
  };
}

/**
 * v2 envelope — CBOR wire format with raw binary fields. Shares crypto
 * semantics with v1 (the AAD is computed with `v: 1` in both cases); v2
 * is a more compact serialisation of the same cryptographic object.
 */
export interface EnvelopeV2 {
  v: 2;
  id: string;
  ts: string;
  enc: {
    alg: Algorithm;
    kid: string;
    ct: Uint8Array;
    commit: Uint8Array;
  };
}

export type AnyEnvelope = EnvelopeV1 | EnvelopeV2;
