/**
 * Error taxonomy for @de-otio/crypto-envelope.
 *
 * ## Partitioning-oracle defence
 *
 * All authenticated failures (wrong CEK, wrong commit key, tampered
 * ciphertext, tampered AAD, tampered commitment) are surfaced through a
 * single class — {@link AuthenticationFailedError} — with a single,
 * fixed message string. The distinctions that WOULD create a
 * partitioning oracle (Len–Grubbs–Ristenpart, USENIX 2021) are
 * deliberately erased: callers cannot distinguish "wrong key" from
 * "tampered envelope" through the error type, message, code, or any
 * other observable.
 *
 * Unauthenticated structural problems (unsupported algorithm, malformed
 * CBOR/JSON, truncated ciphertext) are separately classified because
 * they are detectable WITHOUT a key and therefore leak nothing about
 * key material.
 */

// ── Base class ────────────────────────────────────────────────────────────

/**
 * Base class for all crypto-envelope errors.
 * The `code` discriminator is suitable for downstream `switch` statements.
 */
export class EnvelopeError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
    // Maintain proper prototype chain in transpiled environments.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── Structural / unauthenticated errors ──────────────────────────────────

/**
 * The algorithm name in the envelope is not recognised by this library.
 *
 * This is a structural error, not an authentication failure: the check
 * happens before any key material is used and leaks nothing about the key.
 *
 * code: `UNSUPPORTED_ALGORITHM`
 */
export class UnsupportedAlgorithmError extends EnvelopeError {
  constructor(alg: string) {
    super('UNSUPPORTED_ALGORITHM', `unsupported algorithm: ${alg}`);
    this.name = 'UnsupportedAlgorithmError';
  }
}

/**
 * The `v` field in the envelope contains an unknown version number.
 *
 * code: `UNSUPPORTED_VERSION`
 */
export class UnsupportedVersionError extends EnvelopeError {
  constructor(v: number | string) {
    super('UNSUPPORTED_VERSION', `unsupported envelope version: ${v}`);
    this.name = 'UnsupportedVersionError';
  }
}

/**
 * The envelope bytes could not be parsed: bad CBOR, bad JSON, missing
 * required fields, invalid base64, or any other structural problem that
 * prevents reading the envelope at all.
 *
 * code: `MALFORMED_ENVELOPE`
 */
export class MalformedEnvelopeError extends EnvelopeError {
  constructor(reason: string) {
    super('MALFORMED_ENVELOPE', `malformed envelope: ${reason}`);
    this.name = 'MalformedEnvelopeError';
  }
}

/**
 * The ciphertext blob is shorter than the minimum required length
 * (nonce + tag bytes). No key material is involved in this check.
 *
 * This is a specialisation of {@link MalformedEnvelopeError} for the
 * specific structural fault of truncation.
 *
 * code: `TRUNCATED_CIPHERTEXT`
 */
export class TruncatedCiphertextError extends EnvelopeError {
  constructor(expected: number, got: number) {
    super(
      'TRUNCATED_CIPHERTEXT',
      `truncated ciphertext: expected at least ${expected} bytes, got ${got}`,
    );
    this.name = 'TruncatedCiphertextError';
  }
}

// ── Authenticated failure ─────────────────────────────────────────────────

/**
 * Generic authenticated-failure error.
 *
 * Thrown for ALL of the following:
 * - Wrong content-encryption key (CEK)
 * - Wrong commitment key
 * - Tampered AEAD tag
 * - Tampered ciphertext body
 * - Tampered AAD (id, kid, alg, v)
 * - Tampered commitment field
 *
 * **The message and code are intentionally identical for all of the above.**
 * Distinguishing them would allow a partitioning oracle: an attacker with
 * access to a decrypt oracle that distinguishes "wrong key" from "tampered"
 * can efficiently partition a candidate key set (Len–Grubbs–Ristenpart,
 * USENIX 2021; §4.2). All authenticated failures must be indistinguishable.
 *
 * code: `AUTHENTICATION_FAILED`
 */
export class AuthenticationFailedError extends EnvelopeError {
  static readonly MESSAGE = 'authentication failed; envelope is wrong key or tampered';

  constructor() {
    super('AUTHENTICATION_FAILED', AuthenticationFailedError.MESSAGE);
    this.name = 'AuthenticationFailedError';
  }
}

// Note: NonceBudgetExceeded is defined in envelope-client.ts and exported
// from src/index.ts alongside these classes. It cannot be re-exported here
// without creating a circular dependency (errors.ts → envelope-client.ts →
// errors.ts). Consumers wanting a unified import should use the main package
// entry point.
