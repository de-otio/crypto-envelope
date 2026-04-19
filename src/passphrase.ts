import { deriveFromPassphrase as argon2DeriveFromPassphrase } from './primitives/argon2.js';
import { pbkdf2Sha256 } from './primitives/pbkdf2.js';
import { SecureBuffer } from './secure-buffer.js';
import type { ISecureBuffer, MasterKey } from './types.js';

/**
 * Unified passphrase-KDF API.
 *
 * Produces a branded {@link MasterKey} (32 bytes) that feeds the HKDF
 * subkey derivation inside `EnvelopeClient`. Callers must not use the
 * output directly as a content-encryption key — the brand enforces this
 * at the type level (design-review B8).
 *
 * ## Algorithm selection
 *
 * Argon2id is the **mandatory default** for new consumers. Its
 * memory-hard design defeats GPU/ASIC password-cracking attacks that
 * PBKDF2 does not. Parameters follow OWASP 2023 second-tier
 * recommendations (`t=3, m=64 MiB, p=1, dkLen=32`) and are fixed — callers
 * who want different parameters compose Argon2id themselves against
 * {@link argon2DeriveFromPassphrase}.
 *
 * PBKDF2-SHA256 exists for **compatibility only**: WebCrypto-constrained
 * runtimes where shipping WASM Argon2 is not viable (some browser
 * extension policies, some corporate-locked browsers). Taking the
 * PBKDF2 branch emits a one-time `console.warn` per process, naming the
 * Argon2id-preferred posture.
 *
 * The PBKDF2 iteration floor is enforced at **1,000,000** for SHA-256.
 * OWASP 2023's "600,000" minimum is the published floor but hardware
 * improves ~30%/year; the 1M floor (design-review S1) keeps
 * PBKDF2-on-2026-hardware at roughly OWASP's 2023 intent. Reviewed
 * annually (SECURITY.md cadence commitments).
 *
 * ## Cancellation
 *
 * `deriveMasterKeyFromPassphrase` is `async` and accepts an optional
 * `AbortSignal`. Argon2id runs synchronously inside `@noble/hashes` —
 * the signal is checked before and after derivation, which covers the
 * tab-navigation and request-timeout cases but not mid-iteration abort.
 * A future release may chunk the Argon2id loop; the public shape stays
 * the same.
 *
 * ## Passphrase handling
 *
 * The UTF-8 bytes of `passphrase` are zeroed after derivation regardless
 * of which branch ran. The original JS string lives in the V8 heap until
 * GC and **cannot be zeroed by this library** — callers handling
 * highly-sensitive passphrases should minimise the time the string exists
 * (e.g. take it from a controlled input, pass directly, do not log).
 */

export type PassphraseKdfParams =
  | { algorithm: 'argon2id' }
  | { algorithm: 'pbkdf2-sha256'; iterations: number };

/** Minimum PBKDF2-SHA256 iterations accepted by this library. Raised from
 *  OWASP 2023's 600,000 to keep PBKDF2-on-2026-hardware roughly at the
 *  intended cost budget (design-review S1). */
export const PBKDF2_SHA256_MIN_ITERATIONS = 1_000_000;

let pbkdf2WarnEmitted = false;

export interface DeriveMasterKeyOptions {
  signal?: AbortSignal;
}

/**
 * Derive a 32-byte {@link MasterKey} from a passphrase. Brand the output
 * so it cannot be mis-used as an AEAD key (design-review B8).
 *
 * @throws `AbortError` if `signal` fires.
 * @throws `Error` if PBKDF2 iteration count is below the floor.
 */
export async function deriveMasterKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  params: PassphraseKdfParams,
  options?: DeriveMasterKeyOptions,
): Promise<MasterKey> {
  options?.signal?.throwIfAborted();

  if (params.algorithm === 'argon2id') {
    const buf = argon2DeriveFromPassphrase(passphrase, salt);
    options?.signal?.throwIfAborted();
    return asMasterKey(buf);
  }

  if (params.algorithm === 'pbkdf2-sha256') {
    if (!Number.isInteger(params.iterations) || params.iterations < PBKDF2_SHA256_MIN_ITERATIONS) {
      throw new Error(
        `PBKDF2-SHA256 iterations must be an integer >= ${PBKDF2_SHA256_MIN_ITERATIONS}, got ${params.iterations}`,
      );
    }
    warnOncePbkdf2();

    const passphraseBytes = Buffer.from(passphrase, 'utf8');
    let derived: Uint8Array | undefined;
    try {
      derived = pbkdf2Sha256(passphraseBytes, salt, { iterations: params.iterations });
      options?.signal?.throwIfAborted();
      return asMasterKey(SecureBuffer.from(Buffer.from(derived)));
    } finally {
      if (derived) derived.fill(0);
      passphraseBytes.fill(0);
    }
  }

  const _exhaustive: never = params;
  throw new Error(`unknown KDF algorithm: ${JSON.stringify(_exhaustive)}`);
}

/**
 * Brand an existing {@link ISecureBuffer} as a {@link MasterKey}. Intended
 * for advanced callers (test vectors, migration paths, raw key material
 * from a hardware source). Routine use should go through
 * {@link deriveMasterKeyFromPassphrase}.
 *
 * The buffer must be exactly 32 bytes; other widths throw.
 */
export function asMasterKey(buf: ISecureBuffer): MasterKey {
  if (buf.length !== 32) {
    throw new Error(`MasterKey must be 32 bytes, got ${buf.length}`);
  }
  return buf as MasterKey;
}

function warnOncePbkdf2(): void {
  if (pbkdf2WarnEmitted) return;
  pbkdf2WarnEmitted = true;
  // eslint-disable-next-line no-console
  console.warn(
    '[@de-otio/crypto-envelope] PBKDF2-SHA256 used — prefer Argon2id where available. ' +
      'See SECURITY.md for guidance.',
  );
}

/**
 * Internal: reset the once-per-process PBKDF2 compatibility-warning flag.
 * Not part of the public API; underscore-prefixed to mark it as a testing
 * affordance. Removing it would break no documented consumer.
 */
export function _resetPbkdf2WarnForTests(): void {
  pbkdf2WarnEmitted = false;
}
