import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * PBKDF2-SHA256 primitive — a WebCrypto-compatible fallback for runtimes
 * where Argon2id is not available (restricted browser extensions, some
 * FIPS-constrained environments). Argon2id is the preferred algorithm
 * everywhere it can run; PBKDF2 is the compatibility-only path. See
 * `src/passphrase.ts` for the unified caller surface.
 *
 * Parameters are caller-supplied rather than baked in, but callers are
 * expected to enforce the iteration floor at the passphrase-module layer
 * (`src/passphrase.ts` rejects anything below 1_000_000 for SHA-256).
 *
 * Output length is fixed at 32 bytes because the downstream consumer is
 * always `EnvelopeClient`, which HKDFs a 32-byte master into CEK +
 * commitKey. Broader output widths would be a different primitive.
 */
export const PBKDF2_DEFAULT_OUTPUT_LENGTH = 32;

export interface Pbkdf2Params {
  /** Number of PBKDF2 iterations. Passphrase-layer enforces floor. */
  iterations: number;
  /** Derived key length in bytes. Defaults to 32. */
  dkLen?: number;
}

/**
 * Pure-JS PBKDF2-SHA256 via `@noble/hashes`. Synchronous on every runtime
 * where `@noble/hashes` runs (Node, browsers, Deno, Bun, Cloudflare
 * Workers). Not yieldable mid-computation — the `AbortSignal`-capable
 * wrapper in `src/passphrase.ts` checks before starting and after
 * returning, which is the best we can do without re-implementing PBKDF2
 * in chunks.
 */
export function pbkdf2Sha256(
  passphrase: Uint8Array,
  salt: Uint8Array,
  params: Pbkdf2Params,
): Uint8Array {
  return pbkdf2(sha256, passphrase, salt, {
    c: params.iterations,
    dkLen: params.dkLen ?? PBKDF2_DEFAULT_OUTPUT_LENGTH,
  });
}
