import { argon2id } from '@noble/hashes/argon2.js';

import { SecureBuffer } from '../secure-buffer.js';
import type { ISecureBuffer } from '../types.js';

// Argon2id parameters above the OWASP 2023 minimum — second-tier of the
// OWASP Password Storage Cheat Sheet (t=3, m=64 MiB, p=1).
//   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
// Using @noble/hashes rather than libsodium's crypto_pwhash so the
// primitives layer stays portable to non-Node runtimes if that becomes a
// goal later (see plans/01-extraction.md §7).
const ARGON2_TIME_COST = 3;
const ARGON2_MEMORY_COST = 65536; // KiB
const ARGON2_PARALLELISM = 1;
const ARGON2_OUTPUT_LENGTH = 32;

/**
 * Derive a 32-byte key from a passphrase using Argon2id.
 *
 * Parameters are hard-coded; callers that want different parameters must
 * compose Argon2id themselves against the primitive. Silently changing
 * parameters is a common footgun.
 *
 * The passphrase bytes are zeroed after derivation regardless of path.
 * The caller is still responsible for treating the original `passphrase`
 * string as sensitive (JS strings cannot be zeroed).
 *
 * Passphrases must be valid UTF-16: lone surrogates are silently
 * replaced with U+FFFD (`EF BF BD`) during UTF-8 encoding, so two
 * distinct malformed passphrases would collide on the same derived key.
 * Applications that accept arbitrary user input should validate or
 * NFC-normalise before calling.
 */
export function deriveFromPassphrase(passphrase: string, salt: Uint8Array): ISecureBuffer {
  const passphraseBytes = Buffer.from(passphrase, 'utf8');
  let derived: Uint8Array | undefined;

  try {
    derived = argon2id(passphraseBytes, salt, {
      t: ARGON2_TIME_COST,
      m: ARGON2_MEMORY_COST,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_OUTPUT_LENGTH,
    });

    return SecureBuffer.from(derived);
  } finally {
    if (derived) {
      derived.fill(0);
    }
    passphraseBytes.fill(0);
  }
}
