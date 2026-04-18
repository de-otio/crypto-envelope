import { argon2id } from '@noble/hashes/argon2.js';

import { SecureBuffer } from '../secure-buffer.js';
import type { ISecureBuffer } from '../types.js';

const ARGON2_TIME_COST = 3;
const ARGON2_MEMORY_COST = 65536;
const ARGON2_PARALLELISM = 1;
const ARGON2_OUTPUT_LENGTH = 32;

/**
 * Derive a 32-byte key from a passphrase using Argon2id.
 *
 * Parameters are OWASP-2023 second-tier (t=3, m=64 MiB, p=1) — a
 * deliberate choice above the OWASP minimum recommendation. Callers that
 * want different parameters must compose Argon2id themselves against the
 * primitive; this function exposes no knobs because changing parameters
 * silently is a common footgun.
 *
 * The passphrase bytes are zeroed after derivation regardless of path.
 * The caller is still responsible for treating the original `passphrase`
 * string as sensitive (JS strings cannot be zeroed).
 */
export function deriveFromPassphrase(passphrase: string, salt: Uint8Array): ISecureBuffer {
  const passphraseBytes = Buffer.from(passphrase, 'utf-8');

  try {
    const derived = argon2id(passphraseBytes, salt, {
      t: ARGON2_TIME_COST,
      m: ARGON2_MEMORY_COST,
      p: ARGON2_PARALLELISM,
      dkLen: ARGON2_OUTPUT_LENGTH,
    });

    return SecureBuffer.from(Buffer.from(derived));
  } finally {
    passphraseBytes.fill(0);
  }
}
