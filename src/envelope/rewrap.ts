import { deriveCommitKey, deriveContentKey } from '../primitives/hkdf.js';
import type { AnyEnvelope, MasterKey } from '../types.js';
import { decryptV1, encryptV1 } from './v1.js';
import { downgradeToV1, upgradeToV2 } from './v2.js';

/**
 * Re-encrypt an envelope's payload under a new master key without
 * changing its content identity.
 *
 * Consumed by `@de-otio/keyring`'s `KeyRing.rotate()` — a bulk
 * master-key rotation iterates a blob enumerator and calls this once
 * per envelope.
 *
 * ## Semantics
 *
 * - **Decrypts** `oldEnvelope` under `oldMaster`'s HKDF-derived
 *   `(cek, commitKey)` — reusing `deriveContentKey` / `deriveCommitKey`
 *   from `src/primitives/hkdf.ts`, the same schedule `EnvelopeClient`
 *   uses.
 * - **Re-encrypts** the plaintext under `newMaster`'s derived keys.
 * - **Preserves**: envelope version (v1 → v1, v2 → v2), `id` (blob
 *   identity is content-level, not key-level), `ts` (original create
 *   time — this is a rewrap, not a new blob), `alg`, `kid`.
 * - **Regenerates**: nonce, ciphertext, tag, commitment — all
 *   necessarily new under the new master.
 *
 * ## Error surface
 *
 * Throws on:
 * - Master mismatch (AEAD tag failure) — `oldMaster` did not encrypt
 *   this envelope.
 * - Truncated or malformed ciphertext.
 * - Commitment mismatch (tampered envelope, or wrong commit-key).
 *
 * The error surface matches `decryptV1` — no plaintext is released on
 * any failure path. On success the envelope is fully re-sealed under
 * `newMaster` before the function returns (verify-after-encrypt inside
 * `encryptV1` guarantees this).
 *
 * ## Lifetime
 *
 * `oldMaster` and `newMaster` are **caller-owned** — this function does
 * not dispose them. Any transient `Uint8Array` holding a derived key is
 * zeroed before return via a `finally` block; no SecureBuffer is
 * allocated on the hot path, so the only mlock'd memory in play is the
 * two masters, which the caller keeps live across many rewraps.
 *
 * ## Synchronous
 *
 * Not `async`. The underlying noble AEAD primitives are synchronous.
 * `@de-otio/keyring` wraps this call in a `Promise` for orchestration
 * (batching, abort-signal propagation, event emission).
 *
 * ## v2 handling
 *
 * v2 envelopes are handled by downgrading to v1, rewrapping, and
 * upgrading back. `downgradeToV1`/`upgradeToV2` are lossless format
 * conversions over the same cryptographic object — the AAD is
 * constructed with `v: 1` in both formats (see `src/aad.ts`), so
 * routing v2 through the v1 primitives is safe and avoids a parallel
 * implementation path that could drift from the tested v1 encrypt/
 * decrypt code.
 *
 * @param oldEnvelope The envelope to rewrap. v1 or v2.
 * @param oldMaster The master key `oldEnvelope` is currently encrypted under.
 * @param newMaster The master key to re-encrypt under.
 * @returns A new envelope with the same `v`, `id`, `ts`, `alg`, `kid`
 *   and a freshly-generated nonce/ct/tag/commitment.
 */
export function rewrapEnvelope(
  oldEnvelope: AnyEnvelope,
  oldMaster: MasterKey,
  newMaster: MasterKey,
): AnyEnvelope {
  // `new Uint8Array(typedArray)` copies the contents (per ECMA-262
  // §23.2.1.1), so these are heap-allocated transient buffers — not
  // views into the caller-owned SecureBuffers. They must be zeroed in
  // the finally.
  const oldMasterBytes = new Uint8Array(oldMaster.buffer);
  const newMasterBytes = new Uint8Array(newMaster.buffer);

  if (oldMasterBytes.length !== 32) {
    oldMasterBytes.fill(0);
    newMasterBytes.fill(0);
    throw new Error(`oldMaster must be 32 bytes, got ${oldMasterBytes.length}`);
  }
  if (newMasterBytes.length !== 32) {
    oldMasterBytes.fill(0);
    newMasterBytes.fill(0);
    throw new Error(`newMaster must be 32 bytes, got ${newMasterBytes.length}`);
  }

  const oldCek = deriveContentKey(oldMasterBytes);
  const oldCommit = deriveCommitKey(oldMasterBytes);
  const newCek = deriveContentKey(newMasterBytes);
  const newCommit = deriveCommitKey(newMasterBytes);

  try {
    // v2 envelopes are handled by downgrading to the v1 cryptographic
    // representation (same bytes, different encoding of the binary
    // fields), rewrapping through the v1 primitives, and upgrading back.
    // This keeps a single code path for the actual AEAD/commitment work
    // — v1 and v2 describe the same cryptographic object.
    const oldV1 = oldEnvelope.v === 1 ? oldEnvelope : downgradeToV1(oldEnvelope);

    const payload = decryptV1(oldV1, oldCek, oldCommit);

    const newV1 = encryptV1({
      payload,
      cek: newCek,
      commitKey: newCommit,
      kid: oldV1.enc.kid,
      algorithm: oldV1.enc.alg,
      id: oldV1.id,
      ts: oldV1.ts,
    });

    return oldEnvelope.v === 2 ? upgradeToV2(newV1) : newV1;
  } finally {
    // Zero every transient key copy. Do NOT touch the caller-owned
    // SecureBuffers — the caller retains those across many rewraps.
    oldMasterBytes.fill(0);
    newMasterBytes.fill(0);
    oldCek.fill(0);
    oldCommit.fill(0);
    newCek.fill(0);
    newCommit.fill(0);
  }
}
