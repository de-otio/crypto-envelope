import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { getRandomBytes } from '../internal/runtime.js';
import type { Algorithm } from '../types.js';

// ── Per-algorithm constants ──────────────────────────────────────────────

/** XChaCha20-Poly1305 nonce length in bytes (192-bit). */
export const XCHACHA_NONCE_LENGTH = 24;
/** AES-256-GCM nonce length in bytes (96-bit, per NIST SP 800-38D). */
export const AES_GCM_NONCE_LENGTH = 12;
/** Poly1305 / GCM authenticator length in bytes (128-bit, both algorithms). */
export const TAG_LENGTH = 16;
/** AEAD key length in bytes (256-bit, both algorithms). */
export const KEY_LENGTH = 32;

/** Look up the nonce width for a given AEAD algorithm. */
export function nonceLengthFor(alg: Algorithm): number {
  switch (alg) {
    case 'XChaCha20-Poly1305':
      return XCHACHA_NONCE_LENGTH;
    case 'AES-256-GCM':
      return AES_GCM_NONCE_LENGTH;
    default: {
      const _exhaustive: never = alg;
      throw new Error(`unknown algorithm: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Back-compat alias for callers imported before the algorithm dispatch
 * landed. Refers to the XChaCha20-Poly1305 nonce width because v0.1's
 * single-algorithm primitive used that size. New code should call
 * {@link nonceLengthFor} with an explicit algorithm.
 * @deprecated use `nonceLengthFor(alg)` instead
 */
export const NONCE_LENGTH = XCHACHA_NONCE_LENGTH;

export interface AeadResult {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

// ── Public dispatch surface ──────────────────────────────────────────────

/**
 * Encrypt with the given AEAD algorithm using a fresh random nonce drawn
 * from `globalThis.crypto.getRandomValues`. The public API does **not**
 * accept a nonce parameter — nonce reuse under a key is a classic AEAD
 * break and the library treats "let the caller pick the nonce" as a
 * footgun (see CLAUDE.md §2).
 *
 * Nonce-width implications:
 * - XChaCha20-Poly1305 uses a 192-bit nonce; the birthday bound on random
 *   generation is astronomical for any realistic message volume.
 * - AES-256-GCM uses a 96-bit nonce; the birthday bound is ~n² / 2⁹⁷ per
 *   NIST SP 800-38D §8.3. Consumers encrypting beyond ~2³² messages per
 *   key must rotate — enforced at the `EnvelopeClient` layer in Phase IV
 *   (design-review B2).
 */
export function aeadEncrypt(
  alg: Algorithm,
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): AeadResult {
  switch (alg) {
    case 'XChaCha20-Poly1305':
      return aeadEncryptXChaCha(key, plaintext, aad);
    case 'AES-256-GCM':
      return aeadEncryptAesGcm(key, plaintext, aad);
    default: {
      const _exhaustive: never = alg;
      throw new Error(`unsupported algorithm: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Decrypt and verify. Throws on authentication failure, on unexpected
 * nonce or tag width, or on any mismatch between the supplied AAD and the
 * AAD that was bound to the tag at encrypt time.
 *
 * Algorithm substitution is defeated at the envelope layer by binding
 * `alg` into the AAD (see `src/aad.ts`). A ciphertext produced with
 * XChaCha cannot be presented as AES-GCM (or vice versa) without AEAD
 * authentication failure.
 */
export function aeadDecrypt(
  alg: Algorithm,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  switch (alg) {
    case 'XChaCha20-Poly1305':
      return aeadDecryptXChaCha(key, nonce, ciphertext, tag, aad);
    case 'AES-256-GCM':
      return aeadDecryptAesGcm(key, nonce, ciphertext, tag, aad);
    default: {
      const _exhaustive: never = alg;
      throw new Error(`unsupported algorithm: ${String(_exhaustive)}`);
    }
  }
}

// ── XChaCha20-Poly1305 internals ─────────────────────────────────────────

function aeadEncryptXChaCha(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): AeadResult {
  checkKey(key, 'XChaCha20-Poly1305');
  const nonce = getRandomBytes(XCHACHA_NONCE_LENGTH);
  const cipher = xchacha20poly1305(key, nonce, aad);
  const sealed = cipher.encrypt(plaintext);

  return {
    nonce,
    ciphertext: sealed.subarray(0, sealed.length - TAG_LENGTH),
    tag: sealed.subarray(sealed.length - TAG_LENGTH),
  };
}

function aeadDecryptXChaCha(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  checkKey(key, 'XChaCha20-Poly1305');
  if (nonce.length !== XCHACHA_NONCE_LENGTH) {
    throw new Error(
      `XChaCha20-Poly1305 nonce must be ${XCHACHA_NONCE_LENGTH} bytes, got ${nonce.length}`,
    );
  }
  if (tag.length !== TAG_LENGTH) {
    throw new Error(`tag must be ${TAG_LENGTH} bytes, got ${tag.length}`);
  }

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.decrypt(sealed);
}

// ── AES-256-GCM internals ────────────────────────────────────────────────

function aeadEncryptAesGcm(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): AeadResult {
  checkKey(key, 'AES-256-GCM');
  const nonce = getRandomBytes(AES_GCM_NONCE_LENGTH);
  // `gcm(key, nonce, aad)` — @noble/ciphers v1+ factory shape. Returns an
  // object with .encrypt(plaintext) / .decrypt(sealed) that appends/consumes
  // a 16-byte GCM tag.
  const cipher = gcm(key, nonce, aad);
  const sealed = cipher.encrypt(plaintext);

  return {
    nonce,
    ciphertext: sealed.subarray(0, sealed.length - TAG_LENGTH),
    tag: sealed.subarray(sealed.length - TAG_LENGTH),
  };
}

function aeadDecryptAesGcm(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  checkKey(key, 'AES-256-GCM');
  if (nonce.length !== AES_GCM_NONCE_LENGTH) {
    throw new Error(`AES-256-GCM nonce must be ${AES_GCM_NONCE_LENGTH} bytes, got ${nonce.length}`);
  }
  if (tag.length !== TAG_LENGTH) {
    throw new Error(`tag must be ${TAG_LENGTH} bytes, got ${tag.length}`);
  }

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  const cipher = gcm(key, nonce, aad);
  return cipher.decrypt(sealed);
}

// ── Shared key-length check ──────────────────────────────────────────────

function checkKey(key: Uint8Array, alg: Algorithm): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`${alg} key must be ${KEY_LENGTH} bytes, got ${key.length}`);
  }
}
