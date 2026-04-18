import { randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

/** XChaCha20-Poly1305 nonce length in bytes. */
export const NONCE_LENGTH = 24;
/** Poly1305 authenticator length in bytes. */
export const TAG_LENGTH = 16;

export interface AeadResult {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/**
 * Encrypt with XChaCha20-Poly1305 using a fresh random 24-byte nonce.
 * The nonce width makes random generation safe without a counter — the
 * birthday bound on 192-bit nonces is astronomically large for any
 * realistic message volume. The public API does not accept a nonce
 * parameter; nonce reuse is a classic AEAD break and this library treats
 * "let the caller pick the nonce" as a footgun (see CLAUDE.md §2).
 */
export function aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): AeadResult {
  const nonce = new Uint8Array(randomBytes(NONCE_LENGTH));
  const cipher = xchacha20poly1305(key, nonce, aad);
  const sealed = cipher.encrypt(plaintext);

  return {
    nonce,
    ciphertext: sealed.subarray(0, sealed.length - TAG_LENGTH),
    tag: sealed.subarray(sealed.length - TAG_LENGTH),
  };
}

/**
 * Decrypt and verify XChaCha20-Poly1305. Throws on authentication
 * failure, on unexpected nonce or tag width, or on any mismatch between
 * the supplied AAD and the AAD that was bound to the tag at encrypt time.
 */
export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
  }
  if (tag.length !== TAG_LENGTH) {
    throw new Error(`Tag must be ${TAG_LENGTH} bytes, got ${tag.length}`);
  }

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.decrypt(sealed);
}
