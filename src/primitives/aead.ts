import { randomBytes } from 'node:crypto';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

const NONCE_LENGTH = 24;
const TAG_LENGTH = 16;

export interface AeadResult {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/**
 * Encrypt with XChaCha20-Poly1305 using a fresh random 24-byte nonce.
 * The nonce width makes random generation safe without a counter — the
 * birthday bound on 192-bit nonces is astronomically large for any
 * realistic message volume. Callers must never reuse a key/nonce pair.
 */
export function aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): AeadResult {
  const nonce = new Uint8Array(randomBytes(NONCE_LENGTH));
  return aeadEncryptWithNonce(key, nonce, plaintext, aad);
}

/**
 * Encrypt with a caller-supplied nonce. Intended for test vectors and
 * deterministic KAT verification only — production callers must use
 * {@link aeadEncrypt}, which generates a random nonce.
 */
export function aeadEncryptWithNonce(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): AeadResult {
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`Nonce must be ${NONCE_LENGTH} bytes, got ${nonce.length}`);
  }

  const cipher = xchacha20poly1305(key, nonce, aad);
  const sealed = cipher.encrypt(plaintext);

  const ciphertext = sealed.slice(0, sealed.length - TAG_LENGTH);
  const tag = sealed.slice(sealed.length - TAG_LENGTH);

  return { nonce, ciphertext, tag };
}

/**
 * Decrypt and verify XChaCha20-Poly1305. Throws on authentication
 * failure, on unexpected nonce width, or on any mismatch between the
 * supplied AAD and the AAD that was bound to the tag at encrypt time.
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

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.decrypt(sealed);
}
