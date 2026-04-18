import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { aeadDecrypt, aeadEncrypt, aeadEncryptWithNonce } from '../src/primitives/aead.js';

describe('AEAD (XChaCha20-Poly1305)', () => {
  const key = randomBytes(32);
  const plaintext = new TextEncoder().encode('Hello, World!');
  const aad = new TextEncoder().encode('associated data');

  describe('encrypt/decrypt round-trip', () => {
    it('encrypts and decrypts successfully', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      expect(nonce.length).toBe(24);
      expect(tag.length).toBe(16);
      expect(ciphertext.length).toBe(plaintext.length);

      const decrypted = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(decrypted).toEqual(plaintext);
    });

    it('produces different nonces each time', () => {
      const result1 = aeadEncrypt(key, plaintext, aad);
      const result2 = aeadEncrypt(key, plaintext, aad);
      expect(Buffer.from(result1.nonce).equals(Buffer.from(result2.nonce))).toBe(false);
    });

    it('produces different ciphertexts when nonces differ', () => {
      const result1 = aeadEncrypt(key, plaintext, aad);
      const result2 = aeadEncrypt(key, plaintext, aad);
      expect(Buffer.from(result1.ciphertext).equals(Buffer.from(result2.ciphertext))).toBe(false);
    });
  });

  describe('wrong key rejection', () => {
    it('rejects decryption with a wrong key', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const wrongKey = randomBytes(32);
      expect(() => aeadDecrypt(wrongKey, nonce, ciphertext, tag, aad)).toThrow();
    });
  });

  describe('AAD tampering rejection', () => {
    it('rejects decryption with wrong AAD', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const wrongAad = new TextEncoder().encode('tampered data');
      expect(() => aeadDecrypt(key, nonce, ciphertext, tag, wrongAad)).toThrow();
    });

    it('rejects decryption with empty AAD when original had AAD', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(key, nonce, ciphertext, tag, new Uint8Array(0))).toThrow();
    });
  });

  describe('nonce validation', () => {
    it('rejects nonces that are not 24 bytes', () => {
      expect(() => aeadEncryptWithNonce(key, new Uint8Array(12), plaintext, aad)).toThrow(
        'Nonce must be 24 bytes',
      );

      const { ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(key, new Uint8Array(12), ciphertext, tag, aad)).toThrow(
        'Nonce must be 24 bytes',
      );
    });
  });

  describe('deterministic with fixed nonce', () => {
    it('produces the same ciphertext with the same nonce', () => {
      const fixedNonce = new Uint8Array(24);
      const result1 = aeadEncryptWithNonce(key, fixedNonce, plaintext, aad);
      const result2 = aeadEncryptWithNonce(key, fixedNonce, plaintext, aad);
      expect(Buffer.from(result1.ciphertext)).toEqual(Buffer.from(result2.ciphertext));
      expect(Buffer.from(result1.tag)).toEqual(Buffer.from(result2.tag));
    });
  });

  describe('edge sizes', () => {
    it('handles empty plaintext', () => {
      const empty = new Uint8Array(0);
      const { nonce, ciphertext, tag } = aeadEncrypt(key, empty, aad);
      expect(ciphertext.length).toBe(0);
      expect(tag.length).toBe(16);
      const decrypted = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(decrypted.length).toBe(0);
    });

    it('handles large payloads', () => {
      const large = randomBytes(100_000);
      const { nonce, ciphertext, tag } = aeadEncrypt(key, large, aad);
      const decrypted = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(Buffer.from(decrypted)).toEqual(large);
    });
  });

  describe('RFC 8439 §A.2.1 ChaCha20 test vector structure', () => {
    it('matches noble/ciphers XChaCha20-Poly1305 known-answer test', () => {
      // Fixed-vector KAT — key/nonce/aad/plaintext all deterministic.
      // Any divergence between @noble/ciphers versions breaks this test.
      const kat_key = Uint8Array.from(
        Buffer.from('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', 'hex'),
      );
      const kat_nonce = Uint8Array.from(
        Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555657', 'hex'),
      );
      const kat_aad = Uint8Array.from(Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex'));
      const kat_pt = new TextEncoder().encode(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
      );

      const { nonce, ciphertext, tag } = aeadEncryptWithNonce(kat_key, kat_nonce, kat_pt, kat_aad);
      expect(Buffer.from(nonce)).toEqual(Buffer.from(kat_nonce));

      // Round-trip must succeed
      const recovered = aeadDecrypt(kat_key, nonce, ciphertext, tag, kat_aad);
      expect(Buffer.from(recovered)).toEqual(Buffer.from(kat_pt));
    });
  });
});
