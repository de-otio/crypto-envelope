import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NONCE_LENGTH, TAG_LENGTH, aeadDecrypt, aeadEncrypt } from '../src/primitives/aead.js';

describe('AEAD (XChaCha20-Poly1305)', () => {
  const key = randomBytes(32);
  const plaintext = new TextEncoder().encode('Hello, World!');
  const aad = new TextEncoder().encode('associated data');

  describe('encrypt/decrypt round-trip', () => {
    it('encrypts and decrypts successfully', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      expect(nonce.length).toBe(NONCE_LENGTH);
      expect(tag.length).toBe(TAG_LENGTH);
      expect(ciphertext.length).toBe(plaintext.length);

      const decrypted = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(decrypted).toEqual(plaintext);
    });

    it('produces different nonces each time', () => {
      const r1 = aeadEncrypt(key, plaintext, aad);
      const r2 = aeadEncrypt(key, plaintext, aad);
      expect(Buffer.from(r1.nonce).equals(Buffer.from(r2.nonce))).toBe(false);
    });

    it('produces different ciphertexts when nonces differ', () => {
      const r1 = aeadEncrypt(key, plaintext, aad);
      const r2 = aeadEncrypt(key, plaintext, aad);
      expect(Buffer.from(r1.ciphertext).equals(Buffer.from(r2.ciphertext))).toBe(false);
    });
  });

  describe('authentication failure cases', () => {
    it('rejects a wrong key', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(randomBytes(32), nonce, ciphertext, tag, aad)).toThrow();
    });

    it('rejects a tampered AAD', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const tamperedAad = new TextEncoder().encode('tampered data');
      expect(() => aeadDecrypt(key, nonce, ciphertext, tag, tamperedAad)).toThrow();
    });

    it('rejects an empty AAD when original had AAD', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(key, nonce, ciphertext, tag, new Uint8Array(0))).toThrow();
    });

    it('rejects a mutated tag', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const mutated = Uint8Array.from(tag);
      mutated[0] ^= 0x01;
      expect(() => aeadDecrypt(key, nonce, ciphertext, mutated, aad)).toThrow();
    });

    it('rejects a mutated ciphertext byte', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const mutated = Uint8Array.from(ciphertext);
      mutated[0] ^= 0x01;
      expect(() => aeadDecrypt(key, nonce, mutated, tag, aad)).toThrow();
    });

    it('rejects a mutated nonce byte', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      const mutated = Uint8Array.from(nonce);
      mutated[0] ^= 0x01;
      expect(() => aeadDecrypt(key, mutated, ciphertext, tag, aad)).toThrow();
    });
  });

  describe('input validation', () => {
    it('rejects nonces that are not 24 bytes on decrypt', () => {
      const { ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(key, new Uint8Array(12), ciphertext, tag, aad)).toThrow(
        'Nonce must be 24 bytes',
      );
    });

    it('rejects tags that are not 16 bytes on decrypt', () => {
      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);
      expect(() => aeadDecrypt(key, nonce, ciphertext, tag.slice(0, 8), aad)).toThrow(
        'Tag must be 16 bytes',
      );
    });
  });

  describe('edge sizes', () => {
    it('handles empty plaintext', () => {
      const empty = new Uint8Array(0);
      const { nonce, ciphertext, tag } = aeadEncrypt(key, empty, aad);
      expect(ciphertext.length).toBe(0);
      expect(tag.length).toBe(TAG_LENGTH);
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

  describe('IETF CFRG XChaCha20-Poly1305 KAT (draft-irtf-cfrg-xchacha §A.3.1)', () => {
    // Decrypting a known-answer vector exercises the whole wrapper against
    // externally-published bytes, so a regression in @noble/ciphers or in
    // our ciphertext/tag split will fail this test.
    const kat_key = Buffer.from(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
      'hex',
    );
    const kat_nonce = Buffer.from('404142434445464748494a4b4c4d4e4f5051525354555657', 'hex');
    const kat_aad = Buffer.from('50515253c0c1c2c3c4c5c6c7', 'hex');
    const kat_pt =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const kat_ct_plus_tag = Buffer.from(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
        '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
        '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
        '21f9664c97637da9768812f615c68b13b52e' +
        'c0875924c1c7987947deafd8780acf49',
      'hex',
    );

    it('decrypts the KAT ciphertext to the expected plaintext', () => {
      const ct = kat_ct_plus_tag.subarray(0, kat_ct_plus_tag.length - TAG_LENGTH);
      const tag = kat_ct_plus_tag.subarray(kat_ct_plus_tag.length - TAG_LENGTH);
      const recovered = aeadDecrypt(kat_key, kat_nonce, ct, tag, kat_aad);
      expect(new TextDecoder().decode(recovered)).toBe(kat_pt);
    });
  });
});
