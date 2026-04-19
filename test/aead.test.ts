import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  AES_GCM_NONCE_LENGTH,
  KEY_LENGTH,
  TAG_LENGTH,
  XCHACHA_NONCE_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
  nonceLengthFor,
} from '../src/primitives/aead.js';
import type { Algorithm } from '../src/types.js';

// ── Parameterised suite: every invariant must hold for every algorithm ──

const ALGORITHMS: Array<{ alg: Algorithm; nonceLen: number }> = [
  { alg: 'XChaCha20-Poly1305', nonceLen: XCHACHA_NONCE_LENGTH },
  { alg: 'AES-256-GCM', nonceLen: AES_GCM_NONCE_LENGTH },
];

for (const { alg, nonceLen } of ALGORITHMS) {
  describe(`AEAD (${alg})`, () => {
    const key = randomBytes(KEY_LENGTH);
    const plaintext = new TextEncoder().encode('Hello, World!');
    const aad = new TextEncoder().encode('associated data');

    describe('encrypt/decrypt round-trip', () => {
      it('encrypts and decrypts successfully', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);

        expect(nonce.length).toBe(nonceLen);
        expect(tag.length).toBe(TAG_LENGTH);
        expect(ciphertext.length).toBe(plaintext.length);
        expect(nonceLengthFor(alg)).toBe(nonceLen);

        const decrypted = aeadDecrypt(alg, key, nonce, ciphertext, tag, aad);
        expect(decrypted).toEqual(plaintext);
      });

      it('produces different nonces each time', () => {
        const r1 = aeadEncrypt(alg, key, plaintext, aad);
        const r2 = aeadEncrypt(alg, key, plaintext, aad);
        expect(Buffer.from(r1.nonce).equals(Buffer.from(r2.nonce))).toBe(false);
      });

      it('produces different ciphertexts when nonces differ', () => {
        const r1 = aeadEncrypt(alg, key, plaintext, aad);
        const r2 = aeadEncrypt(alg, key, plaintext, aad);
        expect(Buffer.from(r1.ciphertext).equals(Buffer.from(r2.ciphertext))).toBe(false);
      });
    });

    describe('authentication failure cases', () => {
      it('rejects a wrong key', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        expect(() =>
          aeadDecrypt(alg, randomBytes(KEY_LENGTH), nonce, ciphertext, tag, aad),
        ).toThrow();
      });

      it('rejects a tampered AAD', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        const tamperedAad = new TextEncoder().encode('tampered data');
        expect(() => aeadDecrypt(alg, key, nonce, ciphertext, tag, tamperedAad)).toThrow();
      });

      it('rejects an empty AAD when original had AAD', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        expect(() => aeadDecrypt(alg, key, nonce, ciphertext, tag, new Uint8Array(0))).toThrow();
      });

      it('rejects a mutated tag', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        const mutated = Uint8Array.from(tag);
        mutated[0] ^= 0x01;
        expect(() => aeadDecrypt(alg, key, nonce, ciphertext, mutated, aad)).toThrow();
      });

      it('rejects a mutated ciphertext byte', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        const mutated = Uint8Array.from(ciphertext);
        mutated[0] ^= 0x01;
        expect(() => aeadDecrypt(alg, key, nonce, mutated, tag, aad)).toThrow();
      });

      it('rejects a mutated nonce byte', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        const mutated = Uint8Array.from(nonce);
        mutated[0] ^= 0x01;
        expect(() => aeadDecrypt(alg, key, mutated, ciphertext, tag, aad)).toThrow();
      });
    });

    describe('input validation', () => {
      it(`rejects nonces that are not ${nonceLen} bytes on decrypt`, () => {
        const { ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        const wrongWidth =
          nonceLen === XCHACHA_NONCE_LENGTH ? AES_GCM_NONCE_LENGTH : XCHACHA_NONCE_LENGTH;
        expect(() =>
          aeadDecrypt(alg, key, new Uint8Array(wrongWidth), ciphertext, tag, aad),
        ).toThrow(new RegExp(`nonce must be ${nonceLen} bytes`, 'i'));
      });

      it('rejects tags that are not 16 bytes on decrypt', () => {
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, aad);
        expect(() => aeadDecrypt(alg, key, nonce, ciphertext, tag.slice(0, 8), aad)).toThrow(
          new RegExp(`tag must be ${TAG_LENGTH} bytes`, 'i'),
        );
      });

      it('rejects keys that are not 32 bytes', () => {
        expect(() => aeadEncrypt(alg, randomBytes(16), plaintext, aad)).toThrow(
          new RegExp(`key must be ${KEY_LENGTH} bytes`, 'i'),
        );
      });
    });

    describe('edge sizes', () => {
      it('handles empty plaintext', () => {
        const empty = new Uint8Array(0);
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, empty, aad);
        expect(ciphertext.length).toBe(0);
        expect(tag.length).toBe(TAG_LENGTH);
        const decrypted = aeadDecrypt(alg, key, nonce, ciphertext, tag, aad);
        expect(decrypted.length).toBe(0);
      });

      it('handles empty AAD', () => {
        const emptyAad = new Uint8Array(0);
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, plaintext, emptyAad);
        const decrypted = aeadDecrypt(alg, key, nonce, ciphertext, tag, emptyAad);
        expect(decrypted).toEqual(plaintext);
      });

      it('handles large payloads', () => {
        const large = randomBytes(100_000);
        const { nonce, ciphertext, tag } = aeadEncrypt(alg, key, large, aad);
        const decrypted = aeadDecrypt(alg, key, nonce, ciphertext, tag, aad);
        expect(Buffer.from(decrypted)).toEqual(large);
      });
    });
  });
}

// ── Cross-algorithm substitution rejection ──────────────────────────────

describe('AEAD cross-algorithm substitution', () => {
  const key = randomBytes(KEY_LENGTH);
  const plaintext = new TextEncoder().encode('cross-algorithm test');
  const aad = new TextEncoder().encode('aad');

  it('XChaCha-produced ciphertext does not decrypt as AES-GCM', () => {
    const { nonce, ciphertext, tag } = aeadEncrypt('XChaCha20-Poly1305', key, plaintext, aad);
    // XChaCha nonce is 24 bytes; AES-GCM expects 12 — fails width check.
    expect(() => aeadDecrypt('AES-256-GCM', key, nonce, ciphertext, tag, aad)).toThrow(
      /nonce must be 12 bytes/i,
    );
  });

  it('AES-GCM-produced ciphertext does not decrypt as XChaCha', () => {
    const { nonce, ciphertext, tag } = aeadEncrypt('AES-256-GCM', key, plaintext, aad);
    // AES-GCM nonce is 12 bytes; XChaCha expects 24 — fails width check.
    expect(() => aeadDecrypt('XChaCha20-Poly1305', key, nonce, ciphertext, tag, aad)).toThrow(
      /nonce must be 24 bytes/i,
    );
  });

  it('AES-GCM ciphertext fails to authenticate under XChaCha even with a 24-byte nonce', () => {
    // Synthesise a pathological case: AES-GCM ciphertext with a padded
    // 24-byte "nonce" handed to XChaCha. Different keystream → auth fails.
    // This documents the non-crypto defence (width check) is what stops
    // the cross-alg substitution in practice.
    const { ciphertext, tag } = aeadEncrypt('AES-256-GCM', key, plaintext, aad);
    const padded = new Uint8Array(XCHACHA_NONCE_LENGTH);
    padded.set(randomBytes(AES_GCM_NONCE_LENGTH), 0);
    expect(() => aeadDecrypt('XChaCha20-Poly1305', key, padded, ciphertext, tag, aad)).toThrow();
  });
});

// ── IETF CFRG XChaCha20-Poly1305 KAT (unchanged from v0.1) ──────────────

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
    const recovered = aeadDecrypt('XChaCha20-Poly1305', kat_key, kat_nonce, ct, tag, kat_aad);
    expect(new TextDecoder().decode(recovered)).toBe(kat_pt);
  });
});
