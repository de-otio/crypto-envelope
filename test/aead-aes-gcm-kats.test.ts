import { describe, expect, it } from 'vitest';
import { aeadDecrypt, aeadEncrypt } from '../src/primitives/aead.js';
import { NIST_SP_800_38D_AES_256_GCM } from './vectors/aead/nist-sp-800-38d.js';

const fromHex = (s: string): Uint8Array => Buffer.from(s, 'hex');
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

describe('AES-256-GCM — NIST SP 800-38D / McGrew-Viega KATs', () => {
  for (const v of NIST_SP_800_38D_AES_256_GCM) {
    describe(v.name, () => {
      const key = fromHex(v.key);
      const iv = fromHex(v.iv);
      const plaintext = fromHex(v.plaintext);
      const aad = fromHex(v.aad);
      const expectedCt = fromHex(v.ciphertext);
      const expectedTag = fromHex(v.tag);

      it('decrypts the reference ciphertext to the reference plaintext', () => {
        const recovered = aeadDecrypt('AES-256-GCM', key, iv, expectedCt, expectedTag, aad);
        expect(toHex(recovered)).toBe(v.plaintext);
      });

      it('rejects a bit-flipped tag', () => {
        const mutated = Uint8Array.from(expectedTag);
        mutated[0] ^= 0x01;
        expect(() => aeadDecrypt('AES-256-GCM', key, iv, expectedCt, mutated, aad)).toThrow();
      });

      if (expectedCt.length > 0) {
        it('rejects a bit-flipped ciphertext byte', () => {
          const mutated = Uint8Array.from(expectedCt);
          mutated[0] ^= 0x01;
          expect(() => aeadDecrypt('AES-256-GCM', key, iv, mutated, expectedTag, aad)).toThrow();
        });
      }

      if (aad.length > 0) {
        it('rejects a bit-flipped AAD byte', () => {
          const mutated = Uint8Array.from(aad);
          mutated[0] ^= 0x01;
          expect(() =>
            aeadDecrypt('AES-256-GCM', key, iv, expectedCt, expectedTag, mutated),
          ).toThrow();
        });
      }

      // Note: aeadEncrypt uses a fresh random nonce, so we cannot compare
      // its output against the KAT ciphertext directly. The decryption
      // direction is the KAT gate; encryption is exercised by the
      // round-trip tests in aead.test.ts.
    });
  }
});
