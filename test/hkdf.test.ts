import { describe, expect, it } from 'vitest';
import { deriveKey } from '../src/primitives/hkdf.js';

describe('HKDF-SHA256', () => {
  describe('deriveKey', () => {
    it('produces 32 bytes by default', () => {
      const ikm = new Uint8Array(32).fill(0x0b);
      expect(deriveKey(ikm, 'test-info').length).toBe(32);
    });

    it('produces different output for different info strings', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      const key1 = deriveKey(ikm, 'info-one');
      const key2 = deriveKey(ikm, 'info-two');
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it('produces different output for different salts', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      const key1 = deriveKey(ikm, 'info', new Uint8Array(16).fill(0xaa));
      const key2 = deriveKey(ikm, 'info', new Uint8Array(16).fill(0xbb));
      expect(Buffer.from(key1).equals(Buffer.from(key2))).toBe(false);
    });

    it('is deterministic', () => {
      const ikm = new Uint8Array(32).fill(0x42);
      const key1 = deriveKey(ikm, 'determinism-test');
      const key2 = deriveKey(ikm, 'determinism-test');
      expect(Buffer.from(key1)).toEqual(Buffer.from(key2));
    });

    it('supports custom output lengths', () => {
      const ikm = new Uint8Array(32).fill(0x0b);
      expect(deriveKey(ikm, 'test', undefined, 64).length).toBe(64);
    });

    it('treats undefined and empty salt identically', () => {
      const ikm = new Uint8Array(32).fill(0x0b);
      const withDefault = deriveKey(ikm, 'test');
      const withEmpty = deriveKey(ikm, 'test', new Uint8Array(0));
      expect(Buffer.from(withDefault)).toEqual(Buffer.from(withEmpty));
    });
  });

  describe('RFC 5869 test vector 1 (SHA-256)', () => {
    // From RFC 5869 Appendix A.1.
    //   IKM  = 0x0b repeated 22 times
    //   salt = 0x000102030405060708090a0b0c
    //   info = 0xf0f1f2f3f4f5f6f7f8f9
    //   L    = 42
    //   OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
    //          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
    //          34007208d5b887185865
    it('matches RFC 5869 Appendix A.1 expected OKM', async () => {
      // The deriveKey API takes a string info; RFC 5869 test vectors use raw bytes.
      // To test the vector exactly we call @noble/hashes directly.
      const { hkdf } = await import('@noble/hashes/hkdf.js');
      const { sha256 } = await import('@noble/hashes/sha2.js');
      const ikm = new Uint8Array(22).fill(0x0b);
      const salt = Uint8Array.from([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
      ]);
      const info = Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
      const expected = Buffer.from(
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
        'hex',
      );
      const okm = hkdf(sha256, ikm, salt, info, 42);
      expect(Buffer.from(okm)).toEqual(expected);
    });
  });
});
