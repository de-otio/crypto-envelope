import { describe, expect, it } from 'vitest';
import { deriveCommitKey, deriveContentKey, deriveKey } from '../src/primitives/hkdf.js';

describe('HKDF-SHA256', () => {
  describe('deriveKey', () => {
    it('produces 32 bytes by default', () => {
      const ikm = new Uint8Array(32).fill(0x0b);
      expect(deriveKey(ikm, 'test-info').length).toBe(32);
    });

    it('produces different output for different info strings', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      const k1 = deriveKey(ikm, 'info-one');
      const k2 = deriveKey(ikm, 'info-two');
      expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
    });

    it('produces different output for different salts', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      const k1 = deriveKey(ikm, 'info', new Uint8Array(16).fill(0xaa));
      const k2 = deriveKey(ikm, 'info', new Uint8Array(16).fill(0xbb));
      expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
    });

    it('is deterministic', () => {
      const ikm = new Uint8Array(32).fill(0x42);
      const k1 = deriveKey(ikm, 'determinism-test');
      const k2 = deriveKey(ikm, 'determinism-test');
      expect(Buffer.from(k1)).toEqual(Buffer.from(k2));
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

    it('accepts an empty IKM (RFC 5869 does not forbid it)', () => {
      expect(deriveKey(new Uint8Array(0), 'empty-ikm').length).toBe(32);
    });

    it('rejects zero output length', () => {
      expect(() => deriveKey(new Uint8Array(32), 'info', undefined, 0)).toThrow(RangeError);
    });

    it('rejects output length above RFC 5869 SHA-256 maximum (255 * 32)', () => {
      expect(() => deriveKey(new Uint8Array(32), 'info', undefined, 255 * 32 + 1)).toThrow(
        RangeError,
      );
    });

    it('accepts output length equal to the RFC 5869 SHA-256 maximum', () => {
      expect(deriveKey(new Uint8Array(32), 'info', undefined, 255 * 32).length).toBe(255 * 32);
    });
  });

  describe('RFC 5869 Appendix A.1 (SHA-256)', () => {
    it('matches the published OKM byte-for-byte', async () => {
      // The deriveKey API takes info as a string; RFC 5869 test vectors
      // use raw info bytes (0xf0..0xf9). We call @noble/hashes directly
      // here to assert against the RFC expected value; this guards the
      // underlying library version we pin.
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
      expect(Buffer.from(hkdf(sha256, ikm, salt, info, 42))).toEqual(expected);
    });
  });

  describe('deriveKey wrapper pinned output', () => {
    // Pinned against the wrapper itself. Guards against future wrapper
    // changes — swapping the info encoder (e.g. UTF-16), default salt,
    // or default length would break this test.
    it('produces a stable output for a fixed (ikm, info, salt, len)', () => {
      const ikm = new Uint8Array(32).fill(0x0b);
      const salt = new Uint8Array(16).fill(0x42);
      const out = deriveKey(ikm, 'envelope-test/v1', salt, 32);
      expect(Buffer.from(out).toString('hex')).toBe(
        '07df1037781ff1c2ca474605eb418aed7f855163c74e1a15451c0f7ad0235237',
      );
    });
  });

  describe('named helpers', () => {
    it('deriveContentKey and deriveCommitKey produce distinct bytes from the same IKM', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      const content = deriveContentKey(ikm);
      const commit = deriveCommitKey(ikm);
      expect(content.length).toBe(32);
      expect(commit.length).toBe(32);
      expect(Buffer.from(content).equals(Buffer.from(commit))).toBe(false);
    });

    it('named helpers are deterministic', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      expect(Buffer.from(deriveContentKey(ikm))).toEqual(Buffer.from(deriveContentKey(ikm)));
      expect(Buffer.from(deriveCommitKey(ikm))).toEqual(Buffer.from(deriveCommitKey(ikm)));
    });

    it('named helpers use the documented info strings', () => {
      const ikm = new Uint8Array(32).fill(0x01);
      expect(Buffer.from(deriveContentKey(ikm))).toEqual(
        Buffer.from(deriveKey(ikm, 'crypto-envelope/v1/content')),
      );
      expect(Buffer.from(deriveCommitKey(ikm))).toEqual(
        Buffer.from(deriveKey(ikm, 'crypto-envelope/v1/commit')),
      );
    });
  });
});
