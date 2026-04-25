import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { deriveCommitKey, deriveContentKey, deriveKey } from '../src/primitives/hkdf.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadJson<T>(relPath: string): T {
  return JSON.parse(readFileSync(join(__dirname, relPath), 'utf8')) as T;
}

interface Rfc5869A1Vector {
  inputs: { ikmHex: string; saltHex: string; infoHex: string; length: number };
  expected: { prkHex: string; okmHex: string };
}

interface EnvelopeWrapperPinnedVector {
  inputs: { ikmHex: string; saltHex: string; info: string; length: number };
  expected: { okmHex: string };
}

const rfc5869A1 = loadJson<Rfc5869A1Vector>('vectors/hkdf/rfc-5869-a1.json');
const wrapperPinned = loadJson<EnvelopeWrapperPinnedVector>(
  'vectors/hkdf/envelope-wrapper-pinned.json',
);

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
    // Data loaded from test/vectors/hkdf/rfc-5869-a1.json.
    it('matches the published OKM byte-for-byte', async () => {
      // The deriveKey API takes info as a string; RFC 5869 test vectors
      // use raw info bytes (0xf0..0xf9). We call @noble/hashes directly
      // here to assert against the RFC expected value; this guards the
      // underlying library version we pin.
      const { hkdf } = await import('@noble/hashes/hkdf.js');
      const { sha256 } = await import('@noble/hashes/sha2.js');
      const ikm = Buffer.from(rfc5869A1.inputs.ikmHex, 'hex');
      const salt = Buffer.from(rfc5869A1.inputs.saltHex, 'hex');
      const info = Buffer.from(rfc5869A1.inputs.infoHex, 'hex');
      const expected = Buffer.from(rfc5869A1.expected.okmHex, 'hex');
      expect(Buffer.from(hkdf(sha256, ikm, salt, info, rfc5869A1.inputs.length))).toEqual(expected);
    });
  });

  describe('deriveKey wrapper pinned output', () => {
    // Data loaded from test/vectors/hkdf/envelope-wrapper-pinned.json.
    // Guards against future wrapper changes — swapping the info encoder
    // (e.g. UTF-16), default salt, or default length would break this test.
    it('produces a stable output for a fixed (ikm, info, salt, len)', () => {
      const ikm = Buffer.from(wrapperPinned.inputs.ikmHex, 'hex');
      const salt = Buffer.from(wrapperPinned.inputs.saltHex, 'hex');
      const out = deriveKey(ikm, wrapperPinned.inputs.info, salt, wrapperPinned.inputs.length);
      expect(Buffer.from(out).toString('hex')).toBe(wrapperPinned.expected.okmHex);
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
