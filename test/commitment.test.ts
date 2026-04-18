import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { computeCommitment, verifyCommitment } from '../src/primitives/commitment.js';

describe('key commitment (HMAC-SHA256)', () => {
  const commitKey = randomBytes(32);
  const id = 'b_abc123';
  const rawCt = randomBytes(128);

  describe('computeCommitment', () => {
    it('returns a 32-byte tag', () => {
      expect(computeCommitment(commitKey, id, rawCt).length).toBe(32);
    });

    it('is deterministic for the same inputs', () => {
      const c1 = computeCommitment(commitKey, id, rawCt);
      const c2 = computeCommitment(commitKey, id, rawCt);
      expect(Buffer.from(c1)).toEqual(Buffer.from(c2));
    });

    it('produces a different tag for a different key', () => {
      const c1 = computeCommitment(commitKey, id, rawCt);
      const c2 = computeCommitment(randomBytes(32), id, rawCt);
      expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
    });

    it('produces a different tag for a different id', () => {
      const c1 = computeCommitment(commitKey, id, rawCt);
      const c2 = computeCommitment(commitKey, 'b_different', rawCt);
      expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
    });

    it('produces a different tag for a different ciphertext', () => {
      const c1 = computeCommitment(commitKey, id, rawCt);
      const c2 = computeCommitment(commitKey, id, randomBytes(128));
      expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
    });
  });

  describe('verifyCommitment', () => {
    it('accepts a matching tag', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      expect(verifyCommitment(commitKey, id, rawCt, c)).toBe(true);
    });

    it('rejects a mutated tag', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      const mutated = Uint8Array.from(c);
      mutated[0] ^= 0x01;
      expect(verifyCommitment(commitKey, id, rawCt, mutated)).toBe(false);
    });

    it('rejects a tag of the wrong length without throwing', () => {
      const tooShort = new Uint8Array(16);
      expect(verifyCommitment(commitKey, id, rawCt, tooShort)).toBe(false);
      const tooLong = new Uint8Array(64);
      expect(verifyCommitment(commitKey, id, rawCt, tooLong)).toBe(false);
    });

    it('rejects when the key differs', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      expect(verifyCommitment(randomBytes(32), id, rawCt, c)).toBe(false);
    });

    it('rejects when the id differs', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      expect(verifyCommitment(commitKey, 'b_different', rawCt, c)).toBe(false);
    });

    it('rejects when the ciphertext differs', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      expect(verifyCommitment(commitKey, id, randomBytes(128), c)).toBe(false);
    });
  });

  describe('RFC 2104 HMAC-SHA256 structure', () => {
    // Smoke test: verify the underlying HMAC matches a known vector so
    // a swap of the noble/hashes implementation would be detected.
    it('produces a known tag for RFC 4231 test case 2', () => {
      // RFC 4231 §4.3 — key = "Jefe", data = "what do ya want for nothing?"
      // Expected: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
      const key = new TextEncoder().encode('Jefe');
      const data = new TextEncoder().encode('what do ya want for nothing?');
      // Our computeCommitment prepends the id string; use empty id so the
      // HMAC input is just `data`, matching the RFC vector.
      const tag = computeCommitment(key, '', data);
      expect(Buffer.from(tag).toString('hex')).toBe(
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
      );
    });
  });
});
