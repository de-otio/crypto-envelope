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

    it('rejects a prefix of the correct tag', () => {
      const c = computeCommitment(commitKey, id, rawCt);
      expect(verifyCommitment(commitKey, id, rawCt, c.slice(0, 16))).toBe(false);
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

  describe('external KATs', () => {
    // RFC 4231 §4.3 — HMAC-SHA256 test case 2, key="Jefe",
    // data="what do ya want for nothing?". We invoke through
    // computeCommitment with an empty id so the HMAC input is just data.
    it('matches RFC 4231 HMAC-SHA256 test case 2 (empty id)', () => {
      const key = new TextEncoder().encode('Jefe');
      const data = new TextEncoder().encode('what do ya want for nothing?');
      const tag = computeCommitment(key, '', data);
      expect(Buffer.from(tag).toString('hex')).toBe(
        '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
      );
    });

    it('pins a non-empty-id vector so a refactor dropping the id prefix is caught', async () => {
      // Cross-check against a direct HMAC(key, id_bytes || data) with
      // @noble/hashes. Any wrapper change that reorders, drops, or
      // double-encodes the id will break this.
      const { hmac } = await import('@noble/hashes/hmac.js');
      const { sha256 } = await import('@noble/hashes/sha2.js');
      const key = new TextEncoder().encode('Jefe');
      const data = new TextEncoder().encode('what do ya want for nothing?');
      const idStr = 'b_envelope_id';
      const idBytes = new TextEncoder().encode(idStr);
      const combined = new Uint8Array(idBytes.length + data.length);
      combined.set(idBytes, 0);
      combined.set(data, idBytes.length);
      const expected = hmac(sha256, key, combined);

      expect(Buffer.from(computeCommitment(key, idStr, data))).toEqual(Buffer.from(expected));
    });
  });
});
