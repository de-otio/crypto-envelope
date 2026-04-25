import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { computeCommitment, verifyCommitment } from '../src/primitives/commitment.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadJson<T>(relPath: string): T {
  return JSON.parse(readFileSync(join(__dirname, relPath), 'utf8')) as T;
}

interface CommitmentVector {
  inputs: { keyHex: string; id: string; dataHex: string };
  expected: { tagHex: string };
}

const rfc4231v3 = loadJson<CommitmentVector>('vectors/commitment/rfc-4231-4-3.json');
const nonEmptyId = loadJson<CommitmentVector>('vectors/commitment/non-empty-id-pinned.json');

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
    // Data loaded from test/vectors/commitment/rfc-4231-4-3.json.
    // RFC 4231 §4.3 — HMAC-SHA256 test case 2, key="Jefe",
    // data="what do ya want for nothing?". We invoke through
    // computeCommitment with an empty id so the HMAC input is just data.
    it('matches RFC 4231 HMAC-SHA256 test case 2 (empty id)', () => {
      const key = Buffer.from(rfc4231v3.inputs.keyHex, 'hex');
      const data = Buffer.from(rfc4231v3.inputs.dataHex, 'hex');
      const tag = computeCommitment(key, rfc4231v3.inputs.id, data);
      expect(Buffer.from(tag).toString('hex')).toBe(rfc4231v3.expected.tagHex);
    });

    // Data loaded from test/vectors/commitment/non-empty-id-pinned.json.
    // Cross-check against a direct HMAC(key, id_bytes || data) with
    // @noble/hashes. Any wrapper change that reorders, drops, or
    // double-encodes the id will break this.
    it('pins a non-empty-id vector so a refactor dropping the id prefix is caught', async () => {
      const { hmac } = await import('@noble/hashes/hmac.js');
      const { sha256 } = await import('@noble/hashes/sha2.js');
      const key = Buffer.from(nonEmptyId.inputs.keyHex, 'hex');
      const data = Buffer.from(nonEmptyId.inputs.dataHex, 'hex');
      const idStr = nonEmptyId.inputs.id;
      const idBytes = new TextEncoder().encode(idStr);
      const combined = new Uint8Array(idBytes.length + data.length);
      combined.set(idBytes, 0);
      combined.set(data, idBytes.length);
      const expected = hmac(sha256, key, combined);

      // Both the direct HMAC and our vector pin must agree.
      expect(Buffer.from(computeCommitment(key, idStr, data))).toEqual(Buffer.from(expected));
      expect(Buffer.from(computeCommitment(key, idStr, data)).toString('hex')).toBe(
        nonEmptyId.expected.tagHex,
      );
    });
  });
});
