import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptV1, deserializeV1, encryptV1, serializeV1 } from '../src/envelope/v1.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';
import type { EnvelopeV1 } from '../src/types.js';

function keys() {
  const master = new Uint8Array(32).fill(0x42);
  return { cek: deriveContentKey(master), commitKey: deriveCommitKey(master) };
}

describe('envelope v1 (JSON wire format)', () => {
  describe('round-trip', () => {
    it('encrypts and decrypts a simple payload', () => {
      const { cek, commitKey } = keys();
      const payload = { type: 'note', body: 'hello' };

      const envelope = encryptV1({ payload, cek, commitKey, kid: 'default' });
      expect(envelope.v).toBe(1);
      expect(envelope.id).toMatch(/^b_/);
      expect(envelope.enc.alg).toBe('XChaCha20-Poly1305');
      expect(envelope.enc.kid).toBe('default');
      expect(typeof envelope.enc.ct).toBe('string');
      expect(typeof envelope.enc.commit).toBe('string');

      const recovered = decryptV1(envelope, cek, commitKey);
      expect(recovered).toEqual(payload);
    });

    it('handles a nested payload with arrays and nulls', () => {
      const { cek, commitKey } = keys();
      const payload = {
        tags: ['a', 'b', 'c'],
        meta: { author: 'x', year: 2026, draft: false, rating: null },
        body: 'the quick brown fox',
      };

      const envelope = encryptV1({ payload, cek, commitKey, kid: 'k1' });
      expect(decryptV1(envelope, cek, commitKey)).toEqual(payload);
    });

    it('produces a valid ISO 8601 timestamp', () => {
      const { cek, commitKey } = keys();
      const envelope = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
      });
      expect(Number.isNaN(new Date(envelope.ts).getTime())).toBe(false);
    });

    it('respects caller-supplied id and ts', () => {
      const { cek, commitKey } = keys();
      const envelope = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
        id: 'b_fixed_id',
        ts: '2026-04-18T12:00:00Z',
      });
      expect(envelope.id).toBe('b_fixed_id');
      expect(envelope.ts).toBe('2026-04-18T12:00:00Z');
    });

    it('ct.len matches decoded ciphertext length', () => {
      const { cek, commitKey } = keys();
      const envelope = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
      });
      expect(Buffer.from(envelope.enc.ct, 'base64').length).toBe(envelope.enc['ct.len']);
    });
  });

  describe('tamper rejection', () => {
    function freshEnvelope(): { env: EnvelopeV1; cek: Uint8Array; commitKey: Uint8Array } {
      const { cek, commitKey } = keys();
      const env = encryptV1({
        payload: { type: 'note', body: 'secret' },
        cek,
        commitKey,
        kid: 'default',
      });
      return { env, cek, commitKey };
    }

    it('rejects a mutated id', () => {
      const { env, cek, commitKey } = freshEnvelope();
      expect(() => decryptV1({ ...env, id: 'b_tampered' }, cek, commitKey)).toThrow();
    });

    it('rejects a mutated kid', () => {
      const { env, cek, commitKey } = freshEnvelope();
      expect(() =>
        decryptV1({ ...env, enc: { ...env.enc, kid: 'attacker' } }, cek, commitKey),
      ).toThrow();
    });

    it('rejects a mutated commitment', () => {
      const { env, cek, commitKey } = freshEnvelope();
      const fake = Buffer.alloc(32, 0xff).toString('base64');
      expect(() =>
        decryptV1({ ...env, enc: { ...env.enc, commit: fake } }, cek, commitKey),
      ).toThrow('key commitment verification failed');
    });

    it('rejects a mutated ciphertext byte', () => {
      const { env, cek, commitKey } = freshEnvelope();
      const ctBytes = Buffer.from(env.enc.ct, 'base64');
      ctBytes[30] ^= 0x01;
      const tampered = {
        ...env,
        enc: { ...env.enc, ct: ctBytes.toString('base64') },
      };
      // Commitment is computed over rawCt — flipping a byte breaks it
      // before AEAD verify even runs.
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow();
    });

    it('rejects a ct.len mismatch', () => {
      const { env, cek, commitKey } = freshEnvelope();
      expect(() =>
        decryptV1({ ...env, enc: { ...env.enc, 'ct.len': env.enc['ct.len'] + 1 } }, cek, commitKey),
      ).toThrow('ciphertext length mismatch');
    });

    it('rejects a truncated ciphertext', () => {
      const { env, cek, commitKey } = freshEnvelope();
      const tooShort = Buffer.alloc(10).toString('base64');
      expect(() =>
        decryptV1(
          {
            ...env,
            enc: { ...env.enc, ct: tooShort, 'ct.len': 10 },
          },
          cek,
          commitKey,
        ),
      ).toThrow('truncated ciphertext');
    });

    it('rejects an unsupported version', () => {
      const { env, cek, commitKey } = freshEnvelope();
      expect(() => decryptV1({ ...env, v: 9 as unknown as 1 }, cek, commitKey)).toThrow(
        'unsupported envelope version',
      );
    });

    it('rejects an unsupported algorithm', () => {
      const { env, cek, commitKey } = freshEnvelope();
      expect(() =>
        decryptV1(
          { ...env, enc: { ...env.enc, alg: 'AES-CBC' as 'XChaCha20-Poly1305' } },
          cek,
          commitKey,
        ),
      ).toThrow('unsupported algorithm');
    });
  });

  describe('wrong keys', () => {
    it('rejects a different CEK', () => {
      const { cek, commitKey } = keys();
      const env = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
      });
      const other = new Uint8Array(randomBytes(32));
      expect(() => decryptV1(env, other, commitKey)).toThrow();
    });

    it('rejects a different commit key', () => {
      const { cek, commitKey } = keys();
      const env = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
      });
      const other = new Uint8Array(randomBytes(32));
      expect(() => decryptV1(env, cek, other)).toThrow('key commitment verification failed');
    });
  });

  describe('serialisation', () => {
    it('round-trips through JSON bytes', () => {
      const { cek, commitKey } = keys();
      const env = encryptV1({
        payload: { x: 1 },
        cek,
        commitKey,
        kid: 'default',
      });
      const bytes = serializeV1(env);
      const parsed = deserializeV1(bytes);
      expect(parsed).toEqual(env);
      expect(decryptV1(parsed, cek, commitKey)).toEqual({ x: 1 });
    });

    it('rejects JSON bytes with wrong version', () => {
      const bogus = new TextEncoder().encode(JSON.stringify({ v: 99 }));
      expect(() => deserializeV1(bogus)).toThrow('unexpected version');
    });
  });
});
