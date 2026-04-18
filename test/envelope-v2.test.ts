import { describe, expect, it } from 'vitest';
import {
  decryptV1,
  deserialize,
  deserializeV2,
  downgradeToV1,
  encryptV1,
  serializeV1,
  serializeV2,
  upgradeToV2,
} from '../src/envelope/index.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';

function keys() {
  const master = new Uint8Array(32).fill(0x42);
  return { cek: deriveContentKey(master), commitKey: deriveCommitKey(master) };
}

function makeV1() {
  const { cek, commitKey } = keys();
  const env = encryptV1({
    payload: { type: 'note', body: 'hello from v2 test' },
    cek,
    commitKey,
    kid: 'default',
  });
  return { env, cek, commitKey };
}

describe('envelope v2 (CBOR wire format)', () => {
  describe('upgrade / downgrade', () => {
    it('upgradeToV2 produces binary fields', () => {
      const { env } = makeV1();
      const v2 = upgradeToV2(env);
      expect(v2.v).toBe(2);
      expect(v2.id).toBe(env.id);
      expect(v2.ts).toBe(env.ts);
      expect(v2.enc.kid).toBe(env.enc.kid);
      expect(v2.enc.ct).toBeInstanceOf(Uint8Array);
      expect(v2.enc.commit).toBeInstanceOf(Uint8Array);
      expect(v2.enc.ct.length).toBe(env.enc['ct.len']);
    });

    it('downgradeToV1 is the inverse of upgradeToV2', () => {
      const { env } = makeV1();
      const back = downgradeToV1(upgradeToV2(env));
      expect(back).toEqual(env);
    });

    it('decrypts a payload that was upgraded and downgraded', () => {
      const { env, cek, commitKey } = makeV1();
      const v2 = upgradeToV2(env);
      const v1back = downgradeToV1(v2);
      expect(decryptV1(v1back, cek, commitKey)).toEqual({
        type: 'note',
        body: 'hello from v2 test',
      });
    });
  });

  describe('serialise / deserialise', () => {
    it('round-trips a v2 envelope through CBOR bytes', () => {
      const { env } = makeV1();
      const v2 = upgradeToV2(env);
      const bytes = serializeV2(v2);
      expect(bytes[0]).toBe(0x43); // 'C'
      expect(bytes[1]).toBe(0x4b); // 'K'
      expect(bytes[2]).toBe(0x42); // 'B'
      const parsed = deserializeV2(bytes);
      expect(parsed).toEqual(v2);
    });

    it('refuses to serialise a non-v2 envelope', () => {
      const { env } = makeV1();
      // @ts-expect-error — deliberate invalid input
      expect(() => serializeV2(env)).toThrow('version must be 2');
    });

    it('rejects CBOR bytes lacking the magic prefix', () => {
      expect(() => deserializeV2(new Uint8Array([0x01, 0x02, 0x03]))).toThrow('magic prefix');
    });

    it('rejects a CBOR envelope with a non-2 version field', async () => {
      // Build the bad bytes manually — serializeV2 refuses to emit v != 2,
      // so we bypass it via cborg directly.
      const { encode } = await import('cborg');
      const body = encode({
        v: 99,
        id: 'b_x',
        ts: 'now',
        enc: {
          alg: 'XChaCha20-Poly1305',
          kid: 'k',
          ct: new Uint8Array(1),
          commit: new Uint8Array(1),
        },
      });
      const bytes = new Uint8Array(3 + body.length);
      bytes.set([0x43, 0x4b, 0x42], 0);
      bytes.set(body, 3);
      expect(() => deserializeV2(bytes)).toThrow('unexpected version');
    });
  });

  describe('auto-detect deserialize()', () => {
    it('routes a v1 JSON blob to v1 parser', () => {
      const { env } = makeV1();
      const bytes = serializeV1(env);
      const parsed = deserialize(bytes);
      expect(parsed.v).toBe(1);
      expect(parsed).toEqual(env);
    });

    it('routes a v2 CBOR blob to v2 parser', () => {
      const { env } = makeV1();
      const v2 = upgradeToV2(env);
      const bytes = serializeV2(v2);
      const parsed = deserialize(bytes);
      expect(parsed.v).toBe(2);
    });

    it('decrypts a v2-transported envelope via downgrade', () => {
      const { env, cek, commitKey } = makeV1();
      const wire = serializeV2(upgradeToV2(env));
      const parsed = deserialize(wire);
      const v1 = parsed.v === 1 ? parsed : downgradeToV1(parsed);
      expect(decryptV1(v1, cek, commitKey)).toEqual({
        type: 'note',
        body: 'hello from v2 test',
      });
    });
  });
});
