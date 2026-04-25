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
import { rewrapEnvelope } from '../src/envelope/rewrap.js';
import { asMasterKey } from '../src/passphrase.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';
import { SecureBuffer } from '../src/secure-buffer.js';
import type { EnvelopeV2 } from '../src/types.js';

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

// ---------------------------------------------------------------------------
// T7 — v2 tamper-rejection (was absent from the original suite)
// For both XChaCha20-Poly1305 and AES-256-GCM, mutate each CBOR field
// individually and assert decrypt throws. v2 envelopes are decrypted by
// downgrading to v1 first, so the tamper checks go through the same
// commitment + AEAD path as v1.
// ---------------------------------------------------------------------------

function makeV2(alg: 'XChaCha20-Poly1305' | 'AES-256-GCM' = 'XChaCha20-Poly1305') {
  const master =
    alg === 'AES-256-GCM' ? new Uint8Array(32).fill(0x44) : new Uint8Array(32).fill(0x42);
  const cek = deriveContentKey(master);
  const commitKey = deriveCommitKey(master);
  const v1 = encryptV1({
    payload: { type: 'v2-tamper-test', body: 'secret', alg },
    cek,
    commitKey,
    kid: 'default',
    algorithm: alg,
  });
  const v2 = upgradeToV2(v1);
  return { v2, cek, commitKey };
}

function decryptV2(
  v2: ReturnType<typeof makeV2>['v2'],
  cek: Uint8Array,
  commitKey: Uint8Array,
): Record<string, unknown> {
  return decryptV1(downgradeToV1(v2), cek, commitKey);
}

describe('envelope v2 tamper-rejection (XChaCha20-Poly1305)', () => {
  it('rejects a mutated id field', () => {
    const { v2, cek, commitKey } = makeV2();
    expect(() => decryptV2({ ...v2, id: 'b_fake' }, cek, commitKey)).toThrow();
  });

  it('rejects a mutated kid field', () => {
    const { v2, cek, commitKey } = makeV2();
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, kid: 'attacker' } }, cek, commitKey),
    ).toThrow();
  });

  it('rejects a mutated alg field', () => {
    const { v2, cek, commitKey } = makeV2('XChaCha20-Poly1305');
    // Swapping alg will change AAD; commitment + AEAD both reject.
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, alg: 'AES-256-GCM' } }, cek, commitKey),
    ).toThrow();
  });

  it('rejects a mutated commitment field', () => {
    const { v2, cek, commitKey } = makeV2();
    const fakeCommit = new Uint8Array(32).fill(0xff);
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, commit: fakeCommit } }, cek, commitKey),
    ).toThrow('key commitment verification failed');
  });

  it('rejects a single flipped bit in the ct field (nonce region)', () => {
    const { v2, cek, commitKey } = makeV2();
    const ct = new Uint8Array(v2.enc.ct);
    ct[0] ^= 0x01;
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });

  it('rejects a single flipped bit in the ct field (ciphertext body)', () => {
    const { v2, cek, commitKey } = makeV2();
    const ct = new Uint8Array(v2.enc.ct);
    ct[16] ^= 0x01; // past the XChaCha nonce (24 bytes); also past AES nonce (12)
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });

  it('rejects a single flipped bit in the ct field (tag region)', () => {
    const { v2, cek, commitKey } = makeV2();
    const ct = new Uint8Array(v2.enc.ct);
    ct[ct.length - 1] ^= 0x01; // last byte of tag
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });
});

describe('envelope v2 tamper-rejection (AES-256-GCM)', () => {
  it('rejects a mutated id field', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    expect(() => decryptV2({ ...v2, id: 'b_fake' }, cek, commitKey)).toThrow();
  });

  it('rejects a mutated kid field', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, kid: 'attacker' } }, cek, commitKey),
    ).toThrow();
  });

  it('rejects a mutated alg field', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, alg: 'XChaCha20-Poly1305' } }, cek, commitKey),
    ).toThrow();
  });

  it('rejects a mutated commitment field', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    const fakeCommit = new Uint8Array(32).fill(0xff);
    expect(() =>
      decryptV2({ ...v2, enc: { ...v2.enc, commit: fakeCommit } }, cek, commitKey),
    ).toThrow('key commitment verification failed');
  });

  it('rejects a single flipped bit in the ct field (nonce region)', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    const ct = new Uint8Array(v2.enc.ct);
    ct[0] ^= 0x01; // AES-GCM nonce is 12 bytes
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });

  it('rejects a single flipped bit in the ct field (ciphertext body)', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    const ct = new Uint8Array(v2.enc.ct);
    ct[12] ^= 0x01; // past 12-byte AES-GCM nonce
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });

  it('rejects a single flipped bit in the ct field (tag region)', () => {
    const { v2, cek, commitKey } = makeV2('AES-256-GCM');
    const ct = new Uint8Array(v2.enc.ct);
    ct[ct.length - 1] ^= 0x01;
    expect(() => decryptV2({ ...v2, enc: { ...v2.enc, ct } }, cek, commitKey)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// T7 — Cross-version tamper test
// Encrypt as v1, rewrap to v2, mutate a v2 byte, downgrade back to v1,
// decrypt MUST throw.
// ---------------------------------------------------------------------------

describe('cross-version tamper test', () => {
  it('v1 → upgrade v2 → mutate v2 byte → downgrade v1 → decrypt throws', () => {
    const master = new Uint8Array(32).fill(0x55);
    const cek = deriveContentKey(master);
    const commitKey = deriveCommitKey(master);

    // Step 1: encrypt v1.
    const v1 = encryptV1({
      payload: { secret: 'cross-version-tamper' },
      cek,
      commitKey,
      kid: 'default',
    });

    // Step 2: upgrade to v2.
    const v2 = upgradeToV2(v1);

    // Step 3: mutate a byte in v2's ct field (ciphertext body region).
    const mutatedCt = new Uint8Array(v2.enc.ct);
    mutatedCt[30] ^= 0xab;
    const tamperedV2 = { ...v2, enc: { ...v2.enc, ct: mutatedCt } };

    // Step 4: downgrade back to v1 and attempt decrypt — must throw.
    const backToV1 = downgradeToV1(tamperedV2);
    expect(() => decryptV1(backToV1, cek, commitKey)).toThrow();
  });

  it('v1 → rewrap to v2 → mutate v2 ct → downgrade → decrypt throws', () => {
    // This path exercises rewrapEnvelope's v2 output as well.
    const masterBytesA = new Uint8Array(32).fill(0x56);
    const masterBytesB = new Uint8Array(32).fill(0x57);
    const cekB = deriveContentKey(masterBytesB);
    const commitKeyB = deriveCommitKey(masterBytesB);

    const oldMaster = asMasterKey(SecureBuffer.from(Uint8Array.from(masterBytesA)));
    const newMaster = asMasterKey(SecureBuffer.from(Uint8Array.from(masterBytesB)));
    const cek = deriveContentKey(masterBytesA);
    const commitKey = deriveCommitKey(masterBytesA);

    // Encrypt v1 under oldMaster then upgrade to v2.
    const origV1 = encryptV1({ payload: { x: 1 }, cek, commitKey, kid: 'default' });
    const origV2 = upgradeToV2(origV1);

    // Rewrap v2 under newMaster — result is v2.
    const rewrappedV2 = rewrapEnvelope(origV2, oldMaster, newMaster) as EnvelopeV2;
    expect(rewrappedV2.v).toBe(2);

    // Mutate a ct byte in the rewrapped v2.
    const mutCt = new Uint8Array(rewrappedV2.enc.ct);
    mutCt[20] ^= 0xff;
    const tamperedV2 = { ...rewrappedV2, enc: { ...rewrappedV2.enc, ct: mutCt } };

    // Downgrade and decrypt must throw.
    const backV1 = downgradeToV1(tamperedV2);
    expect(() => decryptV1(backV1, cekB, commitKeyB)).toThrow();
  });
});
