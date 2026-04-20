import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { rewrapEnvelope } from '../src/envelope/rewrap.js';
import { decryptV1, encryptV1 } from '../src/envelope/v1.js';
import { downgradeToV1, upgradeToV2 } from '../src/envelope/v2.js';
import { asMasterKey } from '../src/passphrase.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';
import { SecureBuffer } from '../src/secure-buffer.js';
import type { Algorithm, AnyEnvelope, EnvelopeV1, EnvelopeV2, MasterKey } from '../src/types.js';

/**
 * Wrap raw 32-byte master-key material as a `MasterKey` via
 * `SecureBuffer.from` + `asMasterKey`. Note that `SecureBuffer.from`
 * zeroes the source `Uint8Array`, so this test helper takes a copy
 * internally.
 */
function masterFromBytes(bytes: Uint8Array): MasterKey {
  return asMasterKey(SecureBuffer.from(Uint8Array.from(bytes)));
}

function freshMaster(fill = 0x42): MasterKey {
  return masterFromBytes(new Uint8Array(32).fill(fill));
}

function encryptUnder(
  master: MasterKey,
  payload: Record<string, unknown>,
  opts: { kid?: string; algorithm?: Algorithm; id?: string; ts?: string } = {},
): EnvelopeV1 {
  const masterBytes = new Uint8Array(master.buffer);
  const cek = deriveContentKey(masterBytes);
  const commitKey = deriveCommitKey(masterBytes);
  try {
    return encryptV1({
      payload,
      cek,
      commitKey,
      kid: opts.kid ?? 'default',
      algorithm: opts.algorithm,
      id: opts.id,
      ts: opts.ts,
    });
  } finally {
    cek.fill(0);
    commitKey.fill(0);
  }
}

function decryptUnder(master: MasterKey, env: EnvelopeV1): Record<string, unknown> {
  const masterBytes = new Uint8Array(master.buffer);
  const cek = deriveContentKey(masterBytes);
  const commitKey = deriveCommitKey(masterBytes);
  try {
    return decryptV1(env, cek, commitKey);
  } finally {
    cek.fill(0);
    commitKey.fill(0);
  }
}

describe('rewrapEnvelope', () => {
  const payload = { type: 'note', body: 'hello', tags: ['a', 'b'] };

  describe('round-trip under the same master', () => {
    it('rewraps and decrypts back, with a fresh nonce/ct/tag/commitment', () => {
      const master = freshMaster(0x11);
      const orig = encryptUnder(master, payload);

      const rewrapped = rewrapEnvelope(orig, master, master) as EnvelopeV1;

      expect(rewrapped.v).toBe(1);
      expect(rewrapped.id).toBe(orig.id);
      expect(rewrapped.ts).toBe(orig.ts);
      expect(rewrapped.enc.alg).toBe(orig.enc.alg);
      expect(rewrapped.enc.kid).toBe(orig.enc.kid);

      // Regenerated under the same keys: ct and commitment differ (new
      // nonce and tag), same plaintext.
      expect(rewrapped.enc.ct).not.toEqual(orig.enc.ct);
      expect(rewrapped.enc.commit).not.toEqual(orig.enc.commit);

      expect(decryptUnder(master, rewrapped)).toEqual(payload);
      master.dispose();
    });
  });
});

describe('rewrapEnvelope — different master', () => {
  const payload = { type: 'note', body: 'rotated', n: 42 };

  it('transfers the payload to a new master (XChaCha20-Poly1305)', () => {
    const oldMaster = freshMaster(0x11);
    const newMaster = freshMaster(0x22);
    const orig = encryptUnder(oldMaster, payload, { kid: 'k1' });

    const rewrapped = rewrapEnvelope(orig, oldMaster, newMaster) as EnvelopeV1;

    // Identity preserved
    expect(rewrapped.id).toBe(orig.id);
    expect(rewrapped.ts).toBe(orig.ts);
    expect(rewrapped.enc.alg).toBe('XChaCha20-Poly1305');
    expect(rewrapped.enc.kid).toBe('k1');

    // Old master no longer opens it
    expect(() => decryptUnder(oldMaster, rewrapped)).toThrow();
    // New master does
    expect(decryptUnder(newMaster, rewrapped)).toEqual(payload);
  });

  it('transfers the payload to a new master (AES-256-GCM)', () => {
    const oldMaster = freshMaster(0x33);
    const newMaster = freshMaster(0x44);
    const orig = encryptUnder(oldMaster, payload, {
      kid: 'aes-kid',
      algorithm: 'AES-256-GCM',
    });

    const rewrapped = rewrapEnvelope(orig, oldMaster, newMaster) as EnvelopeV1;

    expect(rewrapped.id).toBe(orig.id);
    expect(rewrapped.ts).toBe(orig.ts);
    expect(rewrapped.enc.alg).toBe('AES-256-GCM');
    expect(rewrapped.enc.kid).toBe('aes-kid');

    expect(() => decryptUnder(oldMaster, rewrapped)).toThrow();
    expect(decryptUnder(newMaster, rewrapped)).toEqual(payload);
  });

  it('same-master rewrap with AES-256-GCM regenerates nonce/ct/tag', () => {
    const master = freshMaster(0x55);
    const orig = encryptUnder(master, payload, { algorithm: 'AES-256-GCM' });
    const rewrapped = rewrapEnvelope(orig, master, master) as EnvelopeV1;

    expect(rewrapped.enc.alg).toBe('AES-256-GCM');
    expect(rewrapped.enc.ct).not.toEqual(orig.enc.ct);
    expect(rewrapped.enc.commit).not.toEqual(orig.enc.commit);
    expect(decryptUnder(master, rewrapped)).toEqual(payload);
  });
});

describe('rewrapEnvelope — v2 envelope support', () => {
  const payload = { type: 'v2-note', body: 'cbor wire' };

  it('preserves the v2 wire shape and rewraps under the new master', () => {
    const oldMaster = freshMaster(0x66);
    const newMaster = freshMaster(0x77);
    const origV1 = encryptUnder(oldMaster, payload, { kid: 'v2-kid' });
    const origV2 = upgradeToV2(origV1);

    const rewrapped = rewrapEnvelope(origV2, oldMaster, newMaster);

    // Wire shape is still v2 — same envelope format on both sides.
    expect(rewrapped.v).toBe(2);
    const rewrappedV2 = rewrapped as EnvelopeV2;
    expect(rewrappedV2.enc.ct).toBeInstanceOf(Uint8Array);
    expect(rewrappedV2.enc.commit).toBeInstanceOf(Uint8Array);

    expect(rewrappedV2.id).toBe(origV2.id);
    expect(rewrappedV2.ts).toBe(origV2.ts);
    expect(rewrappedV2.enc.alg).toBe(origV2.enc.alg);
    expect(rewrappedV2.enc.kid).toBe(origV2.enc.kid);

    // Decrypt by downgrading back to v1 under the new master.
    const backV1 = downgradeToV1(rewrappedV2);
    expect(decryptUnder(newMaster, backV1)).toEqual(payload);

    // Old master cannot open it.
    expect(() => decryptUnder(oldMaster, backV1)).toThrow();
  });

  it('rewraps a v2 AES-GCM envelope under a new master', () => {
    const oldMaster = freshMaster(0x88);
    const newMaster = freshMaster(0x99);
    const origV1 = encryptUnder(oldMaster, payload, { algorithm: 'AES-256-GCM' });
    const origV2 = upgradeToV2(origV1);

    const rewrapped = rewrapEnvelope(origV2, oldMaster, newMaster) as EnvelopeV2;

    expect(rewrapped.v).toBe(2);
    expect(rewrapped.enc.alg).toBe('AES-256-GCM');
    expect(decryptUnder(newMaster, downgradeToV1(rewrapped))).toEqual(payload);
  });
});

describe('rewrapEnvelope — error surface', () => {
  const payload = { x: 1, y: 'two' };

  it('throws on a wrong old master (no plaintext released)', () => {
    const master = freshMaster(0xaa);
    const wrongMaster = freshMaster(0xbb);
    const newMaster = freshMaster(0xcc);
    const orig = encryptUnder(master, payload);

    expect(() => rewrapEnvelope(orig, wrongMaster, newMaster)).toThrow();
  });

  it('throws when the ciphertext is tampered', () => {
    const oldMaster = freshMaster(0xde);
    const newMaster = freshMaster(0xef);
    const orig = encryptUnder(oldMaster, payload);

    const ctBytes = Buffer.from(orig.enc.ct, 'base64');
    ctBytes[30] ^= 0x01;
    const tampered: EnvelopeV1 = {
      ...orig,
      enc: { ...orig.enc, ct: ctBytes.toString('base64') },
    };

    expect(() => rewrapEnvelope(tampered, oldMaster, newMaster)).toThrow();
  });

  it('throws when the envelope id was tampered (AAD binding)', () => {
    const oldMaster = freshMaster(0x01);
    const newMaster = freshMaster(0x02);
    const orig = encryptUnder(oldMaster, payload);
    const tampered: EnvelopeV1 = { ...orig, id: 'b_tampered' };

    expect(() => rewrapEnvelope(tampered, oldMaster, newMaster)).toThrow();
  });

  it('throws when the commitment was tampered', () => {
    const oldMaster = freshMaster(0x03);
    const newMaster = freshMaster(0x04);
    const orig = encryptUnder(oldMaster, payload);
    const fakeCommit = Buffer.alloc(32, 0xff).toString('base64');
    const tampered: EnvelopeV1 = {
      ...orig,
      enc: { ...orig.enc, commit: fakeCommit },
    };

    expect(() => rewrapEnvelope(tampered, oldMaster, newMaster)).toThrow(
      'key commitment verification failed',
    );
  });

  it('throws on a truncated ciphertext', () => {
    const oldMaster = freshMaster(0x05);
    const newMaster = freshMaster(0x06);
    const orig = encryptUnder(oldMaster, payload);
    const truncated = Buffer.alloc(10).toString('base64');
    const broken: EnvelopeV1 = {
      ...orig,
      enc: { ...orig.enc, ct: truncated, 'ct.len': 10 },
    };

    expect(() => rewrapEnvelope(broken, oldMaster, newMaster)).toThrow('truncated ciphertext');
  });

  it('throws on invalid master key length', () => {
    const oldMaster = freshMaster(0x07);
    const newMaster = freshMaster(0x08);
    const orig = encryptUnder(oldMaster, payload);

    const shortSb = SecureBuffer.from(new Uint8Array(16).fill(0x09));
    const shortMaster = shortSb as unknown as MasterKey;
    expect(() => rewrapEnvelope(orig, shortMaster, newMaster)).toThrow(/must be 32 bytes/);
    shortSb.dispose();
  });
});

describe('rewrapEnvelope — caller owns master lifecycle', () => {
  it('does not dispose either master', () => {
    const oldMaster = freshMaster(0x10);
    const newMaster = freshMaster(0x20);
    const orig = encryptUnder(oldMaster, { a: 1 });

    rewrapEnvelope(orig, oldMaster, newMaster);

    expect(oldMaster.isDisposed).toBe(false);
    expect(newMaster.isDisposed).toBe(false);
  });
});

// -------------------------------------------------------------------------
// Vector-driven tests
//
// Since rewrap regenerates the nonce on every call, there is nothing
// stable to pin against byte-equality. Each vector file instead fixes
// the *inputs* that stress a distinct code path: `oldMasterHex`,
// `newMasterHex`, the desired wire `v`, `alg`, `kid`, a fixed `id`/`ts`
// for identity preservation, and the plaintext `payload`.
//
// The test encrypts under `oldMaster`, rewraps to `newMaster`, decrypts
// under `newMaster`, and asserts identity-fields and plaintext match.
// This covers the full (v1, v2) × (XChaCha20-Poly1305, AES-256-GCM)
// matrix called out in plan-04 §G1-Worker-A.
// -------------------------------------------------------------------------

interface RewrapVector {
  name: string;
  /** Wire-format version of the envelope under test. */
  wireVersion: 1 | 2;
  alg: Algorithm;
  oldMasterHex: string;
  newMasterHex: string;
  /** Fixed id so vector round-trips are reproducible across reruns. */
  id: string;
  /** Fixed ts so vector round-trips are reproducible. */
  ts: string;
  kid: string;
  payload: Record<string, unknown>;
}

const VECTORS_DIR = fileURLToPath(new URL('./vectors/rewrap/', import.meta.url));

function loadVector(file: string): RewrapVector {
  const full = join(VECTORS_DIR, file);
  const raw = readFileSync(full, 'utf8');
  return JSON.parse(raw) as RewrapVector;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`odd-length hex: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('rewrapEnvelope — test vectors', () => {
  const files = readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json'));

  // Sanity: the matrix described in plan-04 is 4 vectors.
  it('ships the full (v1, v2) × (XChaCha, AES-GCM) matrix', () => {
    expect(files.length).toBeGreaterThanOrEqual(4);
  });

  it.each(files)('vector %s round-trips through rewrap', (file) => {
    const v = loadVector(file);
    const oldMaster = masterFromBytes(hexToBytes(v.oldMasterHex));
    const newMaster = masterFromBytes(hexToBytes(v.newMasterHex));

    // Encrypt under oldMaster with the vector's fixed id/ts/kid/alg.
    const origV1 = encryptUnder(oldMaster, v.payload, {
      id: v.id,
      ts: v.ts,
      kid: v.kid,
      algorithm: v.alg,
    });
    const oldEnv: AnyEnvelope = v.wireVersion === 2 ? upgradeToV2(origV1) : origV1;

    const rewrapped = rewrapEnvelope(oldEnv, oldMaster, newMaster);

    // Version preserved
    expect(rewrapped.v).toBe(v.wireVersion);
    // Identity preserved
    expect(rewrapped.id).toBe(v.id);
    expect(rewrapped.ts).toBe(v.ts);
    expect(rewrapped.enc.alg).toBe(v.alg);
    expect(rewrapped.enc.kid).toBe(v.kid);

    // Decrypts to the recorded payload under the new master.
    const v1 = rewrapped.v === 1 ? rewrapped : downgradeToV1(rewrapped);
    expect(decryptUnder(newMaster, v1)).toEqual(v.payload);

    // Old master cannot open it.
    expect(() => decryptUnder(oldMaster, v1)).toThrow();

    oldMaster.dispose();
    newMaster.dispose();
  });
});
