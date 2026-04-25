/**
 * test/envelope-vectors.test.ts
 *
 * Wire-format pinning tests for envelope v1 and v2.
 *
 * Each JSON file under test/vectors/envelope-v1/ encodes:
 *   inputs   — master key, kid, algorithm, payload, fixed nonce, id, ts
 *   expected — the full v1 envelope object and v2 hex bytes
 *
 * Three invariants are verified per vector:
 *   1. Re-encrypting with the same inputs produces byte-identical output.
 *   2. Decrypting the pinned envelope yields the original plaintext.
 *   3. Tampering one byte of ct, commit, kid, alg, or id causes decrypt to throw.
 *
 * Determinism is achieved by patching globalThis.crypto.getRandomValues for
 * the duration of each encryption call. No src/ files are modified.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { decryptV1, encryptV1 } from '../src/envelope/v1.js';
import { downgradeToV1, serializeV2, upgradeToV2 } from '../src/envelope/v2.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';
import type { Algorithm, EnvelopeV1 } from '../src/types.js';

// ── Types ─────────────────────────────────────────────────────────────────────

interface EnvelopeVectorInputs {
  masterKeyHex: string;
  kid: string;
  algorithm: string;
  payload: Record<string, unknown>;
  nonceHex: string;
  id: string;
  ts: string;
}

interface EnvelopeVector {
  description: string;
  inputs: EnvelopeVectorInputs;
  expected: {
    v1: EnvelopeV1;
    v2Hex: string;
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = join(__dirname, 'vectors', 'envelope-v1');

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function loadVector(file: string): EnvelopeVector {
  return JSON.parse(readFileSync(join(VECTORS_DIR, file), 'utf8')) as EnvelopeVector;
}

/**
 * Temporarily replace globalThis.crypto.getRandomValues with a function
 * that fills the output buffer from `nonceBytes`, call `fn`, then restore.
 * This makes aeadEncrypt deterministic — the fresh-nonce call inside the
 * library will receive exactly the bytes we provide.
 */
function withFixedNonce<T>(nonceBytes: Uint8Array, fn: () => T): T {
  const saved = globalThis.crypto.getRandomValues.bind(globalThis.crypto);

  // biome-ignore lint/suspicious/noExplicitAny: temporary mock for deterministic vectors
  (globalThis.crypto as any).getRandomValues = <B extends ArrayBufferView | null>(buf: B): B => {
    if (buf instanceof Uint8Array) {
      buf.set(nonceBytes);
    }
    return buf;
  };

  try {
    return fn();
  } finally {
    // biome-ignore lint/suspicious/noExplicitAny: restoring original WebCrypto
    (globalThis.crypto as any).getRandomValues = saved;
  }
}

function deriveKeys(masterHex: string): { cek: Uint8Array; commitKey: Uint8Array } {
  const master = hexToBytes(masterHex);
  return { cek: deriveContentKey(master), commitKey: deriveCommitKey(master) };
}

function encryptWithVector(v: EnvelopeVector): EnvelopeV1 {
  const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
  const nonce = hexToBytes(v.inputs.nonceHex);

  return withFixedNonce(nonce, () =>
    encryptV1({
      payload: v.inputs.payload,
      cek,
      commitKey,
      kid: v.inputs.kid,
      algorithm: v.inputs.algorithm as Algorithm,
      id: v.inputs.id,
      ts: v.inputs.ts,
    }),
  );
}

// ── Load all vector files ─────────────────────────────────────────────────────

const vectorFiles = readdirSync(VECTORS_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort();

// ── Test suite ────────────────────────────────────────────────────────────────

describe('envelope test vectors', () => {
  it('loads at least 24 vector files (4 combos × 6 payload cases)', () => {
    expect(vectorFiles.length).toBeGreaterThanOrEqual(24);
  });

  describe('v1 pinning — byte-identical re-encryption', () => {
    it.each(vectorFiles)('%s reproduces the pinned v1 envelope', (file) => {
      const v = loadVector(file);
      const produced = encryptWithVector(v);

      // Compare the entire envelope object field-by-field for a clear diff on failure.
      expect(produced.v).toBe(v.expected.v1.v);
      expect(produced.id).toBe(v.expected.v1.id);
      expect(produced.ts).toBe(v.expected.v1.ts);
      expect(produced.enc.alg).toBe(v.expected.v1.enc.alg);
      expect(produced.enc.kid).toBe(v.expected.v1.enc.kid);
      expect(produced.enc.ct).toBe(v.expected.v1.enc.ct);
      expect(produced.enc['ct.len']).toBe(v.expected.v1.enc['ct.len']);
      expect(produced.enc.commit).toBe(v.expected.v1.enc.commit);
    });
  });

  describe('v2 pinning — byte-identical CBOR re-serialisation', () => {
    it.each(vectorFiles)('%s reproduces the pinned v2 hex bytes', (file) => {
      const v = loadVector(file);
      const produced = encryptWithVector(v);
      const v2Bytes = serializeV2(upgradeToV2(produced));
      expect(Buffer.from(v2Bytes).toString('hex')).toBe(v.expected.v2Hex);
    });
  });

  describe('decrypt — pinned ciphertext yields original plaintext', () => {
    it.each(vectorFiles)('%s decrypts to the recorded payload', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);

      // Decrypt the pinned ciphertext (not the freshly produced one).
      const recovered = decryptV1(v.expected.v1, cek, commitKey);
      expect(recovered).toEqual(v.inputs.payload);
    });
  });

  describe('decrypt — v2 downgrade decrypts to the recorded payload', () => {
    it.each(vectorFiles)('%s decrypts via v2 downgrade', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);

      const v2 = upgradeToV2(v.expected.v1);
      const v1back = downgradeToV1(v2);
      const recovered = decryptV1(v1back, cek, commitKey);
      expect(recovered).toEqual(v.inputs.payload);
    });
  });

  describe('tamper rejection — one-byte mutations cause decrypt to throw', () => {
    it.each(vectorFiles)('%s — mutated ct byte throws', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
      const ctBytes = Buffer.from(v.expected.v1.enc.ct, 'base64');
      ctBytes[0] ^= 0xff;
      const tampered: EnvelopeV1 = {
        ...v.expected.v1,
        enc: { ...v.expected.v1.enc, ct: ctBytes.toString('base64') },
      };
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow();
    });

    it.each(vectorFiles)('%s — mutated commit throws', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
      const commitBytes = Buffer.from(v.expected.v1.enc.commit, 'base64');
      commitBytes[0] ^= 0xff;
      const tampered: EnvelopeV1 = {
        ...v.expected.v1,
        enc: { ...v.expected.v1.enc, commit: commitBytes.toString('base64') },
      };
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow(
        'key commitment verification failed',
      );
    });

    it.each(vectorFiles)('%s — mutated kid throws', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
      const tampered: EnvelopeV1 = {
        ...v.expected.v1,
        enc: { ...v.expected.v1.enc, kid: `${v.expected.v1.enc.kid}-tampered` },
      };
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow();
    });

    it.each(vectorFiles)('%s — mutated id throws', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
      const tampered: EnvelopeV1 = { ...v.expected.v1, id: `${v.expected.v1.id}-tampered` };
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow();
    });

    it.each(vectorFiles)('%s — mutated alg throws', (file) => {
      const v = loadVector(file);
      const { cek, commitKey } = deriveKeys(v.inputs.masterKeyHex);
      // Switch to the other algorithm — must fail authentication.
      const otherAlg: Algorithm =
        v.expected.v1.enc.alg === 'XChaCha20-Poly1305' ? 'AES-256-GCM' : 'XChaCha20-Poly1305';
      const tampered: EnvelopeV1 = {
        ...v.expected.v1,
        enc: { ...v.expected.v1.enc, alg: otherAlg },
      };
      expect(() => decryptV1(tampered, cek, commitKey)).toThrow();
    });
  });
});
