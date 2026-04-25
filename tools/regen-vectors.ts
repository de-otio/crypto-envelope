/**
 * tools/regen-vectors.ts
 *
 * Deterministic envelope test-vector generator.
 *
 * Run once to produce pinned JSON files under test/vectors/envelope-v1/
 * and test/vectors/envelope-v2/. Re-running with the same source produces
 * identical output. DO NOT add this to CI — it is a human-triggered tool
 * for generating/refreshing the ground-truth pins.
 *
 * Usage (from repo root):
 *   node --import=tsx/esm tools/regen-vectors.ts
 *
 * Determinism strategy: `aeadEncrypt` draws nonces from
 * `globalThis.crypto.getRandomValues`. We install a deterministic
 * replacement before generating each vector and restore the original
 * afterwards. No source files under src/ are modified.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { encryptV1, serializeV2, upgradeToV2 } from '../src/envelope/index.js';
import { computeCommitment } from '../src/primitives/commitment.js';
import { deriveCommitKey, deriveContentKey, deriveKey } from '../src/primitives/hkdf.js';

// ── Path helpers ────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const V1_DIR = join(REPO_ROOT, 'test', 'vectors', 'envelope-v1');
const V2_DIR = join(REPO_ROOT, 'test', 'vectors', 'envelope-v2');
const HKDF_DIR = join(REPO_ROOT, 'test', 'vectors', 'hkdf');
const COMMITMENT_DIR = join(REPO_ROOT, 'test', 'vectors', 'commitment');
const CANONICAL_JSON_DIR = join(REPO_ROOT, 'test', 'vectors', 'canonical-json');

mkdirSync(V1_DIR, { recursive: true });
mkdirSync(V2_DIR, { recursive: true });
mkdirSync(HKDF_DIR, { recursive: true });
mkdirSync(COMMITMENT_DIR, { recursive: true });
mkdirSync(CANONICAL_JSON_DIR, { recursive: true });

// ── Deterministic nonce injection ────────────────────────────────────────────

/**
 * Replace `globalThis.crypto.getRandomValues` with a deterministic source
 * that fills from the provided bytes, then calls the callback, then restores
 * the original. This means a single `aeadEncrypt` call will consume exactly
 * `nonceBytes.length` bytes. The nonce must be the correct width for the
 * algorithm (24 bytes for XChaCha20-Poly1305, 12 for AES-256-GCM).
 *
 * The original `getRandomValues` is stored and restored even if the callback
 * throws, so a failed vector generation does not corrupt subsequent ones.
 */
function withDeterministicNonce<T>(nonceBytes: Uint8Array, fn: () => T): T {
  const original = globalThis.crypto.getRandomValues.bind(globalThis.crypto);

  let callCount = 0;
  // biome-ignore lint/suspicious/noExplicitAny: must match WebCrypto type
  (globalThis.crypto as any).getRandomValues = <T extends ArrayBufferView | null>(buf: T): T => {
    if (!(buf instanceof Uint8Array)) {
      throw new Error('withDeterministicNonce: only Uint8Array supported in vector generator');
    }
    if (callCount > 0) {
      throw new Error('withDeterministicNonce: getRandomValues called more than once unexpectedly');
    }
    if (buf.length !== nonceBytes.length) {
      throw new Error(
        `withDeterministicNonce: buffer length ${buf.length} != nonce length ${nonceBytes.length}`,
      );
    }
    buf.set(nonceBytes);
    callCount++;
    return buf as unknown as T;
  };

  try {
    return fn();
  } finally {
    // biome-ignore lint/suspicious/noExplicitAny: restoring original
    (globalThis.crypto as any).getRandomValues = original;
  }
}

// ── Fixed master keys ────────────────────────────────────────────────────────

/**
 * All master keys are fixed 32-byte values for determinism. Two are provided
 * so vectors can document "this key", "that key" without reuse.
 *
 * master-A: all 0xAA  (kid=default vectors)
 * master-B: all 0xBB  (kid=alt vectors)
 */
const MASTER_A = new Uint8Array(32).fill(0xaa);
const MASTER_B = new Uint8Array(32).fill(0xbb);

const MASTER_A_HEX = Buffer.from(MASTER_A).toString('hex');
const MASTER_B_HEX = Buffer.from(MASTER_B).toString('hex');

/**
 * Fixed ISO 8601 timestamp used in all vectors so the ts field is pinned.
 */
const FIXED_TS = '2026-04-25T00:00:00.000Z';

// ── Test cases ────────────────────────────────────────────────────────────────

/**
 * All plaintext payloads covered by the vector matrix. Each case name must
 * be filesystem-safe (used in filenames).
 */
const CASES: ReadonlyArray<{ name: string; payload: Record<string, unknown> }> = [
  {
    name: 'empty',
    payload: {},
  },
  {
    name: 'single-ascii',
    payload: { x: 'a' },
  },
  {
    name: '1kb-string',
    payload: { data: 'a'.repeat(1024) },
  },
  {
    name: 'nested-json',
    payload: {
      type: 'document',
      version: 3,
      draft: false,
      rating: null,
      score: 4.75,
      tags: ['alpha', 'beta', 'gamma'],
      meta: {
        author: 'Alice',
        contributors: ['Bob', 'Carol'],
        stats: { words: 1024, chars: 5120 },
      },
    },
  },
  {
    name: 'unicode',
    payload: {
      greeting: 'こんにちは',
      emoji: '\u{1F511}',
      arabic: 'مرحبا',
      math: 'π ≈ 3.14159',
    },
  },
  {
    name: 'numbers',
    payload: {
      integer: 42,
      negative: -7,
      float: Math.PI,
      zero: 0,
      large: 9_007_199_254_740_991,
      small: 1.4e-10,
    },
  },
];

// ── Nonce widths ────────────────────────────────────────────────────────────

const XCHACHA_NONCE_LEN = 24;
const AES_GCM_NONCE_LEN = 12;

/**
 * Fixed nonces for each algorithm. Each vector picks its nonce
 * deterministically from a counter seeded by (alg, kid, caseIndex).
 * The nonces are distinct across all vectors.
 */
function fixedNonce(alg: 'XChaCha20-Poly1305' | 'AES-256-GCM', index: number): Uint8Array {
  const len = alg === 'XChaCha20-Poly1305' ? XCHACHA_NONCE_LEN : AES_GCM_NONCE_LEN;
  const nonce = new Uint8Array(len);
  // Byte 0: encode algorithm (0x01=XChaCha, 0x02=AES-GCM)
  nonce[0] = alg === 'XChaCha20-Poly1305' ? 0x01 : 0x02;
  // Bytes 1..3: little-endian index
  nonce[1] = index & 0xff;
  nonce[2] = (index >> 8) & 0xff;
  nonce[3] = (index >> 16) & 0xff;
  // Remaining bytes: fill with 0xDE to avoid all-zero nonces
  nonce.fill(0xde, 4);
  return nonce;
}

// ── Vector generation ─────────────────────────────────────────────────────────

type Algorithm = 'XChaCha20-Poly1305' | 'AES-256-GCM';

interface Combination {
  alg: Algorithm;
  kid: string;
  masterHex: string;
  masterBytes: Uint8Array;
  id: string;
}

/** All algorithm × kid combinations to generate. */
const COMBINATIONS: Combination[] = [
  {
    alg: 'XChaCha20-Poly1305',
    kid: 'default',
    masterHex: MASTER_A_HEX,
    masterBytes: MASTER_A,
    id: 'xchacha-default',
  },
  {
    alg: 'XChaCha20-Poly1305',
    kid: 'alt',
    masterHex: MASTER_B_HEX,
    masterBytes: MASTER_B,
    id: 'xchacha-alt',
  },
  {
    alg: 'AES-256-GCM',
    kid: 'default',
    masterHex: MASTER_A_HEX,
    masterBytes: MASTER_A,
    id: 'aesgcm-default',
  },
  {
    alg: 'AES-256-GCM',
    kid: 'alt',
    masterHex: MASTER_B_HEX,
    masterBytes: MASTER_B,
    id: 'aesgcm-alt',
  },
];

interface EnvelopeVector {
  description: string;
  inputs: {
    masterKeyHex: string;
    kid: string;
    algorithm: string;
    payload: Record<string, unknown>;
    nonceHex: string;
    id: string;
    ts: string;
  };
  expected: {
    v1: Record<string, unknown>;
    v2Hex: string;
  };
}

let totalGenerated = 0;

for (const combo of COMBINATIONS) {
  const cek = deriveContentKey(combo.masterBytes);
  const commitKey = deriveCommitKey(combo.masterBytes);

  let caseIndex = 0;
  for (const tc of CASES) {
    const nonce = fixedNonce(combo.alg, caseIndex++);
    const nonceHex = Buffer.from(nonce).toString('hex');

    // Generate the envelope with a deterministic nonce.
    const envelope = withDeterministicNonce(nonce, () =>
      encryptV1({
        payload: tc.payload,
        cek,
        commitKey,
        kid: combo.kid,
        algorithm: combo.alg,
        id: combo.id,
        ts: FIXED_TS,
      }),
    );

    // V2 is a serialisation variant of the same crypto object.
    const v2Bytes = serializeV2(upgradeToV2(envelope));
    const v2Hex = Buffer.from(v2Bytes).toString('hex');

    const vector: EnvelopeVector = {
      description: `${combo.alg} / kid=${combo.kid} / case=${tc.name}`,
      inputs: {
        masterKeyHex: combo.masterHex,
        kid: combo.kid,
        algorithm: combo.alg,
        payload: tc.payload,
        nonceHex,
        id: combo.id,
        ts: FIXED_TS,
      },
      expected: {
        v1: envelope as unknown as Record<string, unknown>,
        v2Hex,
      },
    };

    const slug = combo.alg === 'XChaCha20-Poly1305' ? 'xchacha' : 'aesgcm';
    const filename = `${slug}-${combo.kid}-${tc.name}.json`;

    writeFileSync(join(V1_DIR, filename), `${JSON.stringify(vector, null, 2)}\n`);
    writeFileSync(join(V2_DIR, filename), `${JSON.stringify(vector, null, 2)}\n`);

    totalGenerated++;
  }
}

console.log(`Generated ${totalGenerated} envelope vectors into:`);
console.log(`  ${V1_DIR}`);
console.log(`  ${V2_DIR}`);
console.log(
  'Note: envelope-v1/ and envelope-v2/ contain the same JSON vectors; ' +
    'the v1 envelope is in expected.v1 and the v2 bytes are in expected.v2Hex.',
);

// ── HKDF primitive vectors ───────────────────────────────────────────────────

// RFC 5869 Appendix A.1 — already hand-coded into test/vectors/hkdf/rfc-5869-a1.json.
// Generate the wrapper-pinned vector by computing the expected OKM here.
{
  const ikm = new Uint8Array(32).fill(0x0b);
  const salt = new Uint8Array(16).fill(0x42);
  const okm = deriveKey(ikm, 'envelope-test/v1', salt, 32);
  const pinned = {
    description:
      'Pinned output of the crypto-envelope deriveKey wrapper for a fixed (ikm, info, salt, len). ' +
      'Guards against future wrapper changes such as swapping the info encoder, default salt, or default length.',
    reference: 'internal — test/hkdf.test.ts pinned-output section',
    algorithm: 'HKDF-SHA256 via deriveKey wrapper',
    inputs: {
      ikmHex: Buffer.from(ikm).toString('hex'),
      saltHex: Buffer.from(salt).toString('hex'),
      info: 'envelope-test/v1',
      length: 32,
    },
    expected: {
      okmHex: Buffer.from(okm).toString('hex'),
    },
  };
  writeFileSync(
    join(HKDF_DIR, 'envelope-wrapper-pinned.json'),
    `${JSON.stringify(pinned, null, 2)}\n`,
  );
  console.log('Generated HKDF wrapper-pinned vector.');
}

// ── Commitment primitive vectors ─────────────────────────────────────────────

// RFC 4231 §4.3 — key = "Jefe", data = "what do ya want for nothing?", empty id.
{
  const key = new TextEncoder().encode('Jefe');
  const data = new TextEncoder().encode('what do ya want for nothing?');
  const tag = computeCommitment(key, '', data);
  const vec = {
    description:
      "RFC 4231 §4.3 — HMAC-SHA256 test case 2, key='Jefe', data='what do ya want for nothing?'. " +
      'Exercised via computeCommitment with empty id so the HMAC input is just the data bytes.',
    reference: 'https://www.rfc-editor.org/rfc/rfc4231#section-4.3',
    algorithm: 'HMAC-SHA256 via computeCommitment',
    inputs: {
      keyHex: Buffer.from(key).toString('hex'),
      id: '',
      dataHex: Buffer.from(data).toString('hex'),
    },
    expected: {
      tagHex: Buffer.from(tag).toString('hex'),
    },
  };
  writeFileSync(join(COMMITMENT_DIR, 'rfc-4231-4-3.json'), `${JSON.stringify(vec, null, 2)}\n`);
  console.log('Generated commitment RFC-4231-4-3 vector.');
}

// Non-empty-id pinned vector — guards against id ordering/encoding refactors.
{
  const key = new TextEncoder().encode('Jefe');
  const data = new TextEncoder().encode('what do ya want for nothing?');
  const idStr = 'b_envelope_id';
  const tag = computeCommitment(key, idStr, data);
  const vec = {
    description:
      'Pinned vector with a non-empty id to guard against a refactor that drops or reorders ' +
      'the id prefix in computeCommitment. HMAC input is UTF-8(id) || dataBytes.',
    reference: 'internal — test/commitment.test.ts external KATs section',
    algorithm: 'HMAC-SHA256 via computeCommitment',
    inputs: {
      keyHex: Buffer.from(key).toString('hex'),
      id: idStr,
      dataHex: Buffer.from(data).toString('hex'),
    },
    expected: {
      tagHex: Buffer.from(tag).toString('hex'),
    },
    note:
      "expected.tagHex is HMAC-SHA256(key, UTF8('b_envelope_id') || data). " +
      'Any change to id ordering or encoding will break this test.',
  };
  writeFileSync(
    join(COMMITMENT_DIR, 'non-empty-id-pinned.json'),
    `${JSON.stringify(vec, null, 2)}\n`,
  );
  console.log('Generated commitment non-empty-id-pinned vector.');
}

// ── Canonical JSON vectors ───────────────────────────────────────────────────

// RFC 8785 examples — key inputs from the spec and our test suite.
{
  const examples = [
    {
      name: 'sorted-keys',
      description: 'Key sorting: keys must appear in ascending Unicode code-point order.',
      reference: 'RFC 8785 §3.2.3',
      input: { z: 1, a: 2, m: 3 },
      expected: '{"a":2,"m":3,"z":1}',
    },
    {
      name: 'nested-object-sorting',
      description: 'Key sorting applied recursively to nested objects.',
      reference: 'RFC 8785 §3.2.3',
      input: { b: { z: 1, a: 2 }, a: 1 },
      expected: '{"a":1,"b":{"a":2,"z":1}}',
    },
    {
      name: 'envelope-aad-shape',
      description: 'The exact AAD shape used by the crypto-envelope library.',
      reference: 'internal — src/aad.ts constructAAD',
      input: { alg: 'XChaCha20-Poly1305', id: 'b_test000000000000', kid: 'CEK', v: 1 },
      expected: '{"alg":"XChaCha20-Poly1305","id":"b_test000000000000","kid":"CEK","v":1}',
    },
    {
      name: 'null-and-booleans',
      description: 'null and boolean literals.',
      reference: 'RFC 8785 §3.2.2',
      input: { v: null, t: true, f: false },
      expected: '{"f":false,"t":true,"v":null}',
    },
    {
      name: 'numbers',
      description: 'Integer, negative zero (must emit as 0), and float serialisation.',
      reference: 'RFC 8785 §3.2.2.3',
      input: { n: 42, nz: -0, pi: 3.14 },
      expected: '{"n":42,"nz":0,"pi":3.14}',
    },
    {
      name: 'string-escaping',
      description: 'Short-form escapes for control characters (RFC 8785 §3.2.2.2).',
      reference: 'RFC 8785 §3.2.2.2',
      input: { s: '\b\t\n\f\r' },
      expected: '{"s":"\\b\\t\\n\\f\\r"}',
    },
  ];

  const vec = {
    description: 'RFC 8785 canonical JSON examples from the crypto-envelope test suite.',
    reference: 'https://www.rfc-editor.org/rfc/rfc8785',
    examples,
  };
  writeFileSync(
    join(CANONICAL_JSON_DIR, 'rfc-8785-examples.json'),
    `${JSON.stringify(vec, null, 2)}\n`,
  );
  console.log('Generated canonical-json rfc-8785-examples vector.');
}
