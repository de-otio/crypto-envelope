import { decode, encode } from 'cborg';

import type { Algorithm, AnyEnvelope, EnvelopeV1, EnvelopeV2 } from '../types.js';
import { deserializeV1 } from './v1.js';

/**
 * Magic prefix identifying a v2 (CBOR) envelope on the wire. Bytes are
 * "CKB" — historical, inherited from chaoskb's on-disk blobs. Kept
 * stable so a v1 envelope never accidentally deserialises as v2 (JSON
 * payloads start with '{', not 0x43).
 */
const CBOR_MAGIC = new Uint8Array([0x43, 0x4b, 0x42]);

/**
 * Serialise a v2 envelope to wire bytes: `CKB` magic prefix followed by
 * a CBOR encoding of the envelope object. Binary fields (`ct`, `commit`)
 * are emitted as CBOR byte strings rather than base64 — ~33 % smaller
 * than v1 JSON for typical ciphertexts.
 */
export function serializeV2(envelope: EnvelopeV2): Uint8Array {
  if (envelope.v !== 2) {
    throw new Error(`serializeV2: envelope version must be 2, got ${envelope.v}`);
  }
  const body = encode({
    v: 2,
    id: envelope.id,
    ts: envelope.ts,
    enc: {
      alg: envelope.enc.alg,
      kid: envelope.enc.kid,
      ct: envelope.enc.ct,
      commit: envelope.enc.commit,
    },
  });
  const out = new Uint8Array(CBOR_MAGIC.length + body.length);
  out.set(CBOR_MAGIC, 0);
  out.set(body, CBOR_MAGIC.length);
  return out;
}

/** Parse wire bytes (magic-prefixed CBOR) as a v2 envelope. No decryption. */
export function deserializeV2(bytes: Uint8Array): EnvelopeV2 {
  if (!hasCborMagic(bytes)) {
    throw new Error('deserializeV2: missing CBOR magic prefix');
  }
  const body = bytes.subarray(CBOR_MAGIC.length);
  const parsed = decode(body) as {
    v: number;
    id: string;
    ts: string;
    enc: {
      alg: string;
      kid: string;
      ct: Uint8Array;
      commit: Uint8Array;
    };
  };
  if (parsed.v !== 2) {
    throw new Error(`CBOR envelope has unexpected version: ${parsed.v}`);
  }
  return {
    v: 2,
    id: parsed.id,
    ts: parsed.ts,
    enc: {
      alg: parsed.enc.alg as Algorithm,
      kid: parsed.enc.kid,
      ct: new Uint8Array(parsed.enc.ct),
      commit: new Uint8Array(parsed.enc.commit),
    },
  };
}

/**
 * Auto-detect a v1 JSON or v2 CBOR envelope on the wire. Inspects the
 * first three bytes for the CBOR magic prefix; otherwise falls back to
 * v1 JSON parsing. The caller still needs to decrypt — this only parses
 * the wire envelope.
 */
export function deserialize(bytes: Uint8Array): AnyEnvelope {
  return hasCborMagic(bytes) ? deserializeV2(bytes) : deserializeV1(bytes);
}

/**
 * Convert a v1 envelope to v2 for compact transport. The cryptographic
 * state is unchanged — `ct` and `commit` are the same bytes, just
 * re-encoded. AAD was bound at encrypt time with `v: 1` and stays that
 * way; `downgradeToV1` before decrypting.
 */
export function upgradeToV2(v1: EnvelopeV1): EnvelopeV2 {
  return {
    v: 2,
    id: v1.id,
    ts: v1.ts,
    enc: {
      alg: v1.enc.alg,
      kid: v1.enc.kid,
      ct: Uint8Array.fromBase64(v1.enc.ct),
      commit: Uint8Array.fromBase64(v1.enc.commit),
    },
  };
}

/** Convert a v2 envelope back to v1 for JSON consumers or decryption. */
export function downgradeToV1(v2: EnvelopeV2): EnvelopeV1 {
  return {
    v: 1,
    id: v2.id,
    ts: v2.ts,
    enc: {
      alg: v2.enc.alg,
      kid: v2.enc.kid,
      ct: v2.enc.ct.toBase64(),
      'ct.len': v2.enc.ct.length,
      commit: v2.enc.commit.toBase64(),
    },
  };
}

function hasCborMagic(bytes: Uint8Array): boolean {
  return (
    bytes.length >= CBOR_MAGIC.length &&
    bytes[0] === CBOR_MAGIC[0] &&
    bytes[1] === CBOR_MAGIC[1] &&
    bytes[2] === CBOR_MAGIC[2]
  );
}
