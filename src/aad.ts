import { canonicalJson } from './canonical-json.js';
import type { Algorithm } from './types.js';

const ENCODER = new TextEncoder();

/**
 * Construct AAD (Associated Authenticated Data) for an envelope.
 *
 * AAD = UTF-8 bytes of canonicalJson({ alg, id, kid, v }).
 * RFC 8785 canonicalisation fixes the byte sequence so a round-trip
 * through a non-canonical JSON parser can't produce a different AAD.
 * Any modification to any of the four fields between encrypt and
 * decrypt will cause AEAD verification to fail.
 *
 * `v` is the crypto-version — always 1 for v0.1. A v2 envelope (CBOR
 * transport) is a re-serialisation of the same cryptographic object
 * and uses AAD v=1.
 */
export function constructAAD(alg: Algorithm, id: string, kid: string, v: number): Uint8Array {
  return ENCODER.encode(canonicalJson({ alg, id, kid, v }));
}
