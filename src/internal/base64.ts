/**
 * Browser-portable Base64 helpers.
 *
 * Uses `globalThis.btoa` / `globalThis.atob`, which are available on:
 * - Node >= 16 (as globals), browsers, Deno, Bun, Cloudflare Workers.
 *
 * Output is byte-identical to `Buffer.from(bytes).toString('base64')` and
 * `Buffer.from(str, 'base64')` — standard RFC 4648 §4 base64 with `=`
 * padding. No URL-safe variant, no line breaks.
 *
 * Rejects invalid input (non-base64 characters, bad padding) by
 * re-encoding the decoded result and comparing to the normalised input.
 * This catches corrupted wire data early with a clear error rather than
 * silently returning garbage.
 */

/**
 * Encode a `Uint8Array` as a standard Base64 string (RFC 4648 §4).
 *
 * Byte-identical to `Buffer.from(bytes).toString('base64')`.
 */
export function b64encode(bytes: Uint8Array): string {
  // btoa operates on a binary string where each character's code point
  // is the byte value. Build that string without Buffer.
  let binaryStr = '';
  const len = bytes.length;
  for (let i = 0; i < len; i++) {
    binaryStr += String.fromCharCode(bytes[i] as number);
  }
  return globalThis.btoa(binaryStr);
}

/**
 * Decode a standard Base64 string (RFC 4648 §4) to a `Uint8Array`.
 *
 * Byte-identical to `new Uint8Array(Buffer.from(str, 'base64'))`.
 *
 * Throws if the string contains characters outside the Base64 alphabet or
 * has invalid padding.
 */
export function b64decode(str: string): Uint8Array {
  // Normalise: strip whitespace that atob tolerates on some platforms,
  // then validate by re-encoding.
  const normalised = str.replace(/\s/g, '');
  let binaryStr: string;
  try {
    binaryStr = globalThis.atob(normalised);
  } catch {
    throw new Error('b64decode: invalid Base64 input');
  }

  // Validate: re-encode and compare to catch non-canonical encodings that
  // atob silently accepts (e.g. wrong padding, garbage bits in final group).
  // Re-encode produces the canonical form; if it doesn't match the input
  // (modulo whitespace we already stripped), the input was malformed.
  const reEncoded = globalThis.btoa(binaryStr);
  if (reEncoded !== normalised) {
    throw new Error('b64decode: non-canonical Base64 input');
  }

  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return bytes;
}
