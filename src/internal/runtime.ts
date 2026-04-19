/**
 * Runtime helpers that need to work on both Node and browser.
 *
 * - `getRandomBytes`: WebCrypto `crypto.getRandomValues`. Available on
 *   Node ≥20, every modern browser, Deno, Bun, Cloudflare Workers,
 *   Vercel Edge. No `node:crypto` dependency.
 * - `constantTimeEqual`: pure-JS constant-time byte-equality. Replaces
 *   `node:crypto.timingSafeEqual` for browser portability. Compiles to
 *   the same XOR-accumulate pattern every audited implementation uses
 *   (@noble/hashes `equalBytes`, libsodium `sodium_memcmp`).
 */

/**
 * Fresh random bytes from the platform CSPRNG. Throws if `globalThis.crypto`
 * is not available (e.g. a runtime without WebCrypto support), rather than
 * falling back to a weaker source.
 */
export function getRandomBytes(length: number): Uint8Array {
  const crypto = globalThis.crypto;
  if (!crypto || typeof crypto.getRandomValues !== 'function') {
    throw new Error(
      'globalThis.crypto.getRandomValues is not available — require a WebCrypto-compatible runtime ' +
        '(Node >= 20, any modern browser, Deno, Bun, Cloudflare Workers)',
    );
  }
  // Cap per WebCrypto spec: getRandomValues fills at most 65 536 bytes per
  // call. For any realistic crypto use (nonces, salts, keys) we are well
  // under this, so one call suffices.
  if (length > 65_536) {
    throw new Error(`getRandomBytes: requested ${length} bytes exceeds WebCrypto 65_536 cap`);
  }
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Constant-time byte-equality. Returns `false` immediately on length
 * mismatch (this is a known information leak about message length but
 * does not reveal byte contents — matching `node:crypto.timingSafeEqual`
 * behaviour).
 *
 * Pure-JS; runs everywhere. Uses XOR-accumulate so the loop touches every
 * byte regardless of the first mismatch position.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
