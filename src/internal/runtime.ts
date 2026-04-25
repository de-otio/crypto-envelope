/**
 * Runtime helpers that need to work on both Node and browser.
 *
 * - `getRandomBytes`: WebCrypto `crypto.getRandomValues`. Available on
 *   Node ≥20, every modern browser, Deno, Bun, Cloudflare Workers,
 *   Vercel Edge. No `node:crypto` dependency.
 *
 * `constantTimeEqual` is split into platform-specific files
 * (`constant-time.ts` for Node, `constant-time.browser.ts` for browsers)
 * so the Node path can use `node:crypto.timingSafeEqual`; import it from
 * `./constant-time.js`.
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
