import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time byte-equality, Node implementation.
 *
 * Delegates to `node:crypto.timingSafeEqual`, which is implemented in C
 * and is the canonical platform answer. Pure-JS constant-time loops are
 * not contractually constant-time under V8's JIT — using the C primitive
 * removes that whole class of risk on Node.
 *
 * Returns `false` immediately on length mismatch (this is a known
 * information leak about message length but does not reveal byte
 * contents — matching `timingSafeEqual`'s own contract, which throws
 * on length mismatch).
 *
 * Browser builds get the pure-JS fallback from
 * `src/internal/constant-time.browser.ts` via the package.json
 * `"browser"` mapping.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
