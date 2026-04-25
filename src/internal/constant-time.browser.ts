/**
 * Constant-time byte-equality, browser fallback.
 *
 * Browsers expose no equivalent of `node:crypto.timingSafeEqual`
 * (`crypto.subtle` has no constant-time compare primitive), so we use
 * the standard XOR-accumulate idiom that every audited pure-JS
 * implementation uses (@noble/hashes `equalBytes`, libsodium
 * `sodium_memcmp`).
 *
 * Caveat: pure-JS constant-time loops are not contractually
 * constant-time. V8's JIT, inlining decisions, and short-circuiting
 * around any single call site are not guaranteed. The XOR-accumulate
 * pattern is the best available approximation; treat it as
 * best-effort, mirroring the mlock downgrade documented in
 * `secure-buffer.browser.ts`.
 *
 * Returns `false` immediately on length mismatch — same contract as the
 * Node implementation in `constant-time.ts`.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
