import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { SecureBuffer as SecureBufferBrowser } from '../src/secure-buffer.browser.js';

/**
 * Unit tests for the browser variant. Runs under Node for CI convenience
 * — the class is pure-JS (no sodium-native) so it works anywhere. Phase
 * III also ships a bundler smoke test that exercises the actual
 * `browser` package.json field swap.
 */

describe('SecureBufferBrowser (strict-by-default)', () => {
  describe('insecureMemory acknowledgement', () => {
    it('rejects construction without the ack flag', () => {
      // @ts-expect-error — calling without required flag on browser variant.
      expect(() => SecureBufferBrowser.alloc(32)).toThrow(/insecureMemory/);
      // @ts-expect-error — calling .from without the ack flag.
      expect(() => SecureBufferBrowser.from(randomBytes(32))).toThrow(/insecureMemory/);
    });

    it('rejects construction with insecureMemory: false', () => {
      expect(() =>
        // @ts-expect-error — insecureMemory is the type literal `true`.
        SecureBufferBrowser.alloc(32, { insecureMemory: false }),
      ).toThrow(/insecureMemory/);
    });

    it('rejects construction with a truthy non-object ack', () => {
      // @ts-expect-error — ack must be the specific shape.
      expect(() => SecureBufferBrowser.alloc(32, true)).toThrow(/insecureMemory/);
    });

    it('accepts construction with the correct ack', () => {
      const sb = SecureBufferBrowser.alloc(32, { insecureMemory: true });
      expect(sb.length).toBe(32);
      sb.dispose();
    });
  });

  describe('lifecycle', () => {
    it('allocates a zeroed buffer of the requested length', () => {
      const sb = SecureBufferBrowser.alloc(64, { insecureMemory: true });
      expect(sb.length).toBe(64);
      expect(sb.isDisposed).toBe(false);
      expect(Array.from(new Uint8Array(sb.buffer)).every((b) => b === 0)).toBe(true);
    });

    it('copies source bytes into a fresh ArrayBuffer on .from', () => {
      const src = randomBytes(32);
      const copy = Uint8Array.from(src);
      const sb = SecureBufferBrowser.from(copy, { insecureMemory: true });
      // Source is zeroed after .from.
      expect(Buffer.from(copy).equals(Buffer.alloc(32))).toBe(true);
      // SecureBuffer preserves the original bytes.
      expect(Buffer.from(sb.buffer).equals(src)).toBe(true);
    });

    it('zeroes on dispose (best-effort — documented limitation in browsers)', () => {
      const sb = SecureBufferBrowser.from(randomBytes(32), { insecureMemory: true });
      // Alias the underlying ArrayBuffer (not a copy). After dispose, the
      // aliased view reflects the zero-fill.
      const inner = sb.buffer;
      const view = new Uint8Array(inner.buffer, inner.byteOffset, inner.byteLength);
      expect(view.every((b) => b === 0)).toBe(false);
      sb.dispose();
      expect(view.every((b) => b === 0)).toBe(true);
    });

    it('is idempotent on dispose', () => {
      const sb = SecureBufferBrowser.alloc(16, { insecureMemory: true });
      sb.dispose();
      expect(sb.isDisposed).toBe(true);
      expect(() => sb.dispose()).not.toThrow();
      expect(sb.isDisposed).toBe(true);
    });

    it('throws on buffer access after dispose', () => {
      const sb = SecureBufferBrowser.alloc(16, { insecureMemory: true });
      sb.dispose();
      expect(() => sb.buffer).toThrow(/disposed/);
    });

    it('supports `using` syntax via [Symbol.dispose]', () => {
      // Explicit Resource Management — if the target toolchain supports
      // `using`, this block auto-disposes sb on exit.
      const fn = (): void => {
        const sb = SecureBufferBrowser.alloc(16, { insecureMemory: true });
        expect(sb.isDisposed).toBe(false);
        (sb as unknown as { [Symbol.dispose]: () => void })[Symbol.dispose]();
        expect(sb.isDisposed).toBe(true);
      };
      fn();
    });
  });

  describe('backing-storage isolation', () => {
    it('does not share the ArrayBuffer with other SecureBuffers', () => {
      const a = SecureBufferBrowser.alloc(32, { insecureMemory: true });
      const b = SecureBufferBrowser.alloc(32, { insecureMemory: true });
      // Writing through a must not affect b.
      const viewA = new Uint8Array(a.buffer);
      viewA.fill(0xff);
      const viewB = new Uint8Array(b.buffer);
      expect(viewB.every((v) => v === 0)).toBe(true);
      a.dispose();
      b.dispose();
    });

    it('does not alias the source ArrayBuffer on .from', () => {
      const shared = new ArrayBuffer(64);
      const srcView = new Uint8Array(shared, 0, 32);
      const neighbour = new Uint8Array(shared, 32, 32);
      neighbour.fill(0xee);
      srcView.fill(0xaa);

      const sb = SecureBufferBrowser.from(srcView, { insecureMemory: true });
      // Verify the copy preserved srcView's bytes before it was zeroed.
      expect(Buffer.from(sb.buffer).every((b) => b === 0xaa)).toBe(true);
      // Zeroing srcView (via the .from() fill) did NOT touch neighbour.
      expect(neighbour.every((b) => b === 0xee)).toBe(true);
      sb.dispose();
    });
  });
});
