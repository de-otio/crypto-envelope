import sodium from 'sodium-native';

import type { ISecureBuffer } from './types.js';

/**
 * Acknowledgement flag for runtimes that cannot mlock. **Ignored on Node**
 * — `sodium_malloc` mlocks regardless. Required on the browser variant
 * (`src/secure-buffer.browser.ts`) because browsers have no equivalent
 * of mlock and the buffer contents may be swapped, GC-relocated, or
 * DevTools-visible.
 *
 * Accept the flag in signatures here even though Node ignores it, so
 * that code written for both runtimes compiles against one type surface.
 * Runtime asymmetry: Node silently ignores, browser rejects if missing.
 */
export interface InsecureMemoryAck {
  insecureMemory: true;
}

/**
 * Memory-locked buffer for sensitive key material.
 * Backed by `sodium_malloc` (mlock'd pages, guard pages) and zeroed with
 * `sodium_memzero` on dispose. Keys and secrets must use this rather than
 * plain `Uint8Array` / `Buffer` to avoid leakage via swap or crash dumps.
 *
 * Requires the host runtime to permit `mlock` — in practice, Node on any
 * desktop or server OS. On platforms with a restrictive `RLIMIT_MEMLOCK`
 * (AWS Lambda, some container setups), `sodium_malloc` fails and the
 * constructor rethrows with guidance.
 */
export class SecureBuffer implements ISecureBuffer {
  private _buffer: Buffer;
  private _disposed = false;

  private constructor(length: number) {
    try {
      this._buffer = sodium.sodium_malloc(length);
    } catch (err) {
      throw new Error(
        'SecureBuffer allocation failed; host may have a restrictive RLIMIT_MEMLOCK (AWS Lambda, some containers) or insufficient permissions for mlock',
        { cause: err },
      );
    }
  }

  get buffer(): Buffer {
    if (this._disposed) {
      throw new Error('SecureBuffer has been disposed');
    }
    return this._buffer;
  }

  get length(): number {
    return this._buffer.byteLength;
  }

  get isDisposed(): boolean {
    return this._disposed;
  }

  /** Zero the contents and mark disposed. Idempotent. */
  dispose(): void {
    if (this._disposed) {
      return;
    }
    sodium.sodium_memzero(this._buffer);
    this._disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  /**
   * Copy bytes into a new SecureBuffer and zero the source.
   *
   * **Aliasing warning.** If `data` is a `Uint8Array` that is a view into a
   * larger `ArrayBuffer` (common for `Buffer.from(...)` pooled buffers or
   * slices returned by network/filesystem reads), zeroing this view writes
   * zeros through the shared backing storage. Neighbouring buffers over the
   * same `ArrayBuffer` will have their overlapping bytes cleared. Callers
   * that must preserve the source must `SecureBuffer.from(Uint8Array.from(data))`
   * to force a copy.
   */
  static from(data: Buffer | Uint8Array, _ack?: InsecureMemoryAck): SecureBuffer {
    const sb = new SecureBuffer(data.byteLength);
    const buf = Buffer.isBuffer(data)
      ? data
      : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    buf.copy(sb._buffer);
    sodium.sodium_memzero(buf);
    return sb;
  }

  /** Allocate a zeroed SecureBuffer of the given length. */
  static alloc(length: number, _ack?: InsecureMemoryAck): SecureBuffer {
    const sb = new SecureBuffer(length);
    sodium.sodium_memzero(sb._buffer);
    return sb;
  }
}
