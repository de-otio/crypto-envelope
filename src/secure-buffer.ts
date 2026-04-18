import sodium from 'sodium-native';

import type { ISecureBuffer } from './types.js';

/**
 * Memory-locked buffer for sensitive key material.
 * Backed by `sodium_malloc` (mlock'd pages, guard pages) and zeroed with
 * `sodium_memzero` on dispose. Keys and secrets must use this rather than
 * plain `Uint8Array` / `Buffer` to avoid leaks via swap or crash dumps.
 */
export class SecureBuffer implements ISecureBuffer {
  private _buffer: Buffer;
  private _disposed = false;

  private constructor(length: number) {
    this._buffer = sodium.sodium_malloc(length);
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
   * The source is always zeroed — callers must not assume it is preserved.
   */
  static from(data: Buffer | Uint8Array): SecureBuffer {
    const sb = new SecureBuffer(data.byteLength);
    const buf = Buffer.isBuffer(data)
      ? data
      : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    buf.copy(sb._buffer);
    sodium.sodium_memzero(buf);
    return sb;
  }

  /** Allocate a zeroed SecureBuffer of the given length. */
  static alloc(length: number): SecureBuffer {
    const sb = new SecureBuffer(length);
    sodium.sodium_memzero(sb._buffer);
    return sb;
  }
}
