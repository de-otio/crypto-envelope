import type { InsecureMemoryAck } from './secure-buffer.js';
import type { ISecureBuffer } from './types.js';

export type { InsecureMemoryAck } from './secure-buffer.js';

/**
 * Browser-runtime replacement for {@link SecureBuffer}.
 *
 * **This class does not mlock.** Browser runtimes have no portable
 * equivalent of `sodium_malloc` / `mlock` — keys can be swapped to disk,
 * copied by the V8 garbage collector during heap compaction, and
 * inspected via DevTools. Zeroing-on-dispose runs, but the bytes may
 * already have been copied elsewhere by the runtime before the zero.
 *
 * Because the browser posture is materially weaker than Node's, the
 * constructor is **strict by default**: callers must explicitly pass
 * `{ insecureMemory: true }` or it throws. The flag is the audit-trail
 * record of "I understand this buffer cannot mlock." Design-review Q1
 * (chaoskb browser plugin gets the same strict default; per-feature
 * acknowledgement keeps journalist-tier use-cases from silently degrading).
 *
 * The flag propagates through factory methods (`SecureBufferBrowser.from`,
 * `SecureBufferBrowser.alloc`) — every allocation site touches it.
 *
 * Only loaded under the `"browser"` exports condition. Node builds get
 * the real `SecureBuffer` from `src/secure-buffer.ts`.
 */

export class SecureBufferBrowser implements ISecureBuffer {
  private readonly _view: Uint8Array;
  private _disposed = false;

  private constructor(length: number, ack: InsecureMemoryAck | undefined) {
    assertInsecureMemoryAck(ack);
    // Fresh ArrayBuffer (not pooled) so the underlying storage is ours
    // alone — zeroing this view does not touch any neighbouring buffer.
    this._view = new Uint8Array(new ArrayBuffer(length));
  }

  /**
   * Read-only view of the underlying bytes. Typed as `Buffer` to match
   * {@link ISecureBuffer}; at runtime in the browser it is a plain
   * `Uint8Array` that the consumer can still `.set(...)` / `.subarray(...)`
   * / pass to noble primitives.
   */
  get buffer(): Buffer {
    if (this._disposed) {
      throw new Error('SecureBuffer has been disposed');
    }
    // Cast for interface compatibility. The runtime value is Uint8Array
    // which noble ciphers and everything else in this package accept.
    return this._view as unknown as Buffer;
  }

  get length(): number {
    return this._view.byteLength;
  }

  get isDisposed(): boolean {
    return this._disposed;
  }

  /** Zero the contents and mark disposed. Idempotent. Note: browser
   *  zeroing is not a guarantee — V8 may have already moved the storage
   *  during GC compaction. Best-effort only. */
  dispose(): void {
    if (this._disposed) {
      return;
    }
    this._view.fill(0);
    this._disposed = true;
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  /**
   * Copy bytes into a new SecureBufferBrowser and zero the source.
   *
   * Aliasing warning is stronger than the Node `SecureBuffer.from` case:
   * if `data` is a `Uint8Array` that views a larger `ArrayBuffer` owned
   * by another buffer (common for IndexedDB reads, Blob.arrayBuffer()
   * results, and Service Worker transferables), zeroing the source view
   * clears the overlapping bytes of the backing storage. The outer
   * constructor always allocates a fresh `ArrayBuffer` so the returned
   * `SecureBufferBrowser` is isolated; the *source* buffer is not.
   */
  static from(data: Buffer | Uint8Array, ack?: InsecureMemoryAck): SecureBufferBrowser {
    const sb = new SecureBufferBrowser(data.byteLength, ack);
    // Accept Buffer (Node's subclass of Uint8Array) via the Uint8Array view
    // constructor over its backing storage — the resulting copy is owned
    // exclusively by `sb._view`.
    const view = ArrayBuffer.isView(data)
      ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
      : new Uint8Array(data);
    sb._view.set(view);
    view.fill(0);
    return sb;
  }

  /** Allocate a zeroed SecureBufferBrowser of the given length. */
  static alloc(length: number, ack?: InsecureMemoryAck): SecureBufferBrowser {
    return new SecureBufferBrowser(length, ack);
  }
}

/**
 * Export under the canonical `SecureBuffer` name so the `"browser"`
 * exports-condition resolves transparently. Node consumers get
 * `SecureBuffer` from `src/secure-buffer.ts`; browser consumers get
 * `SecureBufferBrowser` aliased as `SecureBuffer` from this file.
 *
 * Signature difference: the browser variant requires
 * `{ insecureMemory: true }` as a second argument to `from` / `alloc`.
 * A type mismatch is intentional — consumers must opt in explicitly.
 */
export { SecureBufferBrowser as SecureBuffer };

function assertInsecureMemoryAck(
  ack: InsecureMemoryAck | undefined,
): asserts ack is InsecureMemoryAck {
  if (
    !ack ||
    typeof ack !== 'object' ||
    (ack as { insecureMemory?: unknown }).insecureMemory !== true
  ) {
    throw new Error(
      'SecureBufferBrowser requires an explicit { insecureMemory: true } acknowledgement. ' +
        'Browser runtimes cannot mlock — keys may be swapped to disk or copied by V8 GC. ' +
        'Pass the flag to confirm you understand the downgrade, or run on Node for mlock.',
    );
  }
}
