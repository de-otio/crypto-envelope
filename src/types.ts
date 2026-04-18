/**
 * Memory-locked buffer for sensitive key material.
 * Implementations must zero the buffer on dispose. The concrete
 * `SecureBuffer` class also implements `Symbol.dispose` so callers can use
 * TC39 Explicit Resource Management (`using sb = SecureBuffer.alloc(...)`);
 * the dispose protocol is a class-level contract rather than part of the
 * interface, so third-party implementations can opt into it or not.
 */
export interface ISecureBuffer {
  readonly buffer: Buffer;
  readonly length: number;
  readonly isDisposed: boolean;
  dispose(): void;
}
