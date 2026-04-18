/**
 * Memory-locked buffer for sensitive key material.
 * Implementations must zero the buffer on dispose; `Symbol.dispose`
 * support is required for TC39 Explicit Resource Management (`using`).
 */
export interface ISecureBuffer {
  readonly buffer: Buffer;
  readonly length: number;
  readonly isDisposed: boolean;
  dispose(): void;
  [Symbol.dispose](): void;
}
