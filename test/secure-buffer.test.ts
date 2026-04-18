import { describe, expect, it } from 'vitest';
import { SecureBuffer } from '../src/secure-buffer.js';

describe('SecureBuffer', () => {
  describe('alloc', () => {
    it('allocates a buffer of the requested size', () => {
      const sb = SecureBuffer.alloc(32);
      expect(sb.length).toBe(32);
      expect(sb.buffer.byteLength).toBe(32);
      expect(sb.isDisposed).toBe(false);
      sb.dispose();
    });

    it('allocates a zeroed buffer', () => {
      const sb = SecureBuffer.alloc(16);
      expect(sb.buffer.every((b) => b === 0)).toBe(true);
      sb.dispose();
    });
  });

  describe('from', () => {
    it('copies data into a SecureBuffer', () => {
      const source = Buffer.from([1, 2, 3, 4, 5]);
      const sb = SecureBuffer.from(source);

      expect(sb.length).toBe(5);
      expect(sb.buffer[0]).toBe(1);
      expect(sb.buffer[4]).toBe(5);
      sb.dispose();
    });

    it('zeroes the source buffer after copying', () => {
      const source = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
      SecureBuffer.from(source);
      expect(source.every((b) => b === 0)).toBe(true);
    });

    it('accepts Uint8Array', () => {
      const source = new Uint8Array([10, 20, 30]);
      const sb = SecureBuffer.from(source);
      expect(sb.length).toBe(3);
      expect(sb.buffer[0]).toBe(10);
      sb.dispose();
    });
  });

  describe('dispose', () => {
    it('marks the buffer as disposed', () => {
      const sb = SecureBuffer.alloc(8);
      sb.buffer[0] = 0xff;
      sb.buffer[7] = 0xaa;

      sb.dispose();
      expect(sb.isDisposed).toBe(true);
    });

    it('throws when accessing buffer after dispose', () => {
      const sb = SecureBuffer.alloc(8);
      sb.dispose();
      expect(() => sb.buffer).toThrow('SecureBuffer has been disposed');
    });

    it('is idempotent', () => {
      const sb = SecureBuffer.alloc(8);
      sb.dispose();
      expect(() => sb.dispose()).not.toThrow();
      expect(sb.isDisposed).toBe(true);
    });
  });

  describe('Symbol.dispose', () => {
    it('supports the TC39 explicit resource management protocol', () => {
      const sb = SecureBuffer.alloc(8);
      expect(typeof sb[Symbol.dispose]).toBe('function');
      sb[Symbol.dispose]();
      expect(sb.isDisposed).toBe(true);
    });
  });

  describe('length', () => {
    it('reports correct length even after dispose', () => {
      const sb = SecureBuffer.alloc(64);
      expect(sb.length).toBe(64);
      sb.dispose();
      expect(sb.length).toBe(64);
    });
  });
});
