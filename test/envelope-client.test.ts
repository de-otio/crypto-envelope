import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EnvelopeClient } from '../src/envelope-client.js';
import { SecureBuffer } from '../src/secure-buffer.js';

describe('EnvelopeClient', () => {
  const masterKey = new Uint8Array(32).fill(0x42);

  describe('round-trip', () => {
    it('encrypts and decrypts a payload (default v2)', () => {
      using client = new EnvelopeClient({ masterKey });
      const wire = client.encrypt({ type: 'note', body: 'hello' });
      expect(wire[0]).toBe(0x43); // CBOR magic 'C'
      expect(client.decrypt(wire)).toEqual({ type: 'note', body: 'hello' });
    });

    it('encrypts and decrypts a payload (v1 opt-in)', () => {
      using client = new EnvelopeClient({ masterKey, format: 'v1' });
      const wire = client.encrypt({ type: 'note', body: 'hello' });
      expect(wire[0]).toBe(0x7b); // '{' — JSON opener
      expect(client.decrypt(wire)).toEqual({ type: 'note', body: 'hello' });
    });

    it('round-trips a large object', () => {
      using client = new EnvelopeClient({ masterKey });
      const payload = {
        lines: Array.from({ length: 1000 }, (_, i) => `line ${i}`),
        metadata: { author: 'x', tags: ['a', 'b', 'c'] },
      };
      expect(client.decrypt(client.encrypt(payload))).toEqual(payload);
    });

    it('accepts a SecureBuffer masterKey without disposing it', () => {
      const sb = SecureBuffer.from(Uint8Array.from(masterKey));
      using client = new EnvelopeClient({ masterKey: sb });
      const wire = client.encrypt({ x: 1 });
      expect(client.decrypt(wire)).toEqual({ x: 1 });
      // Caller-supplied SecureBuffer stays live.
      expect(sb.isDisposed).toBe(false);
      sb.dispose();
    });
  });

  describe('cross-format interop', () => {
    it('decrypts a v1-serialised blob from a v2 client', () => {
      using v1client = new EnvelopeClient({ masterKey, format: 'v1' });
      using v2client = new EnvelopeClient({ masterKey, format: 'v2' });
      const v1wire = v1client.encrypt({ x: 42 });
      expect(v2client.decrypt(v1wire)).toEqual({ x: 42 });
    });

    it('decrypts a v2-serialised blob from a v1 client', () => {
      using v1client = new EnvelopeClient({ masterKey, format: 'v1' });
      using v2client = new EnvelopeClient({ masterKey, format: 'v2' });
      const v2wire = v2client.encrypt({ x: 42 });
      expect(v1client.decrypt(v2wire)).toEqual({ x: 42 });
    });
  });

  describe('wrong key / tamper rejection', () => {
    it('rejects a blob encrypted under a different master key', () => {
      using a = new EnvelopeClient({ masterKey });
      using b = new EnvelopeClient({ masterKey: new Uint8Array(32).fill(0x99) });
      const wire = a.encrypt({ x: 1 });
      expect(() => b.decrypt(wire)).toThrow();
    });

    it("decrypts regardless of the decrypting client's configured kid", () => {
      // kid is stored in the envelope itself; the decryptor pulls it from
      // there to reconstruct AAD. The client's configured kid only
      // controls what gets written on encrypt. A consumer that wants to
      // enforce "only decrypt my own kids" must check it post-decrypt.
      using a = new EnvelopeClient({ masterKey, kid: 'alice' });
      using b = new EnvelopeClient({ masterKey, kid: 'bob' });
      const wire = a.encrypt({ x: 1 });
      expect(b.decrypt(wire)).toEqual({ x: 1 });
    });

    it('rejects a wire blob whose kid has been tampered with', () => {
      using client = new EnvelopeClient({ masterKey, format: 'v1' });
      const wire = client.encrypt({ x: 1 });
      const text = new TextDecoder().decode(wire);
      const tampered = new TextEncoder().encode(
        text.replace('"kid":"default"', '"kid":"attacker"'),
      );
      expect(() => client.decrypt(tampered)).toThrow();
    });
  });

  describe('input validation', () => {
    it('rejects a master key that is not 32 bytes', () => {
      expect(() => new EnvelopeClient({ masterKey: randomBytes(16) })).toThrow('32 bytes');
      expect(() => new EnvelopeClient({ masterKey: randomBytes(64) })).toThrow('32 bytes');
    });
  });

  describe('lifecycle', () => {
    it('is idempotent on dispose', () => {
      const client = new EnvelopeClient({ masterKey });
      client.dispose();
      expect(() => client.dispose()).not.toThrow();
    });

    it('rejects encrypt after dispose', () => {
      const client = new EnvelopeClient({ masterKey });
      client.dispose();
      expect(() => client.encrypt({ x: 1 })).toThrow('disposed');
    });

    it('rejects decrypt after dispose', () => {
      const client = new EnvelopeClient({ masterKey });
      const wire = client.encrypt({ x: 1 });
      client.dispose();
      expect(() => client.decrypt(wire)).toThrow('disposed');
    });
  });
});
