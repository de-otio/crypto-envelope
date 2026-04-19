import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AES_GCM_HARD_CAP, EnvelopeClient, NonceBudgetExceeded } from '../src/envelope-client.js';
import { InMemoryMessageCounter, type MessageCounter } from '../src/message-counter.js';
import { SecureBuffer } from '../src/secure-buffer.js';

describe('EnvelopeClient', () => {
  const masterKey = new Uint8Array(32).fill(0x42);

  // Suppress InMemoryMessageCounter's first-use warn — every instance
  // prints it once, which clutters test output.
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe('round-trip (XChaCha20-Poly1305 default)', () => {
    it('encrypts and decrypts a payload (default v2)', async () => {
      using client = new EnvelopeClient({ masterKey });
      const wire = await client.encrypt({ type: 'note', body: 'hello' });
      expect(wire[0]).toBe(0x43); // CBOR magic 'C'
      expect(await client.decrypt(wire)).toEqual({ type: 'note', body: 'hello' });
    });

    it('encrypts and decrypts a payload (v1 opt-in)', async () => {
      using client = new EnvelopeClient({ masterKey, format: 'v1' });
      const wire = await client.encrypt({ type: 'note', body: 'hello' });
      expect(wire[0]).toBe(0x7b); // '{' — JSON opener
      expect(await client.decrypt(wire)).toEqual({ type: 'note', body: 'hello' });
    });

    it('round-trips a large object', async () => {
      using client = new EnvelopeClient({ masterKey });
      const payload = {
        lines: Array.from({ length: 1000 }, (_, i) => `line ${i}`),
        metadata: { author: 'x', tags: ['a', 'b', 'c'] },
      };
      expect(await client.decrypt(await client.encrypt(payload))).toEqual(payload);
    });

    it('accepts a SecureBuffer masterKey without disposing it', async () => {
      const sb = SecureBuffer.from(Uint8Array.from(masterKey));
      using client = new EnvelopeClient({ masterKey: sb });
      const wire = await client.encrypt({ x: 1 });
      expect(await client.decrypt(wire)).toEqual({ x: 1 });
      // Caller-supplied SecureBuffer stays live.
      expect(sb.isDisposed).toBe(false);
      sb.dispose();
    });
  });

  describe('AES-256-GCM path', () => {
    it('encrypts and decrypts via direct option', async () => {
      using client = new EnvelopeClient({ masterKey, algorithm: 'AES-256-GCM' });
      const wire = await client.encrypt({ x: 1 });
      expect(await client.decrypt(wire)).toEqual({ x: 1 });
    });

    it('encrypts and decrypts via `forAesGcmInterop` factory', async () => {
      using client = EnvelopeClient.forAesGcmInterop({ masterKey });
      const wire = await client.encrypt({ note: 'cross-system interop' });
      expect(await client.decrypt(wire)).toEqual({ note: 'cross-system interop' });
    });

    it('round-trips AES-GCM envelopes through a default-XChaCha client', async () => {
      // Decryption is alg-agnostic — it pulls alg from the envelope.
      using aesClient = EnvelopeClient.forAesGcmInterop({ masterKey });
      using xclient = new EnvelopeClient({ masterKey });
      const wire = await aesClient.encrypt({ x: 1 });
      expect(await xclient.decrypt(wire)).toEqual({ x: 1 });
    });

    it('round-trips in v1 wire format', async () => {
      using client = EnvelopeClient.forAesGcmInterop({ masterKey, format: 'v1' });
      const wire = await client.encrypt({ x: 1 });
      expect(wire[0]).toBe(0x7b); // v1 JSON
      const text = new TextDecoder().decode(wire);
      expect(text).toContain('"alg":"AES-256-GCM"');
      expect(await client.decrypt(wire)).toEqual({ x: 1 });
    });

    it('rejects a blob whose alg field was downgrade-tampered', async () => {
      using client = EnvelopeClient.forAesGcmInterop({ masterKey, format: 'v1' });
      const wire = await client.encrypt({ x: 1 });
      const text = new TextDecoder().decode(wire);
      const tampered = new TextEncoder().encode(
        text.replace('"alg":"AES-256-GCM"', '"alg":"XChaCha20-Poly1305"'),
      );
      // AAD is bound with alg — swapping it breaks AEAD auth, then hits
      // the nonce-width mismatch (12 vs 24). Either error is acceptable.
      await expect(client.decrypt(tampered)).rejects.toThrow();
    });
  });

  describe('cross-format interop', () => {
    it('decrypts a v1-serialised blob from a v2 client', async () => {
      using v1client = new EnvelopeClient({ masterKey, format: 'v1' });
      using v2client = new EnvelopeClient({ masterKey, format: 'v2' });
      const v1wire = await v1client.encrypt({ x: 42 });
      expect(await v2client.decrypt(v1wire)).toEqual({ x: 42 });
    });

    it('decrypts a v2-serialised blob from a v1 client', async () => {
      using v1client = new EnvelopeClient({ masterKey, format: 'v1' });
      using v2client = new EnvelopeClient({ masterKey, format: 'v2' });
      const v2wire = await v2client.encrypt({ x: 42 });
      expect(await v1client.decrypt(v2wire)).toEqual({ x: 42 });
    });
  });

  describe('wrong key / tamper rejection', () => {
    it('rejects a blob encrypted under a different master key', async () => {
      using a = new EnvelopeClient({ masterKey });
      using b = new EnvelopeClient({ masterKey: new Uint8Array(32).fill(0x99) });
      const wire = await a.encrypt({ x: 1 });
      await expect(b.decrypt(wire)).rejects.toThrow();
    });

    it("decrypts regardless of the decrypting client's configured kid", async () => {
      using a = new EnvelopeClient({ masterKey, kid: 'alice' });
      using b = new EnvelopeClient({ masterKey, kid: 'bob' });
      const wire = await a.encrypt({ x: 1 });
      expect(await b.decrypt(wire)).toEqual({ x: 1 });
    });

    it('rejects a wire blob whose kid has been tampered with', async () => {
      using client = new EnvelopeClient({ masterKey, format: 'v1' });
      const wire = await client.encrypt({ x: 1 });
      const text = new TextDecoder().decode(wire);
      const tampered = new TextEncoder().encode(
        text.replace('"kid":"default"', '"kid":"attacker"'),
      );
      await expect(client.decrypt(tampered)).rejects.toThrow();
    });
  });

  describe('MessageCounter integration', () => {
    it('increments the counter on every encrypt', async () => {
      using client = new EnvelopeClient({ masterKey });
      expect(await client.currentCount()).toBe(0);
      await client.encrypt({ x: 1 });
      expect(await client.currentCount()).toBe(1);
      await client.encrypt({ x: 2 });
      expect(await client.currentCount()).toBe(2);
    });

    it('exposes a stable keyFingerprint for the same master', () => {
      using a = new EnvelopeClient({ masterKey });
      using b = new EnvelopeClient({ masterKey });
      expect(Buffer.from(a.keyFingerprint).equals(Buffer.from(b.keyFingerprint))).toBe(true);
    });

    it('produces a different keyFingerprint under a different master', () => {
      using a = new EnvelopeClient({ masterKey });
      using b = new EnvelopeClient({ masterKey: new Uint8Array(32).fill(0x99) });
      expect(Buffer.from(a.keyFingerprint).equals(Buffer.from(b.keyFingerprint))).toBe(false);
    });

    it('shares counter state when the same MessageCounter is injected', async () => {
      const counter = new InMemoryMessageCounter();
      using a = new EnvelopeClient({ masterKey, messageCounter: counter });
      using b = new EnvelopeClient({ masterKey, messageCounter: counter });
      await a.encrypt({ x: 1 });
      await b.encrypt({ x: 2 });
      // Both clients hit the same fingerprint; the shared counter saw 2
      // increments.
      expect(await a.currentCount()).toBe(2);
      expect(await b.currentCount()).toBe(2);
    });
  });

  describe('AES-GCM hard cap (design-review B2)', () => {
    it('throws NonceBudgetExceeded when the counter crosses 2^32', async () => {
      // Inject a counter that starts at the cap so we don't need 4B iterations.
      class PrimedCounter implements MessageCounter {
        private n: number;
        constructor(start: number) {
          this.n = start;
        }
        async increment(): Promise<number> {
          this.n += 1;
          return this.n;
        }
        async current(): Promise<number> {
          return this.n;
        }
      }
      using client = EnvelopeClient.forAesGcmInterop({
        masterKey,
        messageCounter: new PrimedCounter(AES_GCM_HARD_CAP),
      });

      // One past cap → throw.
      await expect(client.encrypt({ x: 1 })).rejects.toBeInstanceOf(NonceBudgetExceeded);
    });

    it('does NOT enforce a hard cap on XChaCha20-Poly1305', async () => {
      class PrimedCounter implements MessageCounter {
        private n: number;
        constructor(start: number) {
          this.n = start;
        }
        async increment(): Promise<number> {
          this.n += 1;
          return this.n;
        }
        async current(): Promise<number> {
          return this.n;
        }
      }
      using client = new EnvelopeClient({
        masterKey,
        messageCounter: new PrimedCounter(AES_GCM_HARD_CAP + 1),
      });

      // Past the AES-GCM cap, but XChaCha has no practical cap — does
      // not throw.
      const wire = await client.encrypt({ x: 1 });
      expect(await client.decrypt(wire)).toEqual({ x: 1 });
    });

    it('NonceBudgetExceeded carries fingerprint, counter, and algorithm', async () => {
      class PrimedCounter implements MessageCounter {
        async increment(): Promise<number> {
          return AES_GCM_HARD_CAP + 1;
        }
        async current(): Promise<number> {
          return AES_GCM_HARD_CAP + 1;
        }
      }
      using client = EnvelopeClient.forAesGcmInterop({
        masterKey,
        messageCounter: new PrimedCounter(),
      });
      try {
        await client.encrypt({ x: 1 });
        throw new Error('expected throw');
      } catch (e) {
        expect(e).toBeInstanceOf(NonceBudgetExceeded);
        const err = e as NonceBudgetExceeded;
        expect(err.code).toBe('NONCE_BUDGET_EXCEEDED');
        expect(err.algorithm).toBe('AES-256-GCM');
        expect(err.counter).toBeGreaterThan(AES_GCM_HARD_CAP);
        expect(err.fingerprint.length).toBe(16);
      }
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

    it('rejects encrypt after dispose', async () => {
      const client = new EnvelopeClient({ masterKey });
      client.dispose();
      await expect(client.encrypt({ x: 1 })).rejects.toThrow('disposed');
    });

    it('rejects decrypt after dispose', async () => {
      const client = new EnvelopeClient({ masterKey });
      const wire = await client.encrypt({ x: 1 });
      client.dispose();
      await expect(client.decrypt(wire)).rejects.toThrow('disposed');
    });

    it('rejects currentCount after dispose', async () => {
      const client = new EnvelopeClient({ masterKey });
      client.dispose();
      await expect(client.currentCount()).rejects.toThrow('disposed');
    });
  });
});
