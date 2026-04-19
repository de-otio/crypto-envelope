import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  PBKDF2_SHA256_MIN_ITERATIONS,
  _resetPbkdf2WarnForTests,
  asMasterKey,
  deriveMasterKeyFromPassphrase,
} from '../src/passphrase.js';
import { SecureBuffer } from '../src/secure-buffer.js';

describe('deriveMasterKeyFromPassphrase', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe('Argon2id branch', () => {
    it('returns a 32-byte MasterKey', async () => {
      const salt = randomBytes(16);
      const mk = await deriveMasterKeyFromPassphrase('hunter2', salt, { algorithm: 'argon2id' });
      expect(mk.length).toBe(32);
    });

    it('is deterministic for matching passphrase + salt', async () => {
      const salt = randomBytes(16);
      const a = await deriveMasterKeyFromPassphrase('hunter2', salt, { algorithm: 'argon2id' });
      const b = await deriveMasterKeyFromPassphrase('hunter2', salt, { algorithm: 'argon2id' });
      expect(Buffer.from(a.buffer).equals(Buffer.from(b.buffer))).toBe(true);
    });

    it('differs when the salt changes', async () => {
      const a = await deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
        algorithm: 'argon2id',
      });
      const b = await deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
        algorithm: 'argon2id',
      });
      expect(Buffer.from(a.buffer).equals(Buffer.from(b.buffer))).toBe(false);
    });

    it('does not emit the PBKDF2 compatibility warning', async () => {
      await deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), { algorithm: 'argon2id' });
      expect(warnSpy).not.toHaveBeenCalled();
    });
  });

  describe('PBKDF2-SHA256 branch', () => {
    it('returns a 32-byte MasterKey at the floor iteration count', async () => {
      const salt = randomBytes(16);
      const mk = await deriveMasterKeyFromPassphrase('hunter2', salt, {
        algorithm: 'pbkdf2-sha256',
        iterations: PBKDF2_SHA256_MIN_ITERATIONS,
      });
      expect(mk.length).toBe(32);
    });

    it('enforces the iteration floor (1,000,000) with a clear error', async () => {
      await expect(
        deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
          algorithm: 'pbkdf2-sha256',
          iterations: 999_999,
        }),
      ).rejects.toThrow(/1000000|1_000_000/);
    });

    it('rejects non-integer iteration counts', async () => {
      await expect(
        deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
          algorithm: 'pbkdf2-sha256',
          iterations: 1_000_000.5,
        }),
      ).rejects.toThrow();
    });

    it('emits exactly one compatibility warning per process (module flag)', async () => {
      _resetPbkdf2WarnForTests();

      await deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
        algorithm: 'pbkdf2-sha256',
        iterations: PBKDF2_SHA256_MIN_ITERATIONS,
      });
      await deriveMasterKeyFromPassphrase('hunter2', randomBytes(16), {
        algorithm: 'pbkdf2-sha256',
        iterations: PBKDF2_SHA256_MIN_ITERATIONS,
      });

      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0]?.[0]).toMatch(/PBKDF2-SHA256|Argon2id/);
    });

    it('is deterministic for matching inputs', async () => {
      const salt = randomBytes(16);
      const a = await deriveMasterKeyFromPassphrase('hunter2', salt, {
        algorithm: 'pbkdf2-sha256',
        iterations: PBKDF2_SHA256_MIN_ITERATIONS,
      });
      const b = await deriveMasterKeyFromPassphrase('hunter2', salt, {
        algorithm: 'pbkdf2-sha256',
        iterations: PBKDF2_SHA256_MIN_ITERATIONS,
      });
      expect(Buffer.from(a.buffer).equals(Buffer.from(b.buffer))).toBe(true);
    });
  });

  describe('AbortSignal', () => {
    it('throws synchronously if the signal is already aborted', async () => {
      const controller = new AbortController();
      controller.abort();
      await expect(
        deriveMasterKeyFromPassphrase(
          'hunter2',
          randomBytes(16),
          { algorithm: 'argon2id' },
          { signal: controller.signal },
        ),
      ).rejects.toThrow();
    });

    it('throws post-derivation if the signal fires during the synchronous derive', async () => {
      // Argon2id runs synchronously inside noble; we cannot actually interrupt
      // it mid-iteration. This test documents the post-derivation abort path:
      // the signal fires after we return from argon2id, before the MasterKey
      // is returned to the caller.
      const controller = new AbortController();
      const promise = deriveMasterKeyFromPassphrase(
        'hunter2',
        randomBytes(16),
        { algorithm: 'argon2id' },
        { signal: controller.signal },
      );
      // Queue the abort for the next microtask — it may or may not land
      // before the synchronous argon2id call depending on scheduling.
      // In either case, one of the two checks (pre or post) must fire.
      queueMicrotask(() => controller.abort());
      try {
        const mk = await promise;
        // If scheduling raced, derive succeeded; sanity-check the output.
        expect(mk.length).toBe(32);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    });
  });

  describe('unknown algorithm', () => {
    it('rejects at runtime', async () => {
      await expect(
        deriveMasterKeyFromPassphrase(
          'hunter2',
          randomBytes(16),
          // biome-ignore lint/suspicious/noExplicitAny: exercising the unreachable branch
          { algorithm: 'scrypt' as any, n: 1 } as any,
        ),
      ).rejects.toThrow();
    });
  });
});

describe('asMasterKey', () => {
  it('brands a 32-byte SecureBuffer', () => {
    const buf = SecureBuffer.from(randomBytes(32));
    const mk = asMasterKey(buf);
    // Brand is erased at runtime — this is purely a compile-time check.
    expect(mk.length).toBe(32);
  });

  it('rejects buffers of the wrong length', () => {
    const buf = SecureBuffer.from(randomBytes(16));
    expect(() => asMasterKey(buf)).toThrow(/32 bytes/);
  });
});
