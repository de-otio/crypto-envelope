import sodium from 'sodium-native';
import { describe, expect, it } from 'vitest';
import { deriveFromPassphrase } from '../../src/primitives/argon2.js';

// Argon2id with t=3, m=64 MiB, p=1 is intentionally slow. Raise the
// timeout to avoid flakes on slower CI runners.
describe('Argon2id KDF', { timeout: 30_000 }, () => {
  const salt = new Uint8Array(16).fill(0xab);

  it('derives a 32-byte key', () => {
    using key = deriveFromPassphrase('test passphrase', salt);
    expect(key.length).toBe(32);
    expect(key.isDisposed).toBe(false);
  });

  it('is deterministic for the same passphrase and salt', () => {
    using k1 = deriveFromPassphrase('deterministic test', salt);
    using k2 = deriveFromPassphrase('deterministic test', salt);
    expect(Buffer.from(k1.buffer)).toEqual(Buffer.from(k2.buffer));
  });

  it('produces different keys for different passphrases', () => {
    using k1 = deriveFromPassphrase('passphrase one', salt);
    using k2 = deriveFromPassphrase('passphrase two', salt);
    expect(Buffer.from(k1.buffer).equals(Buffer.from(k2.buffer))).toBe(false);
  });

  it('produces different keys for different salts', () => {
    using k1 = deriveFromPassphrase('same passphrase', new Uint8Array(16).fill(0x01));
    using k2 = deriveFromPassphrase('same passphrase', new Uint8Array(16).fill(0x02));
    expect(Buffer.from(k1.buffer).equals(Buffer.from(k2.buffer))).toBe(false);
  });

  it('returns a disposable SecureBuffer', () => {
    const key = deriveFromPassphrase('test', salt);
    expect(key.isDisposed).toBe(false);
    expect(key.length).toBe(32);
    key.dispose();
    expect(key.isDisposed).toBe(true);
    expect(() => key.buffer).toThrow();
  });

  describe('cross-implementation KAT (libsodium crypto_pwhash)', () => {
    // Verify our @noble/hashes-backed wrapper agrees byte-for-byte with
    // libsodium's Argon2id for the same (passphrase, salt, t=3, m=64MiB,
    // p=1, dkLen=32). Two independent implementations must match; if
    // either regresses silently, this test fails.
    it('matches libsodium for a fixed passphrase and salt', () => {
      const passphrase = 'correct horse battery staple extra';
      const specSalt = Uint8Array.from([
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf,
      ]);

      const sodiumOut = Buffer.alloc(32);
      sodium.crypto_pwhash(
        sodiumOut,
        Buffer.from(passphrase, 'utf8'),
        Buffer.from(specSalt),
        3, // opslimit = t
        64 * 1024 * 1024, // memlimit in bytes = m * 1024
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );

      using wrapper = deriveFromPassphrase(passphrase, specSalt);
      expect(Buffer.from(wrapper.buffer)).toEqual(sodiumOut);
    });
  });
});
