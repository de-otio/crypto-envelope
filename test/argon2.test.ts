import { describe, expect, it } from 'vitest';
import { deriveFromPassphrase } from '../src/primitives/argon2.js';

// Argon2id with t=3, m=64 MiB, p=1 is intentionally slow. Raise the
// timeout to avoid flakes on slower CI runners.
describe('Argon2id KDF', { timeout: 30_000 }, () => {
  const salt = new Uint8Array(16).fill(0xab);

  it('derives a 32-byte key', () => {
    const key = deriveFromPassphrase('test passphrase', salt);
    expect(key.length).toBe(32);
    expect(key.isDisposed).toBe(false);
    key.dispose();
  });

  it('is deterministic for the same passphrase and salt', () => {
    const key1 = deriveFromPassphrase('deterministic test', salt);
    const key2 = deriveFromPassphrase('deterministic test', salt);
    expect(Buffer.from(key1.buffer)).toEqual(Buffer.from(key2.buffer));
    key1.dispose();
    key2.dispose();
  });

  it('produces different keys for different passphrases', () => {
    const key1 = deriveFromPassphrase('passphrase one', salt);
    const key2 = deriveFromPassphrase('passphrase two', salt);
    expect(Buffer.from(key1.buffer).equals(Buffer.from(key2.buffer))).toBe(false);
    key1.dispose();
    key2.dispose();
  });

  it('produces different keys for different salts', () => {
    const key1 = deriveFromPassphrase('same passphrase', new Uint8Array(16).fill(0x01));
    const key2 = deriveFromPassphrase('same passphrase', new Uint8Array(16).fill(0x02));
    expect(Buffer.from(key1.buffer).equals(Buffer.from(key2.buffer))).toBe(false);
    key1.dispose();
    key2.dispose();
  });

  it('returns a disposable SecureBuffer', () => {
    const key = deriveFromPassphrase('test', salt);
    expect(key.isDisposed).toBe(false);
    expect(key.length).toBe(32);
    key.dispose();
    expect(key.isDisposed).toBe(true);
    expect(() => key.buffer).toThrow();
  });

  it('matches @noble/hashes Argon2id for a pinned input', async () => {
    // Compare our wrapper output to the underlying primitive called with
    // the same parameters. Any accidental parameter drift in
    // deriveFromPassphrase would break this.
    const { argon2id } = await import('@noble/hashes/argon2.js');
    const specSalt = Uint8Array.from([
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
      0xbf,
    ]);
    const passphrase = 'correct horse battery staple extra';

    const wrapperKey = deriveFromPassphrase(passphrase, specSalt);
    const rawKey = argon2id(Buffer.from(passphrase, 'utf-8'), specSalt, {
      t: 3,
      m: 65536,
      p: 1,
      dkLen: 32,
    });

    expect(Buffer.from(wrapperKey.buffer)).toEqual(Buffer.from(rawKey));
    wrapperKey.dispose();
  });
});
