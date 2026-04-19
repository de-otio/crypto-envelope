import { describe, expect, it } from 'vitest';
import { PBKDF2_DEFAULT_OUTPUT_LENGTH, pbkdf2Sha256 } from '../src/primitives/pbkdf2.js';
import { RFC_7914_PBKDF2_SHA256 } from './vectors/kdf/pbkdf2-sha256-rfc-7914.js';

const fromUtf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

describe('PBKDF2-SHA256 primitive', () => {
  it('has a 32-byte default output length', () => {
    expect(PBKDF2_DEFAULT_OUTPUT_LENGTH).toBe(32);
  });

  it('derives the default 32-byte key', () => {
    const out = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 1 });
    expect(out.length).toBe(32);
  });

  it('respects the requested dkLen', () => {
    const out = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 1, dkLen: 64 });
    expect(out.length).toBe(64);
  });

  it('is deterministic for the same inputs', () => {
    const a = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 100 });
    const b = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 100 });
    expect(toHex(a)).toBe(toHex(b));
  });

  it('produces different output when the iteration count changes', () => {
    const a = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 100 });
    const b = pbkdf2Sha256(fromUtf8('passwd'), fromUtf8('salt'), { iterations: 101 });
    expect(toHex(a)).not.toBe(toHex(b));
  });

  describe('RFC 7914 §11 Known-Answer Tests', () => {
    for (const v of RFC_7914_PBKDF2_SHA256) {
      it(v.name, () => {
        const out = pbkdf2Sha256(fromUtf8(v.passphrase), fromUtf8(v.salt), {
          iterations: v.iterations,
          dkLen: v.dkLen,
        });
        expect(toHex(out)).toBe(v.dk);
      });
    }
  });
});
