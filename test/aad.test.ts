import { describe, expect, it } from 'vitest';
import { constructAAD } from '../src/aad.js';

describe('constructAAD', () => {
  it('emits UTF-8 bytes of canonical JSON with sorted keys', () => {
    const aad = constructAAD('XChaCha20-Poly1305', 'b_abc', 'CEK', 1);
    const text = new TextDecoder().decode(aad);
    expect(text).toBe('{"alg":"XChaCha20-Poly1305","id":"b_abc","kid":"CEK","v":1}');
  });

  it('is deterministic for identical inputs', () => {
    const a = constructAAD('XChaCha20-Poly1305', 'b_abc', 'CEK', 1);
    const b = constructAAD('XChaCha20-Poly1305', 'b_abc', 'CEK', 1);
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });

  it('differs when the id changes', () => {
    const a = constructAAD('XChaCha20-Poly1305', 'b_one', 'CEK', 1);
    const b = constructAAD('XChaCha20-Poly1305', 'b_two', 'CEK', 1);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('differs when the kid changes', () => {
    const a = constructAAD('XChaCha20-Poly1305', 'b_abc', 'k1', 1);
    const b = constructAAD('XChaCha20-Poly1305', 'b_abc', 'k2', 1);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('differs when the version changes', () => {
    const a = constructAAD('XChaCha20-Poly1305', 'b_abc', 'CEK', 1);
    const b = constructAAD('XChaCha20-Poly1305', 'b_abc', 'CEK', 2);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});
