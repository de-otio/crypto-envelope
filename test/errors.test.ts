/**
 * Error taxonomy tests for @de-otio/crypto-envelope.
 *
 * Acceptance criteria:
 *   1. Each error class has a stable `code` discriminator.
 *   2. Wrong CEK, tampered ciphertext, tampered AAD, tampered commitment,
 *      and wrong commit key ALL produce AuthenticationFailedError with
 *      IDENTICAL messages — partitioning-oracle defence.
 *   3. Structural problems (bad alg, bad version, bad CBOR/JSON, truncation)
 *      produce distinguishable, unauthenticated error classes.
 */

import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptV1, deserializeV1, encryptV1 } from '../src/envelope/v1.js';
import { deserializeV2 } from '../src/envelope/v2.js';
import {
  AuthenticationFailedError,
  EnvelopeError,
  MalformedEnvelopeError,
  TruncatedCiphertextError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from '../src/errors.js';
import { deriveCommitKey, deriveContentKey } from '../src/primitives/hkdf.js';
import type { EnvelopeV1 } from '../src/types.js';

// ── Test helpers ─────────────────────────────────────────────────────────

function keys(seed = 0x42) {
  const master = new Uint8Array(32).fill(seed);
  return { cek: deriveContentKey(master), commitKey: deriveCommitKey(master) };
}

function freshEnvelope(seed = 0x42): { env: EnvelopeV1; cek: Uint8Array; commitKey: Uint8Array } {
  const { cek, commitKey } = keys(seed);
  const env = encryptV1({
    payload: { secret: 'hello' },
    cek,
    commitKey,
    kid: 'default',
  });
  return { env, cek, commitKey };
}

// ── Error hierarchy ───────────────────────────────────────────────────────

describe('error class hierarchy', () => {
  it('EnvelopeError is an Error', () => {
    const err = new EnvelopeError('MY_CODE', 'test');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe('MY_CODE');
    expect(err.message).toBe('test');
  });

  it('AuthenticationFailedError extends EnvelopeError', () => {
    const err = new AuthenticationFailedError();
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err).toBeInstanceOf(AuthenticationFailedError);
    expect(err.code).toBe('AUTHENTICATION_FAILED');
    expect(err.name).toBe('AuthenticationFailedError');
  });

  it('UnsupportedAlgorithmError extends EnvelopeError', () => {
    const err = new UnsupportedAlgorithmError('AES-128-CBC');
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
    expect(err.message).toContain('AES-128-CBC');
    expect(err.name).toBe('UnsupportedAlgorithmError');
  });

  it('UnsupportedVersionError extends EnvelopeError', () => {
    const err = new UnsupportedVersionError(99);
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe('UNSUPPORTED_VERSION');
    expect(err.message).toContain('99');
    expect(err.name).toBe('UnsupportedVersionError');
  });

  it('MalformedEnvelopeError extends EnvelopeError', () => {
    const err = new MalformedEnvelopeError('bad base64');
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe('MALFORMED_ENVELOPE');
    expect(err.message).toContain('bad base64');
    expect(err.name).toBe('MalformedEnvelopeError');
  });

  it('TruncatedCiphertextError extends EnvelopeError', () => {
    const err = new TruncatedCiphertextError(40, 10);
    expect(err).toBeInstanceOf(EnvelopeError);
    expect(err.code).toBe('TRUNCATED_CIPHERTEXT');
    expect(err.message).toContain('40');
    expect(err.message).toContain('10');
    expect(err.name).toBe('TruncatedCiphertextError');
  });
});

// ── Stable `code` discriminators ─────────────────────────────────────────

describe('stable code discriminators', () => {
  it('all error classes have their documented codes', () => {
    expect(new EnvelopeError('X', 'y').code).toBe('X');
    expect(new AuthenticationFailedError().code).toBe('AUTHENTICATION_FAILED');
    expect(new UnsupportedAlgorithmError('x').code).toBe('UNSUPPORTED_ALGORITHM');
    expect(new UnsupportedVersionError(0).code).toBe('UNSUPPORTED_VERSION');
    expect(new MalformedEnvelopeError('x').code).toBe('MALFORMED_ENVELOPE');
    expect(new TruncatedCiphertextError(1, 0).code).toBe('TRUNCATED_CIPHERTEXT');
  });

  it('codes are usable in a switch statement', () => {
    function classify(e: EnvelopeError): string {
      switch (e.code) {
        case 'AUTHENTICATION_FAILED':
          return 'auth';
        case 'UNSUPPORTED_ALGORITHM':
          return 'alg';
        case 'UNSUPPORTED_VERSION':
          return 'version';
        case 'MALFORMED_ENVELOPE':
          return 'malformed';
        case 'TRUNCATED_CIPHERTEXT':
          return 'truncated';
        default:
          return 'unknown';
      }
    }

    expect(classify(new AuthenticationFailedError())).toBe('auth');
    expect(classify(new UnsupportedAlgorithmError('x'))).toBe('alg');
    expect(classify(new UnsupportedVersionError(0))).toBe('version');
    expect(classify(new MalformedEnvelopeError('x'))).toBe('malformed');
    expect(classify(new TruncatedCiphertextError(1, 0))).toBe('truncated');
  });
});

// ── Authentication failures (partitioning-oracle defence) ─────────────────

describe('AuthenticationFailedError — partitioning-oracle defence', () => {
  /**
   * Security property: ALL of the following must produce AuthenticationFailedError
   * with IDENTICAL error messages. Distinguishing any two would allow an
   * attacker with decrypt-oracle access to partition candidate key sets
   * (Len–Grubbs–Ristenpart, USENIX 2021, §4.2).
   */

  it('wrong CEK throws AuthenticationFailedError', () => {
    const { env, commitKey } = freshEnvelope();
    const wrongCek = new Uint8Array(randomBytes(32));
    expect(() => decryptV1(env, wrongCek, commitKey)).toThrowError(AuthenticationFailedError);
  });

  it('tampered ciphertext throws AuthenticationFailedError', () => {
    const { env, cek, commitKey } = freshEnvelope();
    // Tamper inside the ciphertext body (skip nonce, stay in ct body, not tag)
    const ctBytes = Buffer.from(env.enc.ct, 'base64');
    ctBytes[30] ^= 0x01;
    // Also update ct.len and commitment to bypass structural checks;
    // however, the commitment is keyed on rawCt — tampering ct will break
    // commitment. So the AuthenticationFailedError comes from commitment.
    const tampered: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, ct: ctBytes.toString('base64') },
    };
    expect(() => decryptV1(tampered, cek, commitKey)).toThrowError(AuthenticationFailedError);
  });

  it('tampered AAD (via kid) throws AuthenticationFailedError', () => {
    const { env, cek, commitKey } = freshEnvelope();
    // Mutate kid — AAD changes, AEAD verify fails.
    // But first we need to pass the commitment check, which covers rawCt
    // (not kid). The commitment check passes (rawCt unchanged), but AEAD
    // fails because AAD is reconstructed from the envelope fields.
    const tampered: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, kid: 'attacker' },
    };
    expect(() => decryptV1(tampered, cek, commitKey)).toThrowError(AuthenticationFailedError);
  });

  it('tampered commitment throws AuthenticationFailedError', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const fakeCommit = Buffer.alloc(32, 0xff).toString('base64');
    const tampered: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, commit: fakeCommit },
    };
    expect(() => decryptV1(tampered, cek, commitKey)).toThrowError(AuthenticationFailedError);
  });

  it('wrong commit key throws AuthenticationFailedError', () => {
    const { env, cek } = freshEnvelope();
    const wrongCommitKey = new Uint8Array(randomBytes(32));
    expect(() => decryptV1(env, cek, wrongCommitKey)).toThrowError(AuthenticationFailedError);
  });

  it('ALL five authenticated failures produce IDENTICAL error messages', () => {
    // This is the key partitioning-oracle invariant: no observable distinguishes
    // wrong-key from tampered-envelope through the error.
    const { env, cek, commitKey } = freshEnvelope();

    function getMsg(fn: () => void): string {
      try {
        fn();
        return 'no-throw';
      } catch (e) {
        return e instanceof Error ? e.message : String(e);
      }
    }

    const wrongCek = new Uint8Array(randomBytes(32));
    const wrongCommit = new Uint8Array(randomBytes(32));
    const fakeCommit = Buffer.alloc(32, 0xff).toString('base64');
    const ctBytes = Buffer.from(env.enc.ct, 'base64');
    ctBytes[30] ^= 0x01;
    const tamperedCt: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, ct: ctBytes.toString('base64') },
    };
    const tamperedCommit: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, commit: fakeCommit },
    };
    const tamperedKid: EnvelopeV1 = {
      ...env,
      enc: { ...env.enc, kid: 'attacker' },
    };

    const msg1 = getMsg(() => decryptV1(env, wrongCek, commitKey)); // wrong CEK
    const msg2 = getMsg(() => decryptV1(tamperedCt, cek, commitKey)); // tampered ct
    const msg3 = getMsg(() => decryptV1(tamperedKid, cek, commitKey)); // tampered AAD
    const msg4 = getMsg(() => decryptV1(tamperedCommit, cek, commitKey)); // tampered commit
    const msg5 = getMsg(() => decryptV1(env, cek, wrongCommit)); // wrong commit key

    // All five must be the same message.
    const expected = AuthenticationFailedError.MESSAGE;
    expect(msg1).toBe(expected);
    expect(msg2).toBe(expected);
    expect(msg3).toBe(expected);
    expect(msg4).toBe(expected);
    expect(msg5).toBe(expected);
  });
});

// ── Structural / unauthenticated errors ──────────────────────────────────

describe('UnsupportedAlgorithmError', () => {
  it('thrown for unrecognised alg name on decrypt', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const badAlg = { ...env, enc: { ...env.enc, alg: 'AES-128-CBC' as 'XChaCha20-Poly1305' } };
    expect(() => decryptV1(badAlg, cek, commitKey)).toThrowError(UnsupportedAlgorithmError);
    expect(() => decryptV1(badAlg, cek, commitKey)).toThrowError(/unsupported algorithm/i);
  });

  it('error has code UNSUPPORTED_ALGORITHM', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const badAlg = { ...env, enc: { ...env.enc, alg: 'AES-128-CBC' as 'XChaCha20-Poly1305' } };
    try {
      decryptV1(badAlg, cek, commitKey);
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedAlgorithmError);
      expect((e as UnsupportedAlgorithmError).code).toBe('UNSUPPORTED_ALGORITHM');
    }
  });
});

describe('UnsupportedVersionError', () => {
  it('thrown for unknown v field on decrypt', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const badV = { ...env, v: 99 as unknown as 1 };
    expect(() => decryptV1(badV, cek, commitKey)).toThrowError(UnsupportedVersionError);
  });

  it('error has code UNSUPPORTED_VERSION', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const badV = { ...env, v: 99 as unknown as 1 };
    try {
      decryptV1(badV, cek, commitKey);
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedVersionError);
      expect((e as UnsupportedVersionError).code).toBe('UNSUPPORTED_VERSION');
    }
  });
});

describe('MalformedEnvelopeError', () => {
  it('thrown for bad JSON bytes in deserializeV1', () => {
    const garbage = new TextEncoder().encode('not-json{{{');
    expect(() => deserializeV1(garbage)).toThrowError(MalformedEnvelopeError);
  });

  it('thrown for missing CBOR magic in deserializeV2', () => {
    expect(() => deserializeV2(new Uint8Array([0x01, 0x02, 0x03]))).toThrowError(
      MalformedEnvelopeError,
    );
  });

  it('thrown for CBOR envelope with unexpected version', async () => {
    const { encode } = await import('cborg');
    const body = encode({
      v: 99,
      id: 'b_x',
      ts: 'now',
      enc: {
        alg: 'XChaCha20-Poly1305',
        kid: 'k',
        ct: new Uint8Array(1),
        commit: new Uint8Array(1),
      },
    });
    const bytes = new Uint8Array(3 + body.length);
    bytes.set([0x43, 0x4b, 0x42], 0);
    bytes.set(body, 3);
    expect(() => deserializeV2(bytes)).toThrowError(MalformedEnvelopeError);
  });

  it('thrown for ciphertext length mismatch', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const mismatch = { ...env, enc: { ...env.enc, 'ct.len': env.enc['ct.len'] + 1 } };
    expect(() => decryptV1(mismatch, cek, commitKey)).toThrowError(MalformedEnvelopeError);
  });

  it('error has code MALFORMED_ENVELOPE', () => {
    expect(() => deserializeV2(new Uint8Array(3))).toThrowError(
      expect.objectContaining({ code: 'MALFORMED_ENVELOPE' }),
    );
  });
});

describe('TruncatedCiphertextError', () => {
  it('thrown when ciphertext is shorter than nonce+tag', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const tooShort = Buffer.alloc(10).toString('base64');
    const truncated = { ...env, enc: { ...env.enc, ct: tooShort, 'ct.len': 10 } };
    expect(() => decryptV1(truncated, cek, commitKey)).toThrowError(TruncatedCiphertextError);
  });

  it('error has code TRUNCATED_CIPHERTEXT', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const tooShort = Buffer.alloc(10).toString('base64');
    const truncated = { ...env, enc: { ...env.enc, ct: tooShort, 'ct.len': 10 } };
    try {
      decryptV1(truncated, cek, commitKey);
    } catch (e) {
      expect(e).toBeInstanceOf(TruncatedCiphertextError);
      expect((e as TruncatedCiphertextError).code).toBe('TRUNCATED_CIPHERTEXT');
    }
  });

  it('error message contains expected and actual sizes', () => {
    const { env, cek, commitKey } = freshEnvelope();
    const tooShort = Buffer.alloc(10).toString('base64');
    const truncated = { ...env, enc: { ...env.enc, ct: tooShort, 'ct.len': 10 } };
    try {
      decryptV1(truncated, cek, commitKey);
    } catch (e) {
      expect((e as TruncatedCiphertextError).message).toMatch(/10/);
    }
  });
});
