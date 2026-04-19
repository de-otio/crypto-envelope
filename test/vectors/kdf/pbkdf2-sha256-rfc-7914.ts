/**
 * PBKDF2-SHA256 Known-Answer Tests.
 *
 * RFC 6070 defines PBKDF2-SHA1 vectors; RFC 7914 (scrypt) defines
 * PBKDF2-SHA256 vectors in §11 as a building-block reference. These are
 * the vectors most TypeScript PBKDF2 implementations reproduce; they are
 * also mirrored in NIST CAVP for FIPS validation.
 *
 * A regression in `@noble/hashes/pbkdf2` or in our wrapper's iteration
 * count / output length handling will fail one of these.
 */

export interface Pbkdf2Vector {
  readonly name: string;
  /** UTF-8 string passphrase (bytes encoded at test time). */
  readonly passphrase: string;
  /** UTF-8 string salt (bytes encoded at test time). */
  readonly salt: string;
  readonly iterations: number;
  readonly dkLen: number;
  /** Hex-encoded expected derived key. */
  readonly dk: string;
}

export const RFC_7914_PBKDF2_SHA256: readonly Pbkdf2Vector[] = [
  {
    name: 'RFC 7914 §11 — "passwd" / "salt" / c=1',
    passphrase: 'passwd',
    salt: 'salt',
    iterations: 1,
    dkLen: 64,
    dk:
      '55ac046e56e3089fec1691c22544b605' +
      'f94185216dde0465e68b9d57c20dacbc' +
      '49ca9cccf179b645991664b39d77ef31' +
      '7c71b845b1e30bd509112041d3a19783',
  },
  {
    name: 'RFC 7914 §11 — "Password" / "NaCl" / c=80000',
    passphrase: 'Password',
    salt: 'NaCl',
    iterations: 80000,
    dkLen: 64,
    dk:
      '4ddcd8f60b98be21830cee5ef22701f9' +
      '641a4418d04c0414aeff08876b34ab56' +
      'a1d425a1225833549adb841b51c9b317' +
      '6a272bdebba1d078478f62b397f33c8d',
  },
];
