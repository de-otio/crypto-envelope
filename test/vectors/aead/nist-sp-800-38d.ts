/**
 * NIST SP 800-38D Appendix B / McGrew-Viega Test Cases for AES-256-GCM.
 *
 * Vectors reproduced verbatim from the appendix of
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 * and the original "The Galois/Counter Mode of Operation (GCM)" paper.
 *
 * These are Known-Answer Tests. A regression in `@noble/ciphers`'s AES-GCM
 * implementation or in our wrapper's ciphertext/tag split will fail one of
 * these.
 *
 * Only the AES-256 test cases are included (the 128/192 key-size variants
 * are out of scope — the package ships AES-256-GCM only).
 */

export interface AesGcmVector {
  readonly name: string;
  /** Hex-encoded 32-byte key. */
  readonly key: string;
  /** Hex-encoded 12-byte IV. */
  readonly iv: string;
  /** Hex-encoded plaintext (may be empty). */
  readonly plaintext: string;
  /** Hex-encoded additional authenticated data (may be empty). */
  readonly aad: string;
  /** Hex-encoded ciphertext (same length as plaintext). */
  readonly ciphertext: string;
  /** Hex-encoded 16-byte authentication tag. */
  readonly tag: string;
}

export const NIST_SP_800_38D_AES_256_GCM: readonly AesGcmVector[] = [
  {
    name: 'Test Case 13 — AES-256, empty plaintext, empty AAD, zero IV',
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '',
    aad: '',
    ciphertext: '',
    tag: '530f8afbc74536b9a963b4f1c4cb738b',
  },
  {
    name: 'Test Case 14 — AES-256, 16-byte zero plaintext, empty AAD',
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    iv: '000000000000000000000000',
    plaintext: '00000000000000000000000000000000',
    aad: '',
    ciphertext: 'cea7403d4d606b6e074ec5d3baf39d18',
    tag: 'd0d1c8a799996bf0265b98b5d48ab919',
  },
  {
    name: 'Test Case 15 — AES-256, full 60-byte plaintext, no AAD (McGrew-Viega)',
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    plaintext:
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
      '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    aad: '',
    ciphertext:
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
      '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
    tag: 'b094dac5d93471bdec1a502270e3cc6c',
  },
  {
    name: 'Test Case 16 — AES-256, 60-byte plaintext with AAD (McGrew-Viega)',
    key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    iv: 'cafebabefacedbaddecaf888',
    plaintext:
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
      '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    ciphertext:
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
      '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    tag: '76fc6ece0f4e1768cddf8853bb2d551b',
  },
];
