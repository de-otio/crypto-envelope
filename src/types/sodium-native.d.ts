// Shim for sodium-native@5 — only the symbols crypto-envelope actually
// uses. Review on version bump.
declare module 'sodium-native' {
  export function sodium_malloc(size: number): Buffer;
  export function sodium_memzero(buf: Buffer): void;
  export function crypto_pwhash(
    output: Buffer,
    password: Buffer,
    salt: Buffer,
    opslimit: number,
    memlimit: number,
    algorithm: number,
  ): void;
  export const crypto_pwhash_ALG_ARGON2ID13: number;
  export const crypto_pwhash_SALTBYTES: number;
}
