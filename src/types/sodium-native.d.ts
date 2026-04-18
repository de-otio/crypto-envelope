declare module 'sodium-native' {
  export function sodium_malloc(size: number): Buffer;
  export function sodium_memzero(buf: Buffer): void;
}
