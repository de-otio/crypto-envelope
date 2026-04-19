import { getRandomBytes } from './internal/runtime.js';

const BASE62_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

// Maximum base62 character count for 16 bytes (log62(2^128) ≈ 21.5 → 22).
const BASE62_WIDTH = 22;

function base62Encode(bytes: Uint8Array): string {
  let num = BigInt(0);
  for (const byte of bytes) {
    num = (num << 8n) | BigInt(byte);
  }

  const chars: string[] = [];
  const base = BigInt(BASE62_ALPHABET.length);
  while (num > 0n) {
    const remainder = Number(num % base);
    chars.unshift(BASE62_ALPHABET[remainder]);
    num = num / base;
  }
  while (chars.length < BASE62_WIDTH) {
    chars.unshift(BASE62_ALPHABET[0]);
  }

  return chars.join('');
}

/**
 * Generate an opaque blob ID: `b_` prefix plus 16 bytes of CSPRNG entropy
 * encoded in base62, zero-padded to a fixed 22-character body (total 24
 * chars). The prefix is a format marker, not a type tag — callers must not
 * encode content type or any metadata in the ID.
 */
export function generateBlobId(): string {
  const bytes = getRandomBytes(16);
  return `b_${base62Encode(bytes)}`;
}
