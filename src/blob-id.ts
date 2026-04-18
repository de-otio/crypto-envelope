import { randomBytes } from 'node:crypto';

const BASE62_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

function base62Encode(bytes: Uint8Array): string {
  let num = BigInt(0);
  for (const byte of bytes) {
    num = (num << 8n) | BigInt(byte);
  }

  if (num === 0n) {
    return BASE62_ALPHABET[0];
  }

  const chars: string[] = [];
  const base = BigInt(BASE62_ALPHABET.length);
  while (num > 0n) {
    const remainder = Number(num % base);
    chars.unshift(BASE62_ALPHABET[remainder]);
    num = num / base;
  }

  return chars.join('');
}

/**
 * Generate an opaque blob ID: `b_` prefix plus 16 bytes of CSPRNG entropy
 * encoded in base62. The prefix is a format marker, not a type tag —
 * callers must not encode content type or any metadata in the ID.
 */
export function generateBlobId(): string {
  const bytes = randomBytes(16);
  return `b_${base62Encode(bytes)}`;
}
