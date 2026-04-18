/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Produces a deterministic byte-exact serialization of a JSON value, suitable
 * for use as Associated Data in an AEAD or as input to a signature/MAC.
 * Keys are sorted alphabetically (recursive), no whitespace is emitted, and
 * strings are escaped per §3.2 of the RFC.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8785
 */

const MAX_DEPTH = 128;
const ASCII_SAFE = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;

export function canonicalJson(obj: Record<string, unknown>): string {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new TypeError('canonicalJson: top-level value must be a plain object');
  }
  return serializeValue(obj, 0);
}

function serializeValue(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new RangeError(`canonicalJson: nesting depth exceeds ${MAX_DEPTH}`);
  }

  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      return serializeNumber(value);

    case 'string':
      return serializeString(value);

    case 'object':
      if (Array.isArray(value)) {
        return serializeArray(value, depth + 1);
      }
      if (Object.getPrototypeOf(value) !== Object.prototype) {
        throw new TypeError(
          'canonicalJson: unsupported object type (only plain objects, arrays, strings, numbers, booleans, and null are allowed)',
        );
      }
      return serializeObject(value as Record<string, unknown>, depth + 1);

    default:
      throw new TypeError(`canonicalJson: unsupported value type '${typeof value}'`);
  }
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new TypeError('canonicalJson: non-finite number');
  }
  if (Object.is(n, -0)) {
    return '0';
  }
  return JSON.stringify(n);
}

function serializeString(s: string): string {
  // Fast path: pure-ASCII string with no characters requiring escape.
  // Covers the overwhelming majority of envelope AAD inputs (alg, kid, ids).
  if (ASCII_SAFE.test(s)) {
    return `"${s}"`;
  }

  const parts: string[] = ['"'];
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);

    // Short escapes
    if (code === 0x08) {
      parts.push('\\b');
      continue;
    }
    if (code === 0x09) {
      parts.push('\\t');
      continue;
    }
    if (code === 0x0a) {
      parts.push('\\n');
      continue;
    }
    if (code === 0x0c) {
      parts.push('\\f');
      continue;
    }
    if (code === 0x0d) {
      parts.push('\\r');
      continue;
    }
    if (code === 0x22) {
      parts.push('\\"');
      continue;
    }
    if (code === 0x5c) {
      parts.push('\\\\');
      continue;
    }
    if (code < 0x20) {
      parts.push(`\\u${code.toString(16).padStart(4, '0')}`);
      continue;
    }

    // Surrogate-pair handling. RFC 8785 requires well-formed UTF-16 on the
    // input side; otherwise two distinct strings (a lone surrogate and
    // U+FFFD) would canonicalise to the same UTF-8 bytes via replacement.
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError('canonicalJson: unpaired high surrogate');
      }
      parts.push(s[i], s[i + 1]);
      i++;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError('canonicalJson: unpaired low surrogate');
    }

    parts.push(s[i]);
  }
  parts.push('"');
  return parts.join('');
}

function serializeArray(arr: unknown[], depth: number): string {
  const items: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    // Sparse-array holes serialise as null (matches JSON.stringify).
    items.push(i in arr ? serializeValue(arr[i], depth) : 'null');
  }
  return `[${items.join(',')}]`;
}

function serializeObject(obj: Record<string, unknown>, depth: number): string {
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter((key) => obj[key] !== undefined)
    .map((key) => `${serializeString(key)}:${serializeValue(obj[key], depth)}`);
  return `{${pairs.join(',')}}`;
}
