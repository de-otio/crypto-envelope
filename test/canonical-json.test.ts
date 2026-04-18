import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/canonical-json.js';

describe('canonicalJson', () => {
  describe('key sorting', () => {
    it('sorts keys alphabetically', () => {
      expect(canonicalJson({ z: 1, a: 2, m: 3 })).toBe('{"a":2,"m":3,"z":1}');
    });

    it('sorts keys recursively in nested objects', () => {
      expect(canonicalJson({ b: { z: 1, a: 2 }, a: 1 })).toBe('{"a":1,"b":{"a":2,"z":1}}');
    });

    it('sorts keys in objects within arrays', () => {
      expect(canonicalJson({ arr: [{ z: 1, a: 2 }] })).toBe('{"arr":[{"a":2,"z":1}]}');
    });
  });

  describe('no whitespace', () => {
    it('produces compact output with no whitespace', () => {
      const result = canonicalJson({ key: 'value', num: 42 });
      expect(result).not.toContain(' ');
      expect(result).not.toContain('\n');
      expect(result).not.toContain('\t');
    });
  });

  describe('string escaping', () => {
    it('escapes control characters', () => {
      expect(canonicalJson({ s: '\x00\x01\x1f' })).toBe('{"s":"\\u0000\\u0001\\u001f"}');
    });

    it('escapes backslash', () => {
      expect(canonicalJson({ s: 'a\\b' })).toBe('{"s":"a\\\\b"}');
    });

    it('escapes double quotes', () => {
      expect(canonicalJson({ s: 'a"b' })).toBe('{"s":"a\\"b"}');
    });

    it('uses short escapes for special characters', () => {
      expect(canonicalJson({ s: '\b\t\n\f\r' })).toBe('{"s":"\\b\\t\\n\\f\\r"}');
    });

    it('passes through a valid surrogate pair (emoji)', () => {
      const result = canonicalJson({ s: 'hello \u{1F600}' });
      expect(result).toContain('\u{1F600}');
    });

    it('rejects lone high surrogate', () => {
      expect(() => canonicalJson({ s: '\uD800' })).toThrow('unpaired high surrogate');
      expect(() => canonicalJson({ s: '\uD800x' })).toThrow('unpaired high surrogate');
    });

    it('rejects lone low surrogate', () => {
      expect(() => canonicalJson({ s: '\uDC00' })).toThrow('unpaired low surrogate');
    });

    it('handles the U+2028 line separator without special treatment', () => {
      // Differs from ECMA-262 §12.8.4 but matches RFC 8785 (JSON does not
      // distinguish). Should appear literally.
      const result = canonicalJson({ s: '\u2028' });
      expect(result).toContain('\u2028');
    });
  });

  describe('number serialization', () => {
    it('serializes integers without decimal point', () => {
      expect(canonicalJson({ n: 42 })).toBe('{"n":42}');
    });

    it('serializes negative zero as 0', () => {
      expect(canonicalJson({ n: -0 })).toBe('{"n":0}');
    });

    it('serializes floats', () => {
      expect(canonicalJson({ n: 3.14 })).toBe('{"n":3.14}');
    });

    it('rejects NaN', () => {
      expect(() => canonicalJson({ n: Number.NaN })).toThrow('non-finite');
    });

    it('rejects Infinity', () => {
      expect(() => canonicalJson({ n: Number.POSITIVE_INFINITY })).toThrow('non-finite');
    });

    it('serialises large positive exponents identically to JSON.stringify', () => {
      // RFC 8785 §3.2.2.3 defers number serialisation to ES §7.1.12.1,
      // which is what V8's JSON.stringify implements (Ryū-based).
      expect(canonicalJson({ n: 1e30 })).toBe(`{"n":${JSON.stringify(1e30)}}`);
    });

    it('serialises small magnitudes', () => {
      expect(canonicalJson({ n: 0.000001 })).toBe(`{"n":${JSON.stringify(0.000001)}}`);
    });

    it('serialises integers above the safe integer boundary', () => {
      // 2^53 is exactly representable; 2^53 + 1 collapses to 2^53. Not a
      // library bug — a fundamental JS Number limitation; consumers that
      // need precise large integers must pass them as strings.
      expect(canonicalJson({ n: 2 ** 53 })).toBe(`{"n":${JSON.stringify(2 ** 53)}}`);
    });
  });

  describe('null and boolean', () => {
    it('serializes null', () => {
      expect(canonicalJson({ v: null })).toBe('{"v":null}');
    });

    it('serializes booleans', () => {
      expect(canonicalJson({ t: true, f: false })).toBe('{"f":false,"t":true}');
    });
  });

  describe('arrays', () => {
    it('serializes arrays', () => {
      expect(canonicalJson({ a: [1, 2, 3] })).toBe('{"a":[1,2,3]}');
    });

    it('serializes empty arrays', () => {
      expect(canonicalJson({ a: [] })).toBe('{"a":[]}');
    });

    it('emits null for sparse-array holes (matches JSON.stringify)', () => {
      // biome-ignore lint/suspicious/noSparseArray: testing sparse-array handling
      const sparse: unknown[] = [1, , 3];
      expect(canonicalJson({ a: sparse })).toBe('{"a":[1,null,3]}');
    });
  });

  describe('undefined values', () => {
    it('omits undefined values', () => {
      expect(canonicalJson({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
    });
  });

  describe('top-level input guard', () => {
    it('rejects a non-object top level', () => {
      expect(() => canonicalJson(42 as unknown as Record<string, unknown>)).toThrow('plain object');
      expect(() => canonicalJson(null as unknown as Record<string, unknown>)).toThrow(
        'plain object',
      );
      expect(() => canonicalJson([1, 2] as unknown as Record<string, unknown>)).toThrow(
        'plain object',
      );
    });
  });

  describe('non-plain object rejection', () => {
    it('rejects Date', () => {
      expect(() => canonicalJson({ d: new Date() })).toThrow('unsupported object type');
    });

    it('rejects Map', () => {
      expect(() => canonicalJson({ m: new Map() })).toThrow('unsupported object type');
    });

    it('rejects Set', () => {
      expect(() => canonicalJson({ s: new Set() })).toThrow('unsupported object type');
    });

    it('rejects class instances', () => {
      class Foo {
        x = 1;
      }
      expect(() => canonicalJson({ v: new Foo() })).toThrow('unsupported object type');
    });
  });

  describe('recursion guard', () => {
    it('rejects deeply nested objects beyond the depth cap', () => {
      let obj: Record<string, unknown> = { leaf: 1 };
      for (let i = 0; i < 200; i++) {
        obj = { wrap: obj };
      }
      expect(() => canonicalJson(obj)).toThrow(/nesting depth/);
    });
  });

  describe('envelope AAD examples', () => {
    it('matches the envelope AAD shape', () => {
      const result = canonicalJson({
        alg: 'XChaCha20-Poly1305',
        id: 'b_test000000000000',
        kid: 'CEK',
        v: 1,
      });
      expect(result).toBe(
        '{"alg":"XChaCha20-Poly1305","id":"b_test000000000000","kid":"CEK","v":1}',
      );
    });
  });
});
