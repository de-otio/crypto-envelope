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

    it('passes through non-BMP characters (emoji) literally', () => {
      const result = canonicalJson({ s: 'hello \u{1F600}' });
      expect(result).toContain('\u{1F600}');
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
      expect(() => canonicalJson({ n: Number.NaN })).toThrow('Non-finite');
    });

    it('rejects Infinity', () => {
      expect(() => canonicalJson({ n: Number.POSITIVE_INFINITY })).toThrow('Non-finite');
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
  });

  describe('undefined values', () => {
    it('omits undefined values', () => {
      expect(canonicalJson({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
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
