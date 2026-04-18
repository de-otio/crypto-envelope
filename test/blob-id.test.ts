import { describe, expect, it } from 'vitest';
import { generateBlobId } from '../src/blob-id.js';

const BASE62_REGEX = /^b_[0-9a-zA-Z]+$/;

describe('generateBlobId', () => {
  it('starts with b_ prefix', () => {
    expect(generateBlobId().startsWith('b_')).toBe(true);
  });

  it('contains only base62 characters after prefix', () => {
    expect(BASE62_REGEX.test(generateBlobId())).toBe(true);
  });

  it('has length consistent with 128 bits of entropy', () => {
    const body = generateBlobId().slice(2);
    expect(body.length).toBeGreaterThanOrEqual(20);
    expect(body.length).toBeLessThanOrEqual(23);
  });

  it('generates unique IDs across a large sample', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(generateBlobId());
    }
    expect(ids.size).toBe(1000);
  });

  it('does not encode payload type in the ID', () => {
    const id = generateBlobId();
    expect(id).not.toContain('source');
    expect(id).not.toContain('chunk');
    expect(id).not.toContain('canary');
  });
});
