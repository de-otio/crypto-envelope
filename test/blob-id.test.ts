import { describe, expect, it } from 'vitest';
import { generateBlobId } from '../src/blob-id.js';

const BLOB_ID_REGEX = /^b_[0-9a-zA-Z]{22}$/;

describe('generateBlobId', () => {
  it('starts with b_ prefix', () => {
    expect(generateBlobId().startsWith('b_')).toBe(true);
  });

  it('matches the fixed-width format b_ + 22 base62 chars', () => {
    // Run enough samples to catch any edge case where the leading byte is
    // zero (historical bug: variable-length output of 20–22 chars).
    for (let i = 0; i < 1000; i++) {
      expect(BLOB_ID_REGEX.test(generateBlobId())).toBe(true);
    }
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
