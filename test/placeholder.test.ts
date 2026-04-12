import { describe, expect, it } from 'vitest';
import { PACKAGE_NAME, PACKAGE_VERSION } from '../src/index.js';

describe('@de-otio/crypto-envelope', () => {
  it('identifies itself', () => {
    expect(PACKAGE_NAME).toBe('@de-otio/crypto-envelope');
  });

  it('has a version', () => {
    expect(PACKAGE_VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
