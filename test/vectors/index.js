/**
 * test/vectors/index.js
 *
 * Re-exports pinned test vectors for use by downstream forks and implementations.
 *
 * Published via the `"./test-vectors"` subpath export in package.json.
 * The JSON files are included in the npm tarball (see `files` in package.json).
 *
 * Usage (after installing @de-otio/crypto-envelope):
 *
 *   import { envelopeV1Vectors } from '@de-otio/crypto-envelope/test-vectors';
 *   // or (CJS)
 *   const { envelopeV1Vectors } = require('@de-otio/crypto-envelope/test-vectors');
 *
 * Vector schema: see tools/regen-vectors.ts for canonical definitions.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadJsonDir(subdir) {
  const dir = join(__dirname, subdir);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}

export const envelopeV1Vectors = loadJsonDir('envelope-v1');
export const envelopeV2Vectors = loadJsonDir('envelope-v2');
export const hkdfVectors = loadJsonDir('hkdf');
export const commitmentVectors = loadJsonDir('commitment');
export const canonicalJsonVectors = loadJsonDir('canonical-json');
export const rewrapVectors = loadJsonDir('rewrap');
