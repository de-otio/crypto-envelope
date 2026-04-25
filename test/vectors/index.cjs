'use strict';
/**
 * test/vectors/index.cjs
 *
 * CommonJS re-export of pinned test vectors.
 * Loaded when the consumer uses require('@de-otio/crypto-envelope/test-vectors').
 */

const { readdirSync, readFileSync } = require('node:fs');
const { join } = require('node:path');

function loadJsonDir(subdir) {
  const dir = join(__dirname, subdir);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}

module.exports = {
  envelopeV1Vectors: loadJsonDir('envelope-v1'),
  envelopeV2Vectors: loadJsonDir('envelope-v2'),
  hkdfVectors: loadJsonDir('hkdf'),
  commitmentVectors: loadJsonDir('commitment'),
  canonicalJsonVectors: loadJsonDir('canonical-json'),
  rewrapVectors: loadJsonDir('rewrap'),
};
