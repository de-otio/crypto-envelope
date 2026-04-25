import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Phase III bundler smoke test.
 *
 * Verifies the `package.json` `"browser"` field redirects:
 *   - sodium-native-backed `secure-buffer.js` → `secure-buffer.browser.js`,
 *     and stubs `sodium-native` to `false`, so no Node-only native-addon
 *     bytes land in a browser bundle;
 *   - `internal/constant-time.js` → `internal/constant-time.browser.js`,
 *     so `node:crypto.timingSafeEqual` (a Node-only built-in) is not
 *     pulled into a browser bundle and the pure-JS XOR-accumulate fallback
 *     is used instead.
 *
 * Runs `esbuild --platform=browser --bundle` against a synthetic entry
 * that imports the full `@de-otio/crypto-envelope` surface, then
 * inspects the output for forbidden substrings.
 */

describe('browser bundler smoke (esbuild)', () => {
  let workdir: string;

  beforeAll(async () => {
    workdir = await mkdtemp(join(tmpdir(), 'ce-bundler-smoke-'));
  });

  afterAll(async () => {
    await rm(workdir, { recursive: true, force: true });
  });

  it('bundles for browser without pulling sodium-native', async () => {
    // Synthetic entry that exercises the full public surface — every
    // export path. If any of these pulls sodium-native transitively,
    // the assertion below fails.
    const entry = join(workdir, 'entry.ts');
    await writeFile(
      entry,
      `
import { SecureBuffer, EnvelopeClient, deriveMasterKeyFromPassphrase, canonicalJson } from '${process.cwd().replace(/\\/g, '/')}/dist/index.js';
import { aeadEncrypt, aeadDecrypt, deriveKey, pbkdf2Sha256 } from '${process.cwd().replace(/\\/g, '/')}/dist/primitives/index.js';

// Reference every import so esbuild keeps them in the bundle.
globalThis.__ce = {
  SecureBuffer,
  EnvelopeClient,
  deriveMasterKeyFromPassphrase,
  canonicalJson,
  aeadEncrypt,
  aeadDecrypt,
  deriveKey,
  pbkdf2Sha256,
};
`,
      'utf8',
    );

    const out = join(workdir, 'bundle.js');
    await build({
      entryPoints: [entry],
      outfile: out,
      bundle: true,
      platform: 'browser',
      format: 'esm',
      target: 'es2022',
      // Respect this package's browser-field swap when resolving our own
      // package's files.
      mainFields: ['browser', 'module', 'main'],
      conditions: ['browser', 'import'],
      // sodium-native is listed as `false` in our browser field; tell
      // esbuild to treat it as external-browser-safe so a stray reference
      // wouldn't break the bundle (instead it would become `undefined`).
      external: [],
      logLevel: 'silent',
    });

    const bundle = await readFile(out, 'utf8');

    // Forbidden: sodium-native is a native addon; no sodium_* function
    // calls should appear.
    expect(bundle).not.toMatch(/sodium_malloc/);
    expect(bundle).not.toMatch(/sodium_memzero/);
    expect(bundle).not.toMatch(/sodium-native/);
    expect(bundle).not.toMatch(/\.node['"]/); // no .node native-addon file references

    // Forbidden: `node:crypto.timingSafeEqual` is a Node-only built-in.
    // The browser-field swap must redirect `internal/constant-time.js`
    // to `internal/constant-time.browser.js`, so neither the import
    // specifier nor the symbol should appear anywhere in the bundle.
    expect(bundle).not.toMatch(/['"]node:crypto['"]/);
    expect(bundle).not.toMatch(/timingSafeEqual/);

    // Expected: the browser SecureBuffer's sentinel error message is in
    // the bundle (proves the browser variant was substituted in).
    expect(bundle).toMatch(/insecureMemory.*acknowledgement/);
  }, 30_000);
});
