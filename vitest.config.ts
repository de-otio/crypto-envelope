import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'src/**/*.test.ts'],
    // KDF tests (PBKDF2 at the 1,000,000-iteration floor, Argon2id at
    // t=3/m=64MiB on pure-JS noble) routinely exceed vitest's 5s default
    // on slow CI runners — Ubuntu and Windows in particular. Patching
    // each affected suite individually with `{ timeout: 30_000 }` was
    // becoming whack-a-mole; bump the global default once.
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/**/*.d.ts'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
  },
});
