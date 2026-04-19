# Changelog

All notable changes to `@de-otio/crypto-envelope` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.1] - 2026-04-19

Second pre-release. Implements plan-02 Phases I–IV — AES-256-GCM as a second AEAD algorithm, unified passphrase-KDF with `MasterKey` brand, strict-by-default browser `SecureBuffer`, and `EnvelopeClient` algorithm selection with the 2³² AES-GCM hard cap. The package now runs on any WebCrypto-compliant runtime (Node ≥22, modern browsers, Deno ≥2, Bun ≥1, Cloudflare Workers, Vercel Edge).

Installs as `@de-otio/crypto-envelope@alpha`. The `@latest` tag remains deliberately unused until chaoskb and trellis each ship a production release on this line.

**Breaking (pre-1.0 alpha line):** `EnvelopeClient.encrypt` / `decrypt` are now `async`; `aeadEncrypt` / `aeadDecrypt` primitives take an explicit `alg` parameter. No external API change for consumers that only use the envelope client's public surface via the v0.1 quick-use pattern, modulo the `async` update.

### Added — Phase I (AES-256-GCM primitive)

- **AES-256-GCM as a second AEAD algorithm** alongside XChaCha20-Poly1305. `Algorithm` union widens to `'XChaCha20-Poly1305' | 'AES-256-GCM'`. Implementation via `@noble/ciphers/aes`'s `gcm(key, nonce, aad)` — the same noble stack already shipping for XChaCha, no new runtime dependency.
- `aeadEncrypt(alg, key, plaintext, aad)` / `aeadDecrypt(alg, key, nonce, ciphertext, tag, aad)` now take an explicit `alg` parameter (breaking change within the pre-1.0 alpha line — callers in this package already updated; chaoskb does not import the primitive directly).
- `nonceLengthFor(alg)` helper returns 24 (XChaCha) or 12 (AES-GCM). Per-algorithm exports `XCHACHA_NONCE_LENGTH`, `AES_GCM_NONCE_LENGTH`, `KEY_LENGTH`, `TAG_LENGTH`.
- NIST SP 800-38D Appendix B / McGrew-Viega AES-256-GCM test cases 13–16 added as Known-Answer Tests (`test/aead-aes-gcm-kats.test.ts`). Tamper detection (tag, ciphertext, AAD) asserted per vector.
- Wycheproof adversarial vectors — 66 AES-256-GCM / 96-bit-IV / 128-bit-tag cases from [C2SP/wycheproof](https://github.com/C2SP/wycheproof) committed as a filtered snapshot under `test/vectors/aead/wycheproof-aes-256-gcm.json`. Covers short tags, all-zero IV, malformed encodings; every Wycheproof verdict (`valid`/`invalid`/`acceptable`) is honoured.
- Existing AEAD test suite parameterised over both algorithms — round-trip, tamper detection on ciphertext/tag/AAD/nonce, key-length validation, empty-AAD handling, large payloads. Both algorithms pass identical invariants.
- Cross-algorithm substitution rejection tests — an XChaCha ciphertext cannot be presented as AES-GCM and vice versa (defeated by nonce-width check; envelope layer further binds `alg` into AAD).

### Changed — Phase I

- `envelope/v1.ts` routes through the new dispatch surface. v1 envelopes currently still produce XChaCha; Phase IV widens `EnvelopeClient` to select the AES-GCM path at encrypt time.
- `NONCE_LENGTH` export remains as a `@deprecated` alias for `XCHACHA_NONCE_LENGTH` to keep any external callers compiling; removal scheduled for v0.3.
- `Algorithm` type documents the 96-bit-vs-192-bit nonce trade-off, the per-key message bound for AES-GCM (2³² per NIST SP 800-38D §8.3, hard cap enforced in Phase IV per design-review blocker B2), and the commitment's key-committing (not context-committing) property.

### Added — Phase II (PBKDF2 + passphrase-KDF unification)

- **`MasterKey` branded type** (`ISecureBuffer & { readonly __brand: 'MasterKey' }`) — the 32-byte key that seeds `EnvelopeClient` (Phase IV) and `@de-otio/keyring`'s tier system. The brand prevents key-confusion at compile time (design-review blocker B8): passphrase-derived bytes cannot be handed to an AEAD primitive as a CEK without an explicit unbranding cast.
- **`deriveMasterKeyFromPassphrase(passphrase, salt, params, options?)`** in `src/passphrase.ts` — unified, async, branded-return passphrase KDF with `AbortSignal` support. Discriminated-union `PassphraseKdfParams`:
  - `{ algorithm: 'argon2id' }` — **mandatory default** at OWASP 2023 second-tier parameters (t=3, m=64 MiB, p=1, dkLen=32).
  - `{ algorithm: 'pbkdf2-sha256', iterations: N }` — **compatibility-only fallback**. WebCrypto-constrained runtimes where shipping WASM Argon2 is not viable. Runtime one-time `console.warn` when this branch is taken, naming the Argon2id-preferred posture.
- **PBKDF2-SHA256 iteration floor: 1,000,000** (raised from OWASP 2023's 600,000 per design-review should-fix S1 — hardware improves ~30%/year; the 1M floor keeps PBKDF2-on-2026-hardware roughly at OWASP's intended cost budget). Reviewed annually per SECURITY.md cadence commitments.
- **`pbkdf2Sha256(passphrase, salt, params)`** primitive export under `./primitives` — thin wrapper over `@noble/hashes/pbkdf2`, pure-JS, runs on every WebCrypto-compliant runtime.
- **`asMasterKey(buf: ISecureBuffer): MasterKey`** — brand-assertion helper for advanced callers (test vectors, migration paths, hardware-sourced key material). Rejects buffers not exactly 32 bytes.
- RFC 7914 §11 PBKDF2-SHA256 Known-Answer Tests covering `c=1` (fast path) and `c=80000` (full iteration). Matches the most-reproduced PBKDF2-SHA256 reference vectors; a regression in `@noble/hashes/pbkdf2` or in the wrapper's iteration/length handling will fail these.
- `AbortSignal` on `deriveMasterKeyFromPassphrase`: checked pre- and post-derivation. Argon2id runs synchronously inside `@noble/hashes` so the signal does not interrupt mid-iteration; a future release may chunk the loop.
- Internal testing helper `_resetPbkdf2WarnForTests()` exported (underscore-prefixed) so the one-time-per-process warn flag can be reset in tests. Not part of the public API.

### Notes — Phase II

- **Argon2id migration (design-review B3 / plan §5 / §3.2) is a no-op.** chaoskb's `sodium-native`-backed Argon2 was extracted to `@noble/hashes/argon2` back in Phase B of plan-01 (see v0.1.0-alpha.1 entry below), so Phase II has no algorithm-implementation change on the Argon2 side — only the unified caller surface is new.
- Runtime deps unchanged: `@noble/hashes` was already at the required version; `sodium-native` stays for `SecureBuffer`'s mlock/zero (Node-only, unchanged).

### Added — Phase III (SecureBuffer browser variant + runtime portability)

- **`SecureBufferBrowser`** in `src/secure-buffer.browser.ts` — strict-by-default `ISecureBuffer` implementation for runtimes without `mlock`. Constructor and factory methods require an explicit `{ insecureMemory: true }` acknowledgement; omitting the flag **throws** rather than silently degrading (design-review Q1 / chaoskb browser plugin threat model). Fresh `ArrayBuffer` per allocation — no pool aliasing. `fill(0)` on dispose (best-effort; documented limitation — V8 GC may relocate before the zero).
- **`InsecureMemoryAck` type** exported from `src/secure-buffer.ts`. Node's `SecureBuffer` accepts it as an optional no-op second arg to `from` / `alloc` so portable code can pass the flag everywhere; runtime asymmetry is that Node ignores it and browser enforces it.
- **`package.json` `"browser"` field** remaps `./dist/secure-buffer.js` → `./dist/secure-buffer.browser.js` and stubs `sodium-native` to `false`. Works with every major bundler in 2026 (Vite, esbuild, webpack 5, Rollup, Parcel). The field was chosen over `exports` conditions because it's the only convention bundlers apply to deep package-internal imports.
- **`src/internal/runtime.ts`** with `getRandomBytes(length)` and `constantTimeEqual(a, b)` — pure-JS helpers replacing `node:crypto.randomBytes` and `node:crypto.timingSafeEqual` at the four primitive call-sites (`blob-id`, `envelope/v1`, `primitives/aead`, `primitives/commitment`). Uses `globalThis.crypto.getRandomValues` (available on Node ≥20, every modern browser, Deno ≥2, Bun ≥1, Cloudflare Workers, Vercel Edge). Throws (rather than falling back to `Math.random`) if WebCrypto is unavailable.
- `constantTimeEqual` is the XOR-accumulate pattern used by `@noble/hashes.equalBytes` and `libsodium.sodium_memcmp` — length-mismatch returns early (public-information leak only), then every byte is touched regardless of first differing index.
- **Browser bundler smoke test** (`test/bundler-smoke.test.ts`) — builds a synthetic entry that imports the full public surface via `esbuild --platform=browser`, asserts the output contains no `sodium_malloc` / `sodium_memzero` / `sodium-native` / `.node` strings and contains the browser SecureBuffer's sentinel error message (proving the browser-field swap happened). New devDep `esbuild@^0.28`.
- **`SecureBufferBrowser` unit tests** (12 new) covering ack enforcement (missing flag, truthy-non-object, `insecureMemory: false`), allocation/dispose/zeroing lifecycle, backing-storage isolation between instances, and `.from()` non-aliasing with the source `ArrayBuffer`.

### Changed — Phase III

- `src/primitives/aead.ts` now uses `getRandomBytes` from `src/internal/runtime.ts` instead of `node:crypto.randomBytes`. Doc comment updated.
- `src/primitives/commitment.ts` `verifyCommitment` uses `constantTimeEqual` instead of `node:crypto.timingSafeEqual`. Internal simplification — the length-check short-circuit is now inside `constantTimeEqual`.
- `src/envelope/v1.ts` verify-after-encrypt uses `constantTimeEqual`.
- `src/blob-id.ts` uses `getRandomBytes`.
- No external API changes. The `node:crypto` imports are gone but consumers who relied only on the public exports see no difference.

### Added — Phase IV (EnvelopeClient algorithm selection + AES-GCM hard cap)

- **`EnvelopeClient` algorithm selection.** Constructor gains an optional `algorithm?: Algorithm` option. Default remains `'XChaCha20-Poly1305'`; `'AES-256-GCM'` is available for interop with external systems. Decryption stays algorithm-agnostic — the envelope carries `enc.alg` and the client routes based on it, so a default-XChaCha client can still decrypt AES-GCM envelopes.
- **`EnvelopeClient.forAesGcmInterop(options)`** named factory. The discoverable surface for AES-GCM (design-review blocker B9): the factory name signals the trade-off at the call-site. Mid-level consumers writing first-time code see `forAesGcmInterop` in IntelliSense and can investigate the per-key message cap before committing.
- **`MessageCounter` interface** + **`InMemoryMessageCounter` default** in `src/message-counter.ts`. `async increment(keyFingerprint)` / `async current(keyFingerprint)`. The in-memory default resets on every process restart — suitable for CLI / single-process server use — and emits a one-time `console.warn` naming the limitation so multi-process / serverless consumers are prompted to supply a durable backend (SQLite, DynamoDB, Redis).
- **Key fingerprint** via `keyFingerprint(commitKey)` — HMAC-SHA256 over the commit key with a fixed `"crypto-envelope/v1/keyfp"` label, truncated to 16 bytes. Safe to persist and log (HMAC one-wayness; 128 bits output is collision-resistant for indexing).
- **`AES_GCM_HARD_CAP = 2^32`** constant + **`NonceBudgetExceeded`** error (design-review blocker B2). On every encrypt, the client increments the message counter; if the algorithm is AES-GCM and the new counter value exceeds the cap, encryption throws `NonceBudgetExceeded` with the fingerprint, counter value, and algorithm attached. Consumers are expected to rotate the master key and retry. XChaCha20-Poly1305 has no practical cap — its counter is incremented for rotation-policy observability (keyring consumes this) but no hard refusal applies.
- Keyring integration hook: `client.keyFingerprint` (getter) and `client.currentCount()` (async) expose the fingerprint and current counter so `@de-otio/keyring`'s rotation policy can watch soft/hard thresholds.

### Changed — Phase IV

- **BREAKING (pre-1.0 alpha):** `EnvelopeClient.encrypt(...)` and `EnvelopeClient.decrypt(...)` are now **async**. The counter integration surfaces `Promise<number>` for durable backends; callers update one `await`. Chaoskb's consumer changes as part of plan-01 Phase F.
- `src/envelope/v1.ts` `encryptV1` takes an optional `algorithm?: Algorithm` argument (defaulting to XChaCha20-Poly1305). `decryptV1` stays signature-stable and routes on `envelope.enc.alg`.
- Envelope-client tests rewritten for the async signature (+13 new tests covering AES-GCM via direct option and factory, cross-algorithm decrypt, hard-cap enforcement with primed counters, fingerprint stability, counter sharing).

### Notes — Phase IV

- Durable `MessageCounter` implementations are the **consumer's** responsibility; the package ships only the in-memory default. Keyring's plan §7 and design-review open-question Q5 establish the contract.
- Phase IV does not add Wycheproof-vector coverage for AES-GCM envelopes on top of what the primitive-level tests cover in Phase I — envelope-level integration relies on round-trip + tamper coverage. AES-GCM test-vector snapshots for `envelope-v1`/`v2` can land as a follow-up if a specific external system requires interop verification.


## [0.1.0-alpha.1] - 2026-04-18

First pre-release. Installs as `@de-otio/crypto-envelope@alpha`. The `@latest` tag is deliberately unused until chaoskb and trellis ship production releases against this package.

### Added — Phase A (foundation primitives)

- `canonicalJson(obj)` — RFC 8785 JSON Canonicalization Scheme. Sorted keys recursively, no whitespace, escaping per §3.2. Rejects non-finite numbers, unpaired surrogates, non-plain-object values (Date/Map/Set/class instances), and nesting above depth 128.
- `generateBlobId()` — opaque `b_`-prefixed 128-bit CSPRNG ID in fixed-width 22-char base62 encoding.
- `SecureBuffer` class + `ISecureBuffer` interface — mlock'd, auto-zeroed buffer via `sodium_malloc` / `sodium_memzero`, with `Symbol.dispose` on the class for TC39 Explicit Resource Management (`using`). The interface intentionally does not require `Symbol.dispose` so third-party implementations can opt in.
- Runtime dependency: `sodium-native@^5`.

### Added — Phase B (cryptographic primitives)

Exposed via the `./primitives` subpath:

- `aeadEncrypt(key, plaintext, aad)` / `aeadDecrypt(key, nonce, ct, tag, aad)` — XChaCha20-Poly1305 with 192-bit random nonce generated internally. `NONCE_LENGTH` and `TAG_LENGTH` are exported constants. Decrypt validates nonce width, tag width, and authentication.
- `deriveKey(ikm, info, salt?, length?)` — HKDF-SHA256. Output length bounded to RFC 5869 max (255 × 32 = 8160 bytes).
- `deriveContentKey(ikm, salt?)` / `deriveCommitKey(ikm, salt?)` — named helpers with baked-in info strings `"crypto-envelope/v1/content"` and `"crypto-envelope/v1/commit"` so callers don't accidentally collapse CEK and commitment keys into the same bytes.
- `computeCommitment(commitKey, id, rawCt)` / `verifyCommitment(...)` — HMAC-SHA256 key commitment. Verify uses `node:crypto.timingSafeEqual` with a length-check short-circuit.
- `deriveFromPassphrase(passphrase, salt)` — Argon2id at OWASP 2023 second-tier parameters (t=3, m=64 MiB, p=1, dkLen=32). Passphrase bytes and intermediate derived-key copies are zeroed in a `finally`.
- Runtime dependencies: `@noble/ciphers@^2`, `@noble/hashes@^2`.

### Test vectors

- RFC 8785 behavioural fixtures (surrogate-pair handling, control-character escapes, number edge cases, recursion guard, non-plain-object rejection).
- IETF CFRG XChaCha20-Poly1305 KAT (`draft-irtf-cfrg-xchacha` §A.3.1) via decrypt path.
- RFC 5869 Appendix A.1 HKDF-SHA256 vector.
- RFC 4231 §4.3 HMAC-SHA256 vector.
- Argon2id cross-implementation KAT against libsodium's `crypto_pwhash` (in `test/slow/` — runs only on the ubuntu Node 22 CI cell).

### Design decisions documented here

- **`deriveKeySet` dropped, named helpers added.** chaoskb's multi-key `deriveKeySet` baked in chaoskb-specific HKDF info strings (`chaoskb-content`, `chaoskb-commit`, …). The extracted package exposes generic `deriveContentKey` / `deriveCommitKey` with `crypto-envelope/v1/*` info strings. Consumers migrating from chaoskb's on-disk data will need to call `deriveKey(ikm, 'chaoskb-*', salt)` explicitly during the migration window.
- **`aeadEncryptWithNonce` not exposed publicly.** Accepting a caller-supplied nonce is a classic nonce-reuse footgun (CLAUDE.md §2). KAT verification goes through `aeadDecrypt` against published ciphertexts instead.
- **`ISecureBuffer.[Symbol.dispose]` moved off the interface** so existing chaoskb-internal implementations of the interface don't fail to type-check when chaoskb adopts this package. The concrete class still implements `Symbol.dispose`.
- **Argon2id backed by `@noble/hashes`** rather than libsodium, so the primitives layer stays portable if runtime portability becomes a goal later.
- **Node-only for v0.1.** `sodium-native` is a native addon; non-Node runtimes (Deno, Bun, browsers) aren't supported. A pluggable `SecureBufferImpl` is reserved for a future v2.

### Added — Phase C (envelope v1 — JSON wire format)

- `constructAAD(alg, id, kid, v)` — UTF-8 bytes of `canonicalJson({alg, id, kid, v})`, bound into every AEAD tag.
- `encryptV1({ payload, cek, commitKey, kid, ts?, id? })` / `decryptV1(env, cek, commitKey)` — v1 envelope produce/consume. Includes verify-after-encrypt (round-trips through decrypt before returning). Validates `ct.len`, minimum ciphertext width, algorithm, and wire-format version on decrypt. Key commitment is verified **before** AEAD, so partitioning-oracle attacks land on the commitment check rather than the AEAD decrypt path.
- `serializeV1(env)` / `deserializeV1(bytes)` — JSON wire I/O.

### Added — Phase D (envelope v2 — CBOR wire format)

- `serializeV2(env)` / `deserializeV2(bytes)` — CBOR with `"CKB"` magic prefix. ~33 % smaller than v1 JSON on typical ciphertexts.
- `deserialize(bytes)` — auto-detect (CBOR magic → v2, otherwise v1 JSON).
- `upgradeToV2(v1)` / `downgradeToV1(v2)` — lossless format conversion. Both describe the same cryptographic object; AAD is computed with `v: 1` in both cases.
- Runtime dependency: `cborg@^4`.

### Added — Phase E (high-level client)

- `EnvelopeClient` — stateful client holding HKDF-derived content and commit keys in `SecureBuffer`s. Accepts a `Uint8Array` or `ISecureBuffer` master key. Default wire format is v2; v1 opt-in. Default `kid` is `'default'`. Supports `using`-based disposal.
- `encrypt(payload)` / `decrypt(bytes)` — matches the README quickstart.

### Planned

- Phases F/G — wire chaoskb and trellis as consumers.
- Phase H — v0.1-beta release.
