# Changelog

All notable changes to `@de-otio/crypto-envelope` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase I (plan-02, AES-256-GCM primitive)

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
