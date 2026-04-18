# Changelog

All notable changes to `@de-otio/crypto-envelope` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Planned

- Phases C/D — envelope v1 (JSON) and v2 (CBOR) wire formats.
- Phase E — high-level `EnvelopeClient`.
- Phases F/G — wire chaoskb and trellis as consumers.
- Phase H — v0.1-beta release.
