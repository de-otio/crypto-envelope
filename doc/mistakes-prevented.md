# Mistakes prevented

This document is the negative-space companion to `doc/crypto.md`. For each common application-level cryptography mistake, it names the mistake class, the published-literature attack that demonstrates the consequence (where one exists), and the specific code path in `@de-otio/crypto-envelope` that prevents it.

The README's "What this package protects against" bullet list is the starting point; this document expands each bullet to the source line that enforces it.

## 1. Nonce reuse under a single key

**Class**: nonce reuse / IV collision.

**Consequence**: for ChaCha20-Poly1305 and AES-GCM, two messages encrypted with the same `(key, nonce)` produce two ciphertexts whose XOR is the XOR of the plaintexts (full confidentiality break). For AES-GCM specifically, a nonce collision additionally leaks the GHASH authentication subkey, allowing forgery (Joux, "Authentication Failures in NIST version of GCM", 2006).

**How prevented**:

- The public AEAD API has no nonce parameter. `aeadEncrypt` (`src/primitives/aead.ts:63-79`) always generates a fresh nonce internally via `getRandomBytes` (`src/internal/runtime.ts:18-35`).
- XChaCha20-Poly1305 is the default; with a 192-bit random nonce the birthday bound on collision is `2^96` messages — practically unbounded.
- AES-256-GCM has a 96-bit nonce; the per-key collision probability passes 2^-33 at 2^32 messages (NIST SP 800-38D §8.3). The `EnvelopeClient` enforces a hard cap of `2^32` encryptions per key (`src/envelope-client.ts:28,177-193`) and refuses further encryption with `NonceBudgetExceeded`.
- The cap is enforced via a pluggable `MessageCounter` (`src/message-counter.ts`); durable backends (SQLite, DynamoDB, Redis) are required for multi-process topologies. The default `InMemoryMessageCounter` emits a one-time warning (`src/message-counter.ts:63-72`) so accidental serverless use is at least visible.

## 2. Skipped or forged AAD

**Class**: associated-data omission / parameter substitution.

**Consequence**: an AEAD ciphertext encrypted without binding metadata can be replayed in a different context (different `kid`, different `id`, different algorithm-claim). The decryption succeeds and the consumer believes the metadata.

**How prevented**:

- AAD construction is mandatory. There is no encryption code path that omits AAD: `encryptV1` (`src/envelope/v1.ts:54-90`) always calls `constructAAD` (`src/aad.ts:19-21`).
- AAD is the RFC 8785 canonical JSON of `{alg, id, kid, v: 1}`. All four fields are bound by the AEAD tag; tampering any one of them at decrypt time causes AEAD authentication to fail (the tag is computed against AAD).
- AAD canonicalisation goes through `canonicalJson` (`src/canonical-json.ts`) — sorted-key, no-whitespace, deterministic. A non-canonical JSON parser cannot produce a different AAD by accident.

## 3. Version downgrade

**Class**: protocol-version downgrade.

**Consequence** (where applicable): an attacker who can flip the version field steers the decoder into a weaker code path. Classic in TLS (FREAK, POODLE).

**How addressed in this library**:

- The `v` field on the wire is **not** AAD-bound (see `doc/tier-upgrade.md` §5). However, this is not a downgrade vector in the classical sense, because v1 (JSON) and v2 (CBOR) describe the same cryptographic object. Flipping `v` cannot steer the decoder into a weaker AEAD or a missing-commitment path; it only chooses which encoding parser runs.
- A future v3 that introduces a *cryptographically* different object would require the AAD to bind a separate `aad_v` distinct from the wire-format `v`, exactly to defeat downgrade. The current library has no such hazard because there is only one cryptographic version.
- The `enc.alg` field IS AAD-bound, so an attacker cannot make a decoder accept an XChaCha20-Poly1305 ciphertext as AES-GCM or vice versa (see §4).

## 4. Algorithm substitution

**Class**: ciphertext type-confusion.

**Consequence**: presenting a ciphertext encrypted under one algorithm as if it were a different algorithm. With matching key bytes, some primitives produce a "valid" decryption that is in fact garbage.

**How prevented**:

- `enc.alg` is bound into the AAD (`src/aad.ts:19-21`). Tampering with the algorithm field alone causes AEAD authentication to fail before any plaintext is released.
- The nonce-width check at the primitive layer (`src/primitives/aead.ts:134-138, 177-179`) defensively rejects mismatched nonce widths — a ciphertext produced with XChaCha (24-byte nonce) cannot be presented as AES-GCM (12-byte nonce) without tripping this check, even before AAD verification.
- Algorithm-identifier parsing rejects unknown values up front (`src/envelope/v1.ts:115-117`).

## 5. Partitioning oracle attack

**Class**: multi-key key-search via decrypt-success oracle.

**Reference**: Len, J., Grubbs, P., Ristenpart, T., "Partitioning Oracle Attacks", *USENIX Security* 2021. Bellare, M., Hoang, V., "Efficient Schemes for Committing Authenticated Encryption", *EUROCRYPT* 2022.

**Consequence**: standard AEADs are not key-committing — given a ciphertext + tag, an attacker can construct multiple keys that all "decrypt successfully" to different plaintexts. A system that exposes "decryption succeeded vs. failed" as an oracle (most password-derived crypto does, by virtue of telling the user "wrong password" vs "decoded successfully") becomes vulnerable to a `log N` brute-force on candidate-key sets.

**How prevented**:

- A separate HMAC-SHA-256 commitment is computed over `utf8(id) ‖ ct` under a dedicated `commitKey` (`src/primitives/commitment.ts:25-31`).
- The commitKey is HKDF-derived with a domain-separation string distinct from the CEK's (`src/primitives/hkdf.ts:10-12`) — `crypto-envelope/v1/content` for CEK, `crypto-envelope/v1/commit` for commitKey. The two outputs are cryptographically independent.
- Commitment verification runs **before** AEAD decryption (`src/envelope/v1.ts:132-135`), so an oracle distinguishing "decryption succeeded" from "wrong key" is bound to the commitment-verify check, which is keyed by a high-entropy commitKey rather than a low-entropy passphrase-derived candidate.
- Verification is constant-time (`src/internal/runtime.ts:46-53`).

The construction is **key-committing**, not context-committing per Bellare-Hoang 2022 (it does not bind nonce or plaintext to the commitment independently of the AEAD). The library's threat model treats key-committing as sufficient; see SECURITY.md.

## 6. Silent serialisation drift

**Class**: serialise / deserialise / re-serialise asymmetry.

**Consequence**: encrypting `JSON.stringify(payload)` directly is hazardous because two semantically-equal payloads can produce different byte sequences (different key order, whitespace, number formatting). A round-trip through a non-canonical parser produces a different envelope that "decrypts to the same payload" — silent drift that can break audit logging, test-vector cross-validation, or any system that relies on byte-equal ciphertext for byte-equal input.

**How prevented**:

- Plaintext is canonicalised per RFC 8785 (`src/canonical-json.ts`) before encryption (`src/envelope/v1.ts:60`).
- AAD is canonicalised via the same routine (`src/aad.ts:20`).
- Verify-after-encrypt (`src/envelope/v1.ts:72-76`) provides a defence-in-depth check: every envelope is re-decrypted before release and compared byte-for-byte to the input, catching any drift between encrypt and the AEAD primitive.
- Ill-formed UTF-16 input (lone surrogates) is rejected up front (`src/canonical-json.ts:115-127`) rather than silently replaced with `U+FFFD` — without this check, two distinct malformed strings would canonicalise to the same UTF-8.

## 7. Weak passphrase KDF

**Class**: low work-factor / GPU-amenable password hashing.

**Consequence**: PBKDF2 at low iteration counts is brute-forceable on commodity GPUs. A weak-but-plausible 8–10-character passphrase under PBKDF2-100k is recoverable in under an hour at 2025 GPU costs.

**How prevented**:

- Argon2id is the mandated default (`src/passphrase.ts:81-86`). Parameters are OWASP 2023 second-tier (`t=3, m=64 MiB, p=1`, `src/primitives/argon2.ts:12-15`). Memory-hard design defeats GPU/ASIC parallelism.
- PBKDF2-SHA-256 is available as a compatibility-only fallback (WebCrypto-constrained runtimes). The iteration floor is `1,000,000` (`src/passphrase.ts:60`), higher than OWASP 2023's `600,000` minimum to budget for ~2 years of hardware improvement.
- Taking the PBKDF2 branch emits a one-time `console.warn` per process (`src/passphrase.ts:128-136`) so the choice is observable in logs.
- KDF parameters are hard-coded; callers cannot silently weaken them via the public API.

## 8. Key confusion (CEK ↔ commitKey ↔ MasterKey)

**Class**: key reuse across cryptographic roles.

**Consequence**: using the same key for both encryption and MAC, or for both content encryption and key commitment, breaks the security argument of the commitment scheme. A passphrase-derived 32-byte master used directly as an AEAD key bypasses HKDF's domain separation entirely.

**How prevented**:

- HKDF derives CEK and commitKey with distinct info strings (`src/primitives/hkdf.ts:10-12`); the resulting keys are cryptographically independent.
- The `MasterKey` branded type (`src/types.ts:100`) prevents passphrase-derived bytes from being passed directly to an AEAD primitive as a CEK without an explicit unbranding cast. The brand exists only in the type system; runtime is `ISecureBuffer`. Design-review B8.
- `EnvelopeClient` derives CEK and commitKey internally from the master and never exposes either to the caller (`src/envelope-client.ts:122-131`).
- `asMasterKey` (`src/passphrase.ts:121-126`) is the only path to brand a buffer as a `MasterKey` and includes an explicit length check (32 bytes, throws otherwise).

## 9. Timing attack on secret comparisons

**Class**: data-dependent timing of secret-vs-secret comparison.

**Reference**: Kocher, "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems", *CRYPTO* 1996. Brumley & Tuveri, "Remote Timing Attacks are Still Practical", *ESORICS* 2011.

**Consequence**: comparing a candidate MAC/tag/commitment to the expected value with `===`, `Buffer.compare`, or array equality short-circuits on the first mismatching byte. Wall-clock timing of repeated queries leaks the secret a byte at a time.

**How prevented**:

- All comparisons of secret material go through `constantTimeEqual` (`src/internal/runtime.ts:46-53`). XOR-accumulate over every byte regardless of mismatch position.
- Used in: commitment verification (`src/primitives/commitment.ts:39-46`); verify-after-encrypt plaintext compare (`src/envelope/v1.ts:74`).
- AEAD tag verification is delegated to `@noble/ciphers`, which performs constant-time tag comparison internally.
- Length mismatch returns immediately — a known leak about message length (matching `node:crypto.timingSafeEqual` behaviour) but not contents. Plaintext lengths are also visible on the wire (`enc.ct` length), so this leak is already public.

## 10. Keys leaked via swap or crash dumps

**Class**: long-lived plaintext key material in pageable memory.

**Consequence**: keys held in a plain `Uint8Array` may be swapped to disk by the OS, captured in a coredump, or left in heap regions reachable through DevTools / debuggers / `/proc/[pid]/mem`.

**How prevented**:

- `SecureBuffer` (`src/secure-buffer.ts`) backs key material with `sodium_malloc` (mlock'd pages, guard pages either side) and `sodium_memzero` on dispose. Keys are zeroed on `dispose()` and the constructor surfaces an actionable error if mlock is unavailable (e.g. AWS Lambda's `RLIMIT_MEMLOCK = 0`) rather than silently degrading.
- The browser variant `SecureBufferBrowser` (`src/secure-buffer.browser.ts`) is **strict-by-default**: construction requires `{ insecureMemory: true }` because browsers have no portable mlock. The flag is the audit-trail acknowledgement; routine production use is deliberately frictionful (design-review Q1, README "Supported runtimes").
- `EnvelopeClient` holds CEK and commitKey in `SecureBuffer`s for its lifetime and disposes them on `dispose()` (`src/envelope-client.ts:107-113,210-217`), with `[Symbol.dispose]` so `using client = new EnvelopeClient(...)` zeroes on scope exit.
- `rewrapEnvelope` zeroes its transient key copies in a `finally` block (`src/envelope/rewrap.ts:119-128`).
- `deriveFromPassphrase` zeroes the passphrase bytes and the intermediate Argon2 output regardless of return path (`src/primitives/argon2.ts:46-52`).

What `SecureBuffer` cannot do: prevent V8 from copying the underlying storage during heap compaction. The dispose call still zeroes the post-compaction location, but a transient copy may have existed. This limitation is documented inline.

## 11. `Math.random` for key/nonce generation

**Class**: non-CSPRNG entropy.

**Consequence**: `Math.random` is not cryptographically secure. Predicting subsequent outputs from a few observed values is feasible.

**How prevented**:

- `Math.random` does not appear anywhere in `src/`. CLAUDE.md priority #9 enforces this; lint and review treat any `Math.random` introduction as a critical blocker.
- All random bytes come from `getRandomBytes` (`src/internal/runtime.ts:18-35`), which calls `globalThis.crypto.getRandomValues`.
- On a runtime without WebCrypto, `getRandomBytes` **throws** rather than falling back to a weaker source.
- Nonces are generated inside the AEAD primitive (`src/primitives/aead.ts:115,155`); blob IDs in `src/blob-id.ts:35`.

## 12. Silent decryption failure / attacker-controlled garbage

**Class**: fail-open decrypt path.

**Consequence**: a decrypt API that returns `undefined`/`null`/`Result<None>` on failure tempts callers to `?? defaultValue` or otherwise ignore the failure, releasing attacker-controlled garbage as plaintext. A worse variant returns the raw ciphertext-XOR-keystream bytes on tag failure.

**How prevented**:

- `decryptV1` (`src/envelope/v1.ts:107-145`) **throws** on any failure: unknown version, unknown algorithm, truncated ciphertext, ct.len mismatch, commitment failure, AEAD-tag failure. There is no return-undefined path.
- The error messages name the likely cause (`"unsupported envelope version"`, `"truncated ciphertext"`, `"key commitment verification failed"`, etc.) so a caller can discriminate without resorting to string-matching.
- AEAD tag verification is performed by `@noble/ciphers`, which throws on failure rather than returning a short / poisoned plaintext.
- Verify-after-encrypt (`src/envelope/v1.ts:72-76`) blocks any encrypt that would produce a ciphertext failing to round-trip.

## 13. AAD that the caller forgot to provide

**Class**: API ergonomics that allow skipping a security check.

**How prevented**:

- The library has no AEAD primitive that encrypts without AAD. `aeadEncrypt`/`aeadDecrypt` (`src/primitives/aead.ts:63-109`) require an AAD argument; passing an empty AAD is allowed by the type but the envelope-layer encrypt always supplies a non-empty AAD computed from the envelope metadata.
- The envelope-layer encrypt API does not expose an AAD parameter at all (`src/envelope/v1.ts:13-34`); AAD is constructed internally from the canonical envelope fields. A caller cannot forget AAD because they cannot supply it.

## 14. Bypassing canonicalisation

**Class**: serialisation that produces different byte sequences for equivalent inputs.

**How prevented**:

- The encrypt API takes a `Record<string, unknown>` (a JSON object), not a string or a `Uint8Array`. The caller cannot supply pre-serialised bytes; canonicalisation is the only way in.
- `canonicalJson` (`src/canonical-json.ts:15-19`) rejects non-plain-object top-level values up front. Top-level arrays and primitives are not envelope-encryptable.
- `canonicalJson` rejects custom-prototype objects (`src/canonical-json.ts:45-49`) — only `Object.prototype` allowed. Catches accidental Map / Set / class-instance arguments before they silently serialise to `{}`.

## 15. Public-API parameter footguns

**Class**: API shapes that expose internals tuneable to insecure values.

**How prevented**:

- No nonce parameter in encryption (CLAUDE.md priority #2).
- No knob to disable commitment, AAD, or verify-after-encrypt.
- KDF parameters are hard-coded: Argon2id at OWASP-2023 (`src/primitives/argon2.ts:12-15`); PBKDF2 has a floor (`src/passphrase.ts:60`) but is otherwise caller-supplied (the only knob).
- The default wire format is v2 (compact); the only switch is between v1 and v2, which are cryptographically equivalent.
- AES-256-GCM is opt-in via `forAesGcmInterop` (`src/envelope-client.ts:148-150`); the named factory is the discoverable warning that AES-GCM carries a per-key cap.

## 16. Caching plaintexts for performance

**Class**: lifetime expansion of secrets.

**How prevented**:

- The library does not cache. There is no plaintext cache, no decrypted-envelope LRU. Each `decrypt` call performs a full re-decryption.
- This is a documented design choice (CLAUDE.md "Things to push back on, even if they seem reasonable"). PRs adding plaintext caching should be rejected absent a strong justification.

## 17. Network egress from a crypto library

**Class**: surprising side effects.

**How prevented**:

- The library does not use `fetch`, `http`, `https`, or any networking API. Everything is in-process.
- Adding a network call would be a CLAUDE.md priority #10 blocker.

## Cross-reference

| README bullet                                | Section here | Primary code path                                  |
|----------------------------------------------|--------------|----------------------------------------------------|
| Nonce reuse                                  | §1           | `src/primitives/aead.ts`, `src/envelope-client.ts` |
| Skipped AAD / version downgrade              | §2, §3       | `src/aad.ts`, `src/envelope/v1.ts:61,137`          |
| Algorithm substitution                       | §4           | `src/aad.ts`, `src/primitives/aead.ts:134,177`     |
| Multi-key / partitioning-oracle              | §5           | `src/primitives/commitment.ts`                     |
| Silent serialization drift                   | §6           | `src/canonical-json.ts`, `src/envelope/v1.ts:72-76` |
| Weak KDF parameters                          | §7           | `src/primitives/argon2.ts`, `src/passphrase.ts:60` |
| Key confusion                                | §8           | `src/primitives/hkdf.ts`, `src/types.ts:100`       |
| Timing attacks                               | §9           | `src/internal/runtime.ts:46-53`                    |
| Keys in swap / crash dumps                   | §10          | `src/secure-buffer.ts`, `src/secure-buffer.browser.ts` |
| `Math.random` for keys                       | §11          | `src/internal/runtime.ts:18-35`                    |
| Silent decryption failure                    | §12          | `src/envelope/v1.ts:107-145`                       |
