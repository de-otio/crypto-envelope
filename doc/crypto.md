# Cryptographic design

This document explains why each cryptographic primitive in `@de-otio/crypto-envelope` is the one chosen, with citations to the standards and academic literature it relies on. Wire-format details are in `doc/envelope-spec.md`; this document is for verifying that the chosen primitives meet the security claims in `README.md` and `SECURITY.md`.

## 1. AEAD: XChaCha20-Poly1305 (default)

**Reference**: Arciszewski, S. (ed.), "XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305", `draft-irtf-cfrg-xchacha-03` (current as of 2026; the draft is the de-facto standard and is implemented identically by libsodium and `@noble/ciphers`).

**Construction**: HChaCha20 derives a subkey from the master key and the first 16 bytes of the 24-byte nonce; the remaining 8 bytes serve as the standard ChaCha20 nonce. ChaCha20-Poly1305 (RFC 8439) then encrypts under (subkey, 8-byte nonce). The construction extends ChaCha20-Poly1305's 96-bit nonce to 192 bits without weakening the AEAD guarantees.

**Why default**: with a 192-bit random nonce the birthday-bound collision probability after `n` random draws is ~`n² / 2^193`. For `n = 2^96` (one octillion) the probability is ~`2^-1` — i.e. random nonce reuse is **practically impossible** for any realistic message volume. This eliminates the per-key message-cap operational hazard that AES-GCM imposes (§2). The library treats this as the baseline AEAD; consumers who do not opt out get this algorithm.

**Implementation**: `src/primitives/aead.ts:113-149` via `@noble/ciphers/chacha`. Cross-checked against the KAT in `draft-irtf-cfrg-xchacha` §A.3.1 (`test/vectors/aead/`).

## 2. AEAD: AES-256-GCM (interop only)

**Reference**: NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC* (Dworkin, 2007). The original construction is McGrew-Viega, "The Galois/Counter Mode of Operation (GCM)", 2005.

**Why offered**: regulatory/interop scenarios — FIPS 140-3 environments, AWS KMS-derived keys, JOSE consumers expecting `A256GCM`. AES-GCM is the only AEAD universally accepted by these systems.

**Why not default**: NIST SP 800-38D §8.3 "Constraints on Number of Invocations" caps random-IV AES-GCM at `2^32` encryptions per key, after which the birthday collision probability on the 96-bit IV exceeds `2^-33`. A nonce collision on AES-GCM is catastrophic — it leaks the authentication-key polynomial coefficient, allowing forgery as well as a confidentiality break (Joux, "Authentication Failures in NIST version of GCM", 2006).

**How the cap is enforced**: the `EnvelopeClient` layer holds a `MessageCounter` per key fingerprint and refuses encryption past `2^32` with `NonceBudgetExceeded` (`src/envelope-client.ts:28,177-193`; the cap constant `AES_GCM_HARD_CAP = 2 ** 32` is at line 28; the per-encryption check at line 181). Consumers who use `encryptV1` directly without the client must enforce the cap themselves — this is documented in the JSDoc on `encryptV1` (`src/envelope/v1.ts:23-28`).

**Counter durability**: the default `InMemoryMessageCounter` resets on process restart, which is unsafe in serverless or multi-process topologies; a one-time `console.warn` is emitted at first use (`src/message-counter.ts:63-72`). Production multi-process consumers must supply a durable backend.

**Implementation**: `src/primitives/aead.ts:153-190` via `@noble/ciphers/aes`. Cross-checked against NIST SP 800-38D test cases 13–16 and 66 Wycheproof adversarial vectors (`test/vectors/aead/wycheproof-aes-256-gcm.json`).

## 3. Key commitment: HMAC-SHA-256

**References**:
- Len, J., Grubbs, P., Ristenpart, T., "Partitioning Oracle Attacks", *USENIX Security* 2021.
- Bellare, M., Hoang, V., "Efficient Schemes for Committing Authenticated Encryption", *EUROCRYPT* 2022.

**Threat addressed**: standard AEADs (including ChaCha20-Poly1305 and AES-GCM) are *not key-committing*. Given a ciphertext + tag, an attacker who controls keys can construct multiple keys that all decrypt successfully to different plaintexts. If a system exposes an oracle that distinguishes "decryption succeeded" from "decryption failed" — e.g. a password-based decrypt where a server tells the client "wrong password" vs "decoded successfully" — partitioning oracle attacks reduce a brute-force search on a candidate set of `N` keys to roughly `log N` queries.

**Construction**: `commitment = HMAC-SHA-256(commitKey, utf8(id) ‖ ct)` where `commitKey` is HKDF-derived with a domain-separation string distinct from the CEK's. Verified constant-time **before** AEAD decryption (`src/envelope/v1.ts:132-135`, `src/primitives/commitment.ts:25-46`).

**What this commits to**: the construction is **key-committing** (in the Len-Grubbs-Ristenpart sense): given a ciphertext + commitment + AAD, only one master key (and therefore one (CEK, commitKey) pair) successfully verifies the commitment AND decrypts the AEAD. It is **not context-committing** in the Bellare-Hoang sense — it does not bind the nonce or plaintext to the commitment independently of the AEAD. The library's threat model treats key-committing as sufficient for the partitioning-oracle defence; nonce/plaintext binding is provided by the AEAD itself.

**Why HMAC-SHA-256 and not the lighter UtC / RtC constructions**: HMAC-SHA-256 is constant-time, ubiquitous, has interoperable test vectors (RFC 4231), and has no patent or implementation hazards. The cost is one extra SHA-256 pass per envelope, which is negligible compared to the AEAD itself. Using a dedicated commitment scheme (rather than e.g. tagging a fixed plaintext byte under the AEAD as a commitment, the "ChaCha20 with all-zero canary" trick) makes the security argument explicit rather than relying on a property the AEAD does not formally guarantee.

## 4. Key derivation: HKDF-SHA-256

**Reference**: Krawczyk, H., Eronen, P., "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869.

**Why HKDF**: derives multiple cryptographically independent keys from a single high-entropy input. The `info` parameter provides domain separation, ensuring two derived keys with different infos are independent even from a master-key-knowing adversary.

**Schedule** (`src/primitives/hkdf.ts:10-12`):
- CEK: `HKDF-SHA-256(masterKey, salt=∅, info="crypto-envelope/v1/content", L=32)`
- commitKey: `HKDF-SHA-256(masterKey, salt=∅, info="crypto-envelope/v1/commit", L=32)`

The info strings are non-prefixes of one another (no domain confusion). Salt is empty — when IKM is itself uniformly random (a 32-byte master key), HKDF-Extract collapses to `HMAC(0^HashLen, IKM)`, which is sufficient.

**What HKDF does not do here**: passphrase-stretching. HKDF assumes high-entropy IKM. Passphrase-derived material goes through Argon2id or PBKDF2 (§5) first; the HKDF stage starts from the resulting 32-byte master.

**Implementation**: `src/primitives/hkdf.ts` via `@noble/hashes/hkdf`. Cross-checked against RFC 5869 Appendix A.1 (`test/vectors/kdf/`).

## 5. Passphrase KDF: Argon2id (default)

**Reference**: Biryukov, A., Dinu, D., Khovratovich, D., Josefsson, S., "Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications", RFC 9106 (2021). Argon2id is the recommended hybrid variant per RFC 9106 §4.

**Parameters** (`src/primitives/argon2.ts:12-15`):
- `t` (iterations) = `3`
- `m` (memory) = `65536` KiB = `64` MiB
- `p` (parallelism) = `1`
- `dkLen` = `32` bytes

These match the **OWASP Password Storage Cheat Sheet (2023)** "second" recommendation profile (`m=64 MiB, t=3, p=1`). The first profile (`m=46 MiB, t=1, p=1`) is also OWASP-acceptable; the library picks the second for higher work-factor headroom.

**Why memory-hard**: Argon2id's memory access pattern thwarts the GPU/ASIC parallelism advantage that PBKDF2 suffers from. A passphrase that is "weak but plausible" for a human (8–10 characters) is brute-forceable in under an hour on a $1k GPU rig under PBKDF2 but takes years under Argon2id at OWASP-recommended parameters.

**Hard-coded parameters**: callers cannot tune `t/m/p` via the public API. Silently changing parameters is a common footgun (a stored hash with weaker parameters may not be detectable to consumers); the library exposes one knob (algorithm choice) and otherwise commits to a moving target via SECURITY.md cadence.

**Implementation**: `src/primitives/argon2.ts:34-53` via `@noble/hashes/argon2`. Cross-checked against libsodium's `crypto_pwhash` in the slow test suite (`test/slow/`).

## 6. Passphrase KDF: PBKDF2-SHA-256 (compatibility only)

**References**:
- Moriarty, K. (ed.), "PKCS #5: Password-Based Cryptography Specification Version 2.1", RFC 8018 §5.2.
- OWASP Password Storage Cheat Sheet 2023.

**Why offered**: WebCrypto-constrained runtimes — restricted browser-extension policies, FIPS-constrained environments — sometimes cannot ship a WASM Argon2 implementation. PBKDF2 is in WebCrypto's mandatory subset on every browser. Without this fallback, those runtimes have no passphrase path at all.

**Iteration floor**: `1,000,000` iterations (`src/passphrase.ts:60`). This is **higher** than OWASP 2023's stated minimum of `600,000`. Justification in code comments: hardware improves ~30 %/year and the library targets PBKDF2-on-2026-hardware ≈ OWASP-2023-on-2023-hardware (design-review S1, `src/passphrase.ts:30-34`). The floor is reviewed annually per SECURITY.md cadence; a future bump is expected.

**Output**: 32 bytes (one HMAC-SHA-256 block, no chained blocks). Wider outputs are out of scope; the only consumer is the master-key brand.

**Why not the default**: PBKDF2 is not memory-hard. With dedicated GPU silicon, PBKDF2 at any iteration count is several orders of magnitude weaker than Argon2id at OWASP-recommended parameters. The library emits a one-time `console.warn` on first PBKDF2 use (`src/passphrase.ts:128-136`) so the choice is at least observable.

**Implementation**: `src/primitives/pbkdf2.ts` via `@noble/hashes/pbkdf2`. Cross-checked against RFC 7914 §11 vectors (`test/vectors/kdf/`).

## 7. Plaintext canonicalisation: RFC 8785

**Reference**: Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme (JCS)", RFC 8785.

**Why canonicalise plaintext**: encryption is byte-for-byte. Two plaintexts that are "the same JSON" but differ in key order or whitespace produce different ciphertexts and (more importantly for AAD) different bound bytes. Without canonicalisation, a serialise-encrypt-deserialise-reencrypt round-trip can produce a different envelope that decrypts to "the same" payload — silent serialisation drift.

**Why RFC 8785 specifically**: it has a written specification, multi-implementation cross-validation, and does not depend on the source language. Key sorting is alphabetic by Unicode code point; numbers use IEEE 754 ECMAScript canonical form; strings escape per JSON spec §7. Implementations exist in Java, JS, Go, Rust, Python.

**What canonicalisation cannot fix**: ill-formed UTF-16 input (lone surrogates) is rejected up front rather than silently replaced (`src/canonical-json.ts:115-127`) — without this check, two distinct malformed strings would canonicalise to the same UTF-8 (both replaced with `U+FFFD`). The strict-reject posture is a deviation from `JSON.stringify`'s permissive behaviour and is intentional.

**Implementation**: `src/canonical-json.ts`. Used for both plaintext canonicalisation (`src/envelope/v1.ts:60`) and AAD canonicalisation (`src/aad.ts:20`).

## 8. Verify-after-encrypt

**Threat addressed**: a bug in the AEAD primitive — a misconfigured cipher, a mismatched library version, an off-by-one in nonce handling — could produce a ciphertext that does not actually decrypt to the input. Without an explicit check, the library would emit such a "ciphertext" cheerfully and the bug would surface only when a consumer tried to decrypt, possibly months later.

**Construction**: every `encryptV1` call decrypts the just-produced ciphertext and constant-time-compares the result to the input plaintext bytes; a mismatch throws (`src/envelope/v1.ts:72-76`). The cost is one extra AEAD pass per encryption — acceptable for a library that processes one envelope per user action, not per packet.

This is a defence-in-depth measure, not a cryptographic primitive. The CLAUDE.md review priority is #5.

## 9. Constant-time comparisons

**Why**: comparing two byte sequences with `===`, `==`, `Buffer.compare`, or array equality short-circuits on the first mismatch. The wall-clock timing of the comparison leaks the position of the mismatch, which over many queries reveals the secret one byte at a time (Kocher, "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems", *CRYPTO* 1996; Brumley & Tuveri, "Remote Timing Attacks are Still Practical", *ESORICS* 2011).

**Construction**: pure-JS XOR-accumulate (`src/internal/runtime.ts:46-53`):

```js
let diff = 0;
for (let i = 0; i < a.length; i++) {
  diff |= a[i] ^ b[i];
}
return diff === 0;
```

Every byte position is touched regardless of mismatch position. Length mismatch returns immediately — a known leak about message length, not contents (matching Node's `crypto.timingSafeEqual` behaviour).

**Where used**: commitment verification (`src/primitives/commitment.ts:39-46`), verify-after-encrypt (`src/envelope/v1.ts:74`).

**JIT caveats**: a TurboFan/V8 JIT could in principle short-circuit the XOR loop. The pattern used (assign to `diff`, return at end) is the same as audited libraries (`@noble/hashes` `equalBytes`, libsodium `sodium_memcmp`); empirically V8 does not short-circuit it. A compiled-to-WASM constant-time implementation is in scope for v1.x if a JIT regression is ever observed.

## 10. Secure memory: `SecureBuffer`

**Reference**: libsodium's `sodium_malloc` / `sodium_memzero` / `mlock` (Bernstein et al., libsodium documentation; built on the `mlock(2)` POSIX syscall).

**Threat addressed**: keys held in plain `Uint8Array` may be:
- Swapped to disk by the OS, ending up on persistent storage that survives reboot.
- Captured in a crash dump (`/cores`, ABRT) and shipped to a vendor's bug-tracker.
- Garbage-collected to a copy elsewhere in heap before the original is zeroed.
- Inspected via DevTools (browsers).

**Node implementation** (`src/secure-buffer.ts`): `sodium_malloc` allocates `mlock`'d pages with guard pages on either side; `sodium_memzero` zeroes the bytes (compiler-fence-protected, so the zero is not optimised away). Allocation fails on hosts with restrictive `RLIMIT_MEMLOCK` (AWS Lambda, some containers); the constructor surfaces an actionable error rather than silently degrading (`src/secure-buffer.ts:36-44`).

**Browser implementation** (`src/secure-buffer.browser.ts`): browsers have no portable equivalent of `mlock`. Rather than silently provide a buffer that pretends to be memory-locked but is not, the browser variant requires `{ insecureMemory: true }` at construction. The flag is the audit-trail record of "I understand this buffer cannot mlock"; routine production use on browsers is intentional friction. Design-review Q1.

**What SecureBuffer cannot do**:
- Prevent V8 from copying the underlying storage during heap compaction. The dispose call still zeroes the post-compaction location, but a copy may have existed transiently. This is a fundamental limitation of running in a managed-memory runtime and is documented in the browser variant's JSDoc.
- Protect against an attacker with read access to the process memory (debugger attached, ptrace, /proc/[pid]/mem). At that point all bets are off.

**Class-level dispose protocol**: `[Symbol.dispose]` plus an explicit `dispose()` so consumers can use TC39 explicit-resource-management (`using sb = SecureBuffer.alloc(...)`). The interface `ISecureBuffer` does not include `[Symbol.dispose]` so third-party implementations can opt in or not.

## 11. CSPRNG sourcing

**Construction**: `globalThis.crypto.getRandomValues` — the WebCrypto API. Available on Node ≥20, every modern browser, Deno, Bun, Cloudflare Workers, Vercel Edge.

**Failure mode**: `src/internal/runtime.ts:18-35` throws on missing WebCrypto rather than falling back to `Math.random` or any other non-CSPRNG source. CLAUDE.md priority #9: no `Math.random` anywhere in src/.

**Where used**: nonce generation inside the AEAD primitive (`src/primitives/aead.ts:115,155`); blob-id generation (`src/blob-id.ts:35`).

## 12. Security parameters at a glance

| parameter                         | value                  | source            |
|-----------------------------------|------------------------|-------------------|
| Key width (CEK, commitKey)        | 256 bit                | `src/primitives/aead.ts:15` |
| XChaCha20-Poly1305 nonce          | 192 bit (random)       | `draft-irtf-cfrg-xchacha` |
| AES-256-GCM nonce                 | 96 bit (random)        | NIST SP 800-38D     |
| AEAD tag                          | 128 bit                | both algorithms     |
| Commitment output                 | 256 bit (full SHA-256) | `src/primitives/commitment.ts` |
| HKDF info: CEK                    | `crypto-envelope/v1/content` | `src/primitives/hkdf.ts:10` |
| HKDF info: commitKey              | `crypto-envelope/v1/commit`  | `src/primitives/hkdf.ts:12` |
| Argon2id parameters               | t=3, m=64 MiB, p=1, dkLen=32 | OWASP 2023 / `src/primitives/argon2.ts:12-15` |
| PBKDF2-SHA-256 iteration floor    | 1,000,000              | `src/passphrase.ts:60` |
| AES-GCM per-key message cap       | 2³² encryptions        | NIST SP 800-38D §8.3 / `src/envelope-client.ts:28` |

## 13. What this library does not provide

- **Forward secrecy / post-compromise security**: there is no ratchet. A compromised master key compromises every envelope ever produced under it. Use Signal or MLS if forward secrecy matters.
- **Identity / signature verification**: the library only authenticates data under a symmetric key. Signature schemes (Ed25519, RSA-PSS) are out of scope; use `@noble/curves` directly.
- **Replay protection**: an attacker who captures a valid envelope can re-present it later. The library does not bind a sequence number or timestamp to the AAD beyond what consumers themselves include in `id`/`kid`.
- **Censorship resistance / traffic analysis**: the wire format reveals envelope length, algorithm, and `kid`. Padding and traffic shaping are application-layer concerns.

These boundaries are intentional. See README.md "What it isn't".
