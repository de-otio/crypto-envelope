# CLAUDE.md

Guidance for Claude (and other AI coding agents) working in this repository.

## What this project is

`@de-otio/crypto-envelope` — a TypeScript library that produces and verifies authenticated-encryption envelopes. Opinionated defaults, safe-by-construction API, published test vectors. Serves internal de-otio projects (chaoskb, trellis) as its primary purpose; public for transparency and reference.

**This is a cryptographic library. Treat every change as high-stakes.** A bug here translates directly to data loss or confidentiality breach in every downstream consumer.

## Review priorities (in order)

When reviewing a diff, check in this order:

1. **Wire-format stability.** Any change that alters the bytes written by `encrypt()` is a breaking change within v1.x. If the PR is not explicitly a v2 proposal, this kind of change must be rejected.
2. **Nonce handling.** Nonces must always come from `crypto.getRandomValues` / `crypto.randomBytes`. No `Math.random`, no deterministic counters, no user-supplied nonces in the public API. 192-bit nonces for XChaCha20-Poly1305.
3. **AEAD + AAD binding.** AAD must bind `v`, `id`, `alg`, `kid` as RFC 8785 canonical JSON. No code path may encrypt without AAD. No code path may accept a tampered AAD at decrypt.
4. **Key separation.** The commitment key must be derived via HKDF with its own context string (`"chaoskb-commit"` or successor). The encryption key and commitment key must never be the same value, and the API must not allow confusion between them.
5. **Verify-after-encrypt.** Every encryption path must round-trip through decrypt-and-compare before releasing plaintext. No exceptions.
6. **Constant-time comparisons.** Any comparison of secret material (keys, tags, MACs, canary plaintexts) must go through `crypto.timingSafeEqual` or equivalent. `==`, `===`, array equality, and `Buffer.compare` are all non-constant-time and are wrong for secrets.
7. **Secure memory.** Keys held in memory use `SecureBuffer`, which calls `sodium_malloc` / `sodium_memzero` via libsodium or the platform equivalent. Keys are zeroed on drop. Plain `Uint8Array` is not acceptable for long-lived key material.
8. **Canonical JSON.** Plaintext is canonicalised per RFC 8785 before encryption. Any bypass of canonicalisation is a bug.
9. **CSPRNG only.** All random values come from platform CSPRNGs. No `Math.random` anywhere in the source, ever.
10. **No external fetches.** The library does not make network requests. If a PR adds `fetch`, `http`, or similar, it must be justified and almost certainly rejected.

## Review output expectations

Post inline comments on specific lines. For each issue:

- State what the issue is, in plain terms.
- Name the mistake class it falls under (nonce reuse, AAD skip, key confusion, etc.).
- Cite the review priority number above.
- Suggest the fix concretely.

For subtle crypto issues, include a link to the academic reference or CVE where relevant. Do not speculate about attack scenarios that are not documented in public literature.

## Things to push back on, even if they seem reasonable

- **Caching decrypted plaintexts.** Tempting for performance; expands the attack surface. Reject without a very strong rationale.
- **Adding dependencies.** Runtime dependency graph must stay small. `@noble/*` is an acceptable foundation; most other additions are not.
- **"Convenience" APIs that allow skipping safety checks.** An API that takes a nonce as a parameter, disables commitment, or returns undefined on decrypt failure is a footgun. Reject.
- **Non-RFC-8785 JSON serialisation.** Every serialisation format will be "equivalent" in some tests and subtly different in others. The library commits to RFC 8785 specifically.

## Things to encourage

- **More tests.** Especially tests covering edge cases, failure paths, and round-trip invariants.
- **More test vectors.** Every algorithm/kid combination and meaningful edge case should have a vector in `test/vectors/`.
- **Clearer error messages.** A `DecryptionFailure` thrown without context is harder to debug than one that names the likely cause (`"wrong key"`, `"tampered envelope"`, `"unsupported algorithm"`, etc.).
- **Documentation that cites sources.** Cryptographic choices must be justified with public references.

## Scope boundary

Things the library is *not*:

- A protocol library (no Signal ratchet, no MLS, no handshake state machine)
- A key escrow service
- A KMS wrapper
- A file encryption tool (use `age`)
- A JWT/JWE library (use `jose`)

PRs that push the library into these spaces should be redirected to existing libraries that already solve those problems well.

## Severity classification

When posting review comments, use this severity scale:

- **Critical** — a cryptographic weakness that breaks confidentiality, integrity, or authenticity claims. RCE, auth bypass, key leakage, nonce reuse, silent decryption failure returning attacker-controlled garbage. **Blocks merge.**
- **High** — a bug that could become critical under realistic conditions, or that weakens a documented threat-model claim without fully breaking it. Missing AAD, weak KDF parameters, non-constant-time comparison of secrets, ciphertext substitution possible. **Blocks merge.**
- **Medium** — hardening issues, unclear error messages that obscure security-relevant failures, inconsistent application of an invariant, missing test vectors for a new code path. **Should fix before merge.**
- **Low** — best-practice nits, doc clarifications, suggestions that would improve the codebase but are not defects. **Informational.**

## When in doubt

Say you're not sure. Do not guess at cryptographic properties. A clear "I don't know if this is safe" from an AI reviewer is much more useful than a confident incorrect assessment.
