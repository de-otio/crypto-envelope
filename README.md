# @de-otio/crypto-envelope

**Opinionated authenticated-encryption envelopes for TypeScript.** Makes best-practice cryptography accessible to application developers while preventing common implementation mistakes (nonce reuse, skipped AAD, weak KDFs, silent decryption failure, …).

> **Status: pre-release (`0.2.0-alpha`).** AES-256-GCM as a second AEAD, unified passphrase-KDF with branded `MasterKey`, strict-by-default browser `SecureBuffer`, and per-key `MessageCounter` with a 2³² AES-GCM hard cap landed in this line. Internally consumed by [chaoskb](https://github.com/de-otio/chaoskb) and [trellis](https://github.com/de-otio/trellis). The `@latest` tag is reserved until both of those ship production releases; install the alpha explicitly. The wire format is considered mutable between `0.x` minors until then.

## What it is

An **envelope layer** above cryptographic primitives (`@noble/*`, libsodium) and below application protocols (Signal, TLS, JOSE). Takes a plaintext payload + a master key, produces a versioned, authenticated envelope with defensible defaults. Reversibly.

The package is small and opinionated. It does one thing: encrypt and decrypt self-describing blobs. Tiered key management (SSH-wrap, passphrase-derived recovery keys, OS-keychain integration, TOFU pinning) is a separate concern that will land as [`@de-otio/keyring`](https://github.com/de-otio/keyring) — unpublished at the time of writing.

## What it isn't

- Not a primitives library — use [`@noble/*`](https://github.com/paulmillr/noble-ciphers) for that, and this package depends on it.
- Not a protocol library — use `libsignal`, `mls`, or `age` for full sessions, groups, or file encryption.
- Not a KMS wrapper — use `aws-encryption-sdk-js` if you need KMS-backed master keys.
- Not a JWT/JWE token library — use [`jose`](https://github.com/panva/jose).
- Not a key-management framework — use `@de-otio/keyring` (forthcoming) if you want tiered SSH / passphrase unlock, recovery UX, or OS keychain integration.

## Install

```bash
npm install @de-otio/crypto-envelope@alpha
```

**Supported runtimes:** Node ≥22, modern browsers (MV3 extensions and pages), Deno ≥2, Bun ≥1, Cloudflare Workers, Vercel Edge. On Node, the package uses `sodium-native` for `mlock`'d secure memory (prebuilt binaries; no extra toolchain). On browsers and other WebCrypto-only runtimes, a strict-by-default `SecureBufferBrowser` is substituted via the `"browser"` field; constructing one requires an explicit `{ insecureMemory: true }` acknowledgement because browser runtimes cannot `mlock`.

## Quick start

```typescript
import { EnvelopeClient } from '@de-otio/crypto-envelope';

using client = new EnvelopeClient({ masterKey: crypto.getRandomValues(new Uint8Array(32)) });

const wire = await client.encrypt({ type: 'note', body: 'hello' });
const back = await client.decrypt(wire);
// → { type: 'note', body: 'hello' }
```

`encrypt` / `decrypt` are async (the per-key `MessageCounter` uses a `Promise`-returning interface so durable backends — SQLite, DynamoDB, Redis — can plug in). `wire` is a `Uint8Array` in the compact v2 (CBOR) wire format by default; opt into v1 JSON with `{ format: 'v1' }`, both round-trip losslessly.

### Passphrase unlock

```typescript
import {
  EnvelopeClient,
  deriveMasterKeyFromPassphrase,
} from '@de-otio/crypto-envelope';

const masterKey = await deriveMasterKeyFromPassphrase(
  'correct horse battery staple',
  salt, // 16+ random bytes, persisted alongside the ciphertext
  { algorithm: 'argon2id' },
);

using client = new EnvelopeClient({ masterKey });
```

Argon2id is the mandated default (OWASP 2023 second-tier: t=3, m=64 MiB, p=1). PBKDF2-SHA256 is available as a compatibility-only fallback for WebCrypto-constrained runtimes; the iteration floor is 1,000,000 and taking this branch emits a one-time warn.

### AES-256-GCM for interop

```typescript
import { EnvelopeClient } from '@de-otio/crypto-envelope';

using client = EnvelopeClient.forAesGcmInterop({ masterKey });
```

XChaCha20-Poly1305 is the default for every new envelope. Prefer `forAesGcmInterop` only when decrypting or interoperating with systems that require AES-GCM (or FIPS-constrained environments). AES-GCM carries a 2³² per-key message cap — the client refuses further encryption past this via `NonceBudgetExceeded`.

`wire` is a `Uint8Array` in the compact v2 (CBOR) wire format by default. Opt into v1 JSON with `{ format: 'v1' }`; both round-trip losslessly via `upgradeToV2` / `downgradeToV1`, and `decrypt()` auto-detects.

For finer control, the low-level functions are exported too:

```typescript
import {
  encryptV1,
  decryptV1,
  deriveContentKey,
  deriveCommitKey,
} from '@de-otio/crypto-envelope';

const cek = deriveContentKey(masterKey);
const commitKey = deriveCommitKey(masterKey);
const envelope = encryptV1({ payload: { x: 1 }, cek, commitKey, kid: 'default' });
const recovered = decryptV1(envelope, cek, commitKey);
```

## What this package protects against

Design justification for each feature traces back to a specific class of application-level crypto mistake:

- **Nonce reuse** → 192-bit random nonces via XChaCha20-Poly1305 (default). AES-256-GCM's 96-bit nonce is available for interop with a hard 2³² per-key message cap enforced at `EnvelopeClient` — cross-process counter state is pluggable via `MessageCounter`. Nonces are never user-supplied in the public API.
- **Skipped AAD / version downgrade** → AAD is mandatory and binds version + algorithm + blob ID + key identifier.
- **Algorithm substitution** → `alg` bound into AAD; nonce-width check rejects cross-algorithm ciphertext at the primitive.
- **Multi-key / partitioning-oracle attacks** → dedicated commitment key via HKDF with its own domain-separation string; commitment HMAC binds to blob ID; verified **before** AEAD (key-committing, not context-committing — see SECURITY.md).
- **Silent serialization drift** → RFC 8785 canonical JSON for plaintext + verify-after-encrypt (every output round-trips through decrypt before release).
- **Weak KDF parameters** → Argon2id at OWASP-2023 second-tier (t=3, m=64 MiB, p=1, dkLen=32) as the mandated default. PBKDF2-SHA256 available for WebCrypto-only runtimes with a 1,000,000 iteration floor and a first-use warning.
- **Key confusion** → `MasterKey` branded type prevents passphrase-derived bytes from being handed to an AEAD primitive as a CEK without an explicit unbranding cast.
- **Timing attacks** → constant-time comparisons throughout (pure-JS XOR-accumulate; portable across runtimes).
- **Keys in swap / crash dumps** → `SecureBuffer` via `sodium_malloc` / `sodium_memzero` on Node. Browsers and other mlock-less runtimes get a **strict-by-default** `SecureBufferBrowser` requiring `{ insecureMemory: true }` at construction — no silent degradation.
- **`Math.random` for keys** → `globalThis.crypto.getRandomValues` only; no user-callable RNG for security-sensitive values. Throws on missing WebCrypto rather than falling back.
- **Silent decryption failure** → commitment verified before AEAD; decrypt either returns plaintext or throws.

Published test vectors cover RFC 8785 canonicalisation, RFC 5869 Appendix A.1 HKDF-SHA256, RFC 4231 §4.3 HMAC-SHA256, `draft-irtf-cfrg-xchacha` §A.3.1 XChaCha20-Poly1305 KAT, an Argon2id cross-implementation KAT against libsodium's `crypto_pwhash`, RFC 7914 §11 PBKDF2-SHA256 vectors, NIST SP 800-38D / McGrew-Viega AES-256-GCM test cases 13–16, and 66 Wycheproof adversarial AES-256-GCM vectors (keySize=256 / ivSize=96 / tagSize=128).

## Maintenance posture

This is a small-organisation, primarily-internal project. Honest expectations:

- **Maintained for** [chaoskb](https://github.com/de-otio/chaoskb) and [trellis](https://github.com/de-otio/trellis) as long as those projects use it.
- **Published publicly for transparency and reference**, not as a supported product with SLAs.
- **Forking encouraged.** MIT is permissive on purpose. Wire format + test vectors are designed so a fork can remain interoperable.
- **Security issues are responded to on best-effort.** See [SECURITY.md](./SECURITY.md) for the disclosure process.

## Development

Requires Node 22+.

```bash
npm install
npm run build
npm test           # fast suite (~400 ms)
npm run test:slow  # Argon2id cross-implementation KAT (~15 s)
npm run lint
```

## License

[MIT](./LICENSE).
