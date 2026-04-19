# @de-otio/crypto-envelope

**Opinionated authenticated-encryption envelopes for TypeScript.** Makes best-practice cryptography accessible to application developers while preventing common implementation mistakes (nonce reuse, skipped AAD, weak KDFs, silent decryption failure, …).

> **Status: pre-release (`0.1.0-alpha`).** The envelope layer is complete and internally consumed by [chaoskb](https://github.com/de-otio/chaoskb) and [trellis](https://github.com/de-otio/trellis). The `@latest` tag is reserved until both of those ship production releases on this package; install the alpha explicitly. The wire format is considered mutable between `0.x` minors until then.

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

Node 22+ required. The package pulls in `sodium-native` (for `mlock`'d secure memory), which builds prebuilt binaries on install — no extra toolchain or `playwright`-style post-install step.

## Quick start

```typescript
import { EnvelopeClient } from '@de-otio/crypto-envelope';
import { randomBytes } from 'node:crypto';

using client = new EnvelopeClient({ masterKey: randomBytes(32) });

const wire = client.encrypt({ type: 'note', body: 'hello' });
const back = client.decrypt(wire);
// → { type: 'note', body: 'hello' }
```

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

- **Nonce reuse** → 192-bit random nonces via XChaCha20-Poly1305; nonces are never user-supplied in the public API.
- **Skipped AAD / version downgrade** → AAD is mandatory and binds version + algorithm + blob ID + key identifier.
- **Multi-key / partitioning-oracle attacks** → dedicated commitment key via HKDF with its own domain-separation string; commitment HMAC binds to blob ID; verified **before** AEAD.
- **Silent serialization drift** → RFC 8785 canonical JSON for plaintext + verify-after-encrypt (every output round-trips through decrypt before release).
- **Weak KDF parameters** → Argon2id at OWASP-2023 second-tier (t=3, m=64 MiB, p=1, dkLen=32). No weaker option exposed.
- **Timing attacks** → constant-time comparisons throughout (`crypto.timingSafeEqual` in Node).
- **Keys in swap / crash dumps** → `SecureBuffer` via `sodium_malloc` / `sodium_memzero`.
- **`Math.random` for keys** → CSPRNG only; no user-callable RNG for security-sensitive values.
- **Silent decryption failure** → commitment verified before AEAD; decrypt either returns plaintext or throws.

Published test vectors cover RFC 8785 canonicalisation, RFC 5869 Appendix A.1 HKDF-SHA256, RFC 4231 §4.3 HMAC-SHA256, `draft-irtf-cfrg-xchacha` §A.3.1 XChaCha20-Poly1305 KAT (via decrypt path), and an Argon2id cross-implementation KAT against libsodium's `crypto_pwhash`.

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
