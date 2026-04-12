# @de-otio/crypto-envelope

**Opinionated authenticated-encryption envelopes for TypeScript.** Makes best-practice cryptography accessible to application developers while preventing common implementation mistakes (nonce reuse, skipped AAD, weak KDFs, silent decryption failure, …).

> **Status: pre-v0.1, under construction.** This repository is being populated from [chaoskb](https://github.com/de-otio/chaoskb)'s internal crypto module. The design is specified in the [skybber analysis docs](https://github.com/de-otio/skybber/tree/main/analysis/crypto-envelope-package) (private). A v0.1 pre-release is planned once the extraction is complete and consumed internally by [chaoskb](https://github.com/de-otio/chaoskb) and [trellis](https://github.com/de-otio/trellis).

## What it is

An **envelope layer** above cryptographic primitives (`@noble/*`, libsodium) and below application protocols (Signal, TLS, JOSE). Takes a plaintext payload + a key tier, produces a versioned, authenticated envelope with defensible defaults. Reversibly.

The package is small and opinionated. It does one thing: encrypt and decrypt self-describing blobs, with tiered key management for the recovery-UX layer.

## What it isn't

- Not a primitives library — use [`@noble/*`](https://github.com/paulmillr/noble-ciphers) for that, and this package depends on it.
- Not a protocol library — use `libsignal`, `mls`, or `age` for full sessions, groups, or file encryption.
- Not a KMS wrapper — use `aws-encryption-sdk-js` if you need KMS-backed master keys.
- Not a JWT/JWE token library — use [`jose`](https://github.com/panva/jose).

## Install

```bash
npm install @de-otio/crypto-envelope
```

## Quick use (sketch — API shape, not final)

```typescript
import { EnvelopeClient } from '@de-otio/crypto-envelope';

const client = new EnvelopeClient({ masterKey }); // 32-byte Uint8Array
const blob = client.encrypt({ type: 'note', body: 'hello' });
const back = client.decrypt(blob); // → { type: 'note', body: 'hello' }
```

For tier management (SSH-wrap default; passphrase for journalist/activist tier):

```typescript
import { KeyRing } from '@de-otio/crypto-envelope';

const ring = await KeyRing.init({ tier: 'standard', sshPublicKey });
await ring.upgradeTo('maximum', { passphrase });
```

See [`doc/`](./doc/) for the full design (coming with v0.1).

## What this package protects against

Design justification for each feature is traceable to a specific class of application-level crypto mistake. Partial list (non-exhaustive, to be expanded):

- **Nonce reuse** → 192-bit random nonces via XChaCha20-Poly1305; nonce never user-controllable.
- **Skipped AAD / version downgrade** → AAD is mandatory and binds version + algorithm + blob ID.
- **Multi-key attacks** → dedicated commitment key via HKDF; commitment HMAC binds to blob ID.
- **Silent serialization drift** → RFC 8785 canonical JSON + verify-after-encrypt, both mandatory.
- **Weak KDF parameters** → Argon2id at OWASP-2023 × 3.3 memory, × 1.5 iterations. No weaker option.
- **Timing attacks** → constant-time comparisons throughout.
- **Keys in swap / crash dumps** → `SecureBuffer` via `sodium_malloc`/`sodium_memzero`.
- **Math.random() for keys** → CSPRNG only; no user-callable RNG for security-sensitive values.
- **Silent decryption failure** → commitment verified before AEAD; decrypt either returns plaintext or throws.

The full list with publicly documented real-world cases and the specific package decision that prevents each is maintained alongside the design docs.

## Maintenance posture

This is a small-organisation, primarily-internal project. Honest expectations:

- **Maintained for** [chaoskb](https://github.com/de-otio/chaoskb) and [trellis](https://github.com/de-otio/trellis) as long as those projects use it.
- **Published publicly for transparency and reference**, not as a supported product with SLAs.
- **Forking encouraged.** MIT is permissive on purpose. Wire format + test vectors are designed so a fork can remain interoperable.
- **Security issues are responded to on best-effort.** See [SECURITY.md](./SECURITY.md) for the disclosure process.

## Development

Requires Node 20+.

```bash
npm install
npm run build
npm test
npm run lint
```

## License

[MIT](./LICENSE).
