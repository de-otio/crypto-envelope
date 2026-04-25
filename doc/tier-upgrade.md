# Wire-format tiers and v1↔v2 conversion

This document explains why `@de-otio/crypto-envelope` ships two wire formats and how the conversion between them works. The corresponding code lives in `src/envelope/v2.ts:90-118` (`upgradeToV2`, `downgradeToV1`).

The short version: v1 (JSON, base64) and v2 (CBOR, raw bytes) are two encodings of the **same cryptographic object**. They round-trip losslessly. The cryptographic state — nonce, ciphertext, tag, commitment, AAD — is bit-for-bit identical between formats.

## 1. Why two formats exist

There is one set of bytes any consumer cares about cryptographically — the AEAD nonce, ciphertext, tag, and the HMAC commitment. There are at least two distinct deployment situations where those bytes need to be carried, and the optimal envelope shape differs by situation.

**v1 (JSON, base64-encoded binary)** is the human-readable storage tier. JSON is greppable, manually inspectable in any tool that exists, and embeddable in larger JSON documents (a config file, a chaoskb knowledge-base entry, a webhook payload). Base64 ciphertext has ~33 % overhead but no encoding question marks: every JSON tool ever written handles it. v1 is the format used for on-disk blobs in chaoskb and for the test vectors published with the library.

**v2 (CBOR, raw binary)** is the compact-transport tier. CBOR is the IETF binary equivalent of JSON (RFC 8949). Binary fields are byte strings rather than base64, eliminating the 33 % overhead. For a typical envelope of a 200-byte plaintext, v2 is ~140 bytes versus ~210 bytes for v1 — meaningful in network/storage-constrained environments. v2 is the default wire format produced by `EnvelopeClient.encrypt()` (`src/envelope-client.ts:134`).

Neither format is "more secure" than the other — the cryptographic object is identical. The choice is about transport ergonomics.

## 2. Layouts at a glance

Detailed layouts are in `doc/envelope-spec.md`. Side-by-side summary:

| field              | v1 representation                 | v2 representation              |
|--------------------|-----------------------------------|--------------------------------|
| `v`                | JSON number `1`                   | CBOR uint `2`                  |
| `id`               | JSON string                       | CBOR text string               |
| `ts`               | JSON string (ISO 8601)            | CBOR text string (ISO 8601)    |
| `enc.alg`          | JSON string                       | CBOR text string               |
| `enc.kid`          | JSON string                       | CBOR text string               |
| `enc.ct`           | JSON string, **base64**           | CBOR byte string (raw)         |
| `enc['ct.len']`    | JSON number                       | **omitted** (CBOR carries length) |
| `enc.commit`       | JSON string, **base64**           | CBOR byte string (raw)         |
| envelope wrapper   | JSON UTF-8 bytes                  | 3-byte `CKB` magic + CBOR map  |

The cryptographic fields (`nonce`, `ciphertext`, `tag`, `commitment`) are the **same bytes** in both formats. Only the encoding of those bytes differs.

## 3. Conversion rules

### `upgradeToV2(v1)` (`src/envelope/v2.ts:90-102`)

```
v2.v       = 2
v2.id      = v1.id                            (verbatim)
v2.ts      = v1.ts                            (verbatim)
v2.enc.alg = v1.enc.alg                       (verbatim)
v2.enc.kid = v1.enc.kid                       (verbatim)
v2.enc.ct     = base64Decode(v1.enc.ct)       (round-trip)
v2.enc.commit = base64Decode(v1.enc.commit)   (round-trip)
```

`enc['ct.len']` is dropped (CBOR carries length intrinsically).

### `downgradeToV1(v2)` (`src/envelope/v2.ts:105-118`)

```
v1.v       = 1
v1.id      = v2.id                            (verbatim)
v1.ts      = v2.ts                            (verbatim)
v1.enc.alg = v2.enc.alg                       (verbatim)
v1.enc.kid = v2.enc.kid                       (verbatim)
v1.enc.ct        = base64Encode(v2.enc.ct)
v1.enc['ct.len'] = v2.enc.ct.length
v1.enc.commit    = base64Encode(v2.enc.commit)
```

Both functions are pure — no AEAD work, no commitment recomputation, no key access. They are content-preserving re-encodings.

## 4. The `v: 1` AAD invariant

This is the single most important rule in this document, and the reason v1↔v2 conversion is safe.

The AAD bound by the AEAD at encrypt time is:

```
aad = utf8(rfc8785({ alg: <alg>, id: <id>, kid: <kid>, v: 1 }))
```

The `v` in the AAD is **always** the literal integer `1`, regardless of which wire format the envelope is later serialised into. See `src/envelope/v1.ts:61` (encrypt) and `src/envelope/v1.ts:137` (decrypt) — both pass the constant `1` to `constructAAD` (`src/aad.ts:19`).

Practical consequence: an envelope produced as v1 can be `upgradeToV2`'d, transmitted as CBOR, `downgradeToV1`'d on the receiver, and decrypted — and the AAD that the receiver reconstructs from `enc.alg`, `id`, `enc.kid`, plus the constant `1` is exactly the AAD the encrypter bound. No AEAD work is needed during conversion; the existing tag is still valid.

If the AAD bound the wire-format `v` (e.g. AAD-`v` = `1` for JSON envelopes and AAD-`v` = `2` for CBOR envelopes), upgradeToV2 would invalidate the AEAD tag and require re-encryption — which means re-running CSPRNG for a new nonce, re-running the AEAD, re-running the commitment, and (most importantly) re-running verify-after-encrypt. Conversion would no longer be a side-effect-free re-encoding; it would be an entirely separate cryptographic operation requiring access to the master key.

The library opts for the cheaper invariant: AAD pins `v: 1`, and any future wire format (msgpack v3, length-prefixed v4) would also pin `v: 1` in AAD. The cryptographic object is frozen at v1 even as the encoding evolves. See `doc/envelope-spec.md` §8 for when a true cryptographic-version bump (v3) would be required — adding fields, changing the commitment construction, etc.

## 5. The `v` field is not AAD-bound

Direct corollary: an attacker who flips the wire-format `v` field (changes `1` → `2` or vice versa) will not cause AEAD authentication to fail. Two cases:

1. **`v: 1` envelope flipped to `v: 2`**: the JSON parser refuses (CBOR magic prefix is missing) and the envelope is rejected at deserialisation. No cryptographic work runs.
2. **`v: 2` envelope flipped to `v: 1`**: same in reverse — JSON parsing of CBOR-format bytes fails immediately.

Either way, the parser routes back through the correct path (because the actual encoding cannot be tampered to look like the other format without re-encoding the whole envelope, which is a full re-construction). The `v` field is informational metadata about which decoder to use; the cryptographic identity of the envelope is determined by the `(alg, id, kid)` triple bound in AAD plus the AEAD tag.

A more ambitious attacker who re-encodes the entire envelope — say, takes the v1 base64 fields, decodes them, and emits a CBOR document with the same bytes — produces an envelope that is exactly equivalent to `upgradeToV2` of the original. They have not gained anything: the new envelope decrypts to exactly the same plaintext, under the same key, with the same AAD.

This is the desired property. Format conversion is a public, idempotent operation; it cannot be turned into an attack.

## 6. Where conversion happens in practice

- **`EnvelopeClient.encrypt()`** runs `encryptV1` and, when `format === 'v2'` (the default), calls `upgradeToV2` before serialising (`src/envelope-client.ts:185-192`).
- **`EnvelopeClient.decrypt()`** auto-detects v1 vs v2 on the magic prefix, calls `downgradeToV1` if needed, and delegates to `decryptV1` (`src/envelope-client.ts:202-207`).
- **`rewrapEnvelope`** (`src/envelope/rewrap.ts`) preserves the input version: a v1 input rewraps to v1, a v2 input rewraps to v2. Internally it routes through v1 by `downgradeToV1` → `decryptV1` → `encryptV1` → `upgradeToV2` (if originally v2). The downgrade/upgrade is a re-encoding only; the actual cryptographic re-sealing happens in `encryptV1` with new nonce/ct/tag/commitment under the new master.
- **`deserialize`** (`src/envelope/v2.ts:80-82`) is the format-agnostic parser. It checks the first three bytes for the CBOR magic and routes to `deserializeV1` or `deserializeV2`.

## 7. When you should choose which

- **Storing envelopes for grep / debugging / cross-language interop**: v1. The format is JSON — every language can read it without a CBOR library.
- **Network transmission, IndexedDB / SQLite blob columns, transferring through a `MessageChannel`**: v2. ~33 % smaller, no base64 round-trip overhead.
- **Test vectors, audit artefacts, version-control-tracked example envelopes**: v1. Diffs are readable.
- **Default, when you have no strong opinion**: v2 (the library's `EnvelopeClient` default). Compact, decryptable on every consumer of this package, and `decrypt()` auto-detects so a stored v1 still works.

There is no use-case where v1 is cryptographically preferable to v2 (or vice versa). They are interchangeable.

## 8. Forward compatibility

A future `v: 3` could be:

- A different binary encoding (msgpack, length-prefixed). AAD continues to bind `v: 1`. `upgradeToV3`/`downgradeToV1` follow the same pattern. No re-encryption needed.
- A new cryptographic object — a different commitment construction, a third AEAD, a context-committing variant per Bellare-Hoang 2022. AAD binds `v: 3`. No conversion to/from v1/v2 is possible without re-encryption (and therefore without master-key access).

The library distinguishes these two cases internally, and a `v: 3` proposal would have to declare which kind it is. Per CLAUDE.md priority #1, v1.x is restricted to the first kind; the second kind requires a major-version bump.
