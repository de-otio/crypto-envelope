# Envelope wire-format specification

This document specifies the byte layout of `@de-otio/crypto-envelope` envelopes precisely enough that a third-party implementer can produce envelopes interoperable with the reference implementation, and verify cryptographic claims against the source. It applies to library version `0.2.0-alpha` and the eventual `1.x` line — the wire format will not change between alpha and v1.0 except where explicitly called out.

The library defines two wire formats. v1 is JSON; v2 is CBOR. Both encode the **same cryptographic object** (the AAD, ciphertext, tag, and commitment bytes are identical); v1↔v2 conversion is a pure re-encoding. See `doc/tier-upgrade.md` for the conversion rules and the `v: 1` AAD invariant.

The canonical types are defined in `src/types.ts:54-82`.

## 1. Field semantics

Every envelope, regardless of wire format, conveys the following fields. Names below are the names used on the wire; type column is the abstract domain.

| field         | type           | semantics                                                               |
|---------------|----------------|-------------------------------------------------------------------------|
| `v`           | integer        | wire-format version: `1` = JSON, `2` = CBOR. **Not AAD-bound.**         |
| `id`          | string         | opaque blob identifier (typically `b_` + 22-char base62; `src/blob-id.ts:34-37`) |
| `ts`          | string         | ISO 8601 timestamp set at encrypt time                                  |
| `enc.alg`     | string         | AEAD algorithm: `"XChaCha20-Poly1305"` or `"AES-256-GCM"`               |
| `enc.kid`     | string         | opaque key identifier chosen by the caller; bound into AAD              |
| `enc.ct`      | bytes          | concatenation of `nonce ‖ ciphertext ‖ tag` (see §3)                    |
| `enc.commit`  | bytes (32)     | HMAC-SHA-256 key-commitment tag (see §4)                                |
| `enc['ct.len']` | integer (v1 only) | byte length of decoded `ct`; defensively validated on decrypt        |

The `enc.ct` field is a **single binary blob** — a fresh AEAD nonce, the AEAD ciphertext, and the AEAD tag concatenated in that order. Implementers must not invent separate `nonce` / `tag` fields; the layout is fixed.

### 1.1 Algorithm identifiers and nonce widths

Allowed values for `enc.alg` (`src/types.ts:37`, `src/primitives/aead.ts:9-15`):

| identifier             | nonce width | tag width | key width | reference                                  |
|------------------------|-------------|-----------|-----------|--------------------------------------------|
| `XChaCha20-Poly1305`   | 24 B (192 bit) | 16 B   | 32 B      | `draft-irtf-cfrg-xchacha`                  |
| `AES-256-GCM`          | 12 B (96 bit)  | 16 B   | 32 B      | NIST SP 800-38D                            |

Decoders must reject any other value (see `src/envelope/v1.ts:115`).

## 2. v1 wire format (JSON)

A v1 envelope is a UTF-8 JSON document conforming to the type:

```json
{
  "v": 1,
  "id": "b_0000000000000000000abc",
  "ts": "2026-04-25T12:00:00.000Z",
  "enc": {
    "alg": "XChaCha20-Poly1305",
    "kid": "default",
    "ct": "<base64>",
    "ct.len": <integer>,
    "commit": "<base64>"
  }
}
```

Encoding rules:

- `enc.ct` and `enc.commit` are standard base64 (`+/=`, padded). Implementations MAY accept base64url on input but MUST emit standard base64. The reference encodes via `Buffer.from(...).toString('base64')` (`src/envelope/v1.ts:85,87`).
- `enc['ct.len']` is the byte length of the **decoded** `ct` (i.e. `nonce.length + ciphertext.length + tag.length`). Decoders MUST validate it against the actual decoded length and reject on mismatch (`src/envelope/v1.ts:126-130`).
- The on-the-wire JSON document is **not** required to be RFC 8785 canonical. JSON canonicalisation is used internally only for AAD construction (§5).
- Field ordering on the wire is unspecified; decoders must accept any order.

Decoders must enforce the minimum decoded length `nonceWidth + 16` (`src/envelope/v1.ts:122-125`); shorter `ct` is rejected before AEAD verify.

### 2.1 Worked example

Plaintext payload:

```json
{"hello":"world"}
```

A representative v1 envelope (random fields elided to `…`):

```json
{
  "v": 1,
  "id": "b_4z9Lq2mQ7pK1rN3vX8wYbA",
  "ts": "2026-04-25T15:30:00.000Z",
  "enc": {
    "alg": "XChaCha20-Poly1305",
    "kid": "default",
    "ct": "vQ4j…U7w==",
    "ct.len": 57,
    "commit": "Yh2P…aF8="
  }
}
```

Decoded `ct` of length 57 unpacks as `nonce[0..24)` ‖ `ciphertext[24..41)` ‖ `tag[41..57)`. The 17-byte ciphertext has the same length as the 17-byte canonicalised plaintext (`{"hello":"world"}`). XChaCha20 is a stream cipher, so ciphertext length always equals plaintext length.

For machine-checkable test vectors covering RFC 5869 HKDF, RFC 4231 HMAC, the XChaCha20-Poly1305 KAT in `draft-irtf-cfrg-xchacha` §A.3.1, and Wycheproof AES-256-GCM cases, see `test/vectors/`.

## 3. Ciphertext blob layout

The `enc.ct` byte string in both v1 and v2 has the layout (`src/envelope/v1.ts:65-68`):

```
+--------+-------------+-------+
| nonce  | ciphertext  |  tag  |
+--------+-------------+-------+
  N bytes   M bytes      16 B
```

- `N` is `24` for XChaCha20-Poly1305, `12` for AES-256-GCM.
- `M` equals the plaintext length (both AEADs are stream/CTR-mode under the hood).
- Total decoded length is `N + M + 16`.

The nonce is fresh CSPRNG output — `globalThis.crypto.getRandomValues` via `src/internal/runtime.ts:18-35`, called inside the AEAD primitive (`src/primitives/aead.ts:115,155`). It is **not** caller-provided; the public API has no nonce parameter.

## 4. Key commitment

The commitment is HMAC-SHA-256 (`src/primitives/commitment.ts:25-31`):

```
commitment = HMAC-SHA-256(commitKey, utf8(id) ‖ rawCt)
```

where `rawCt` is the full `nonce ‖ ciphertext ‖ tag` blob from §3 and `utf8(id)` is the UTF-8 encoding of the envelope's `id` string. The HMAC output is 32 bytes; the full output is stored in `enc.commit` (no truncation).

`commitKey` is a 32-byte key derived from the master key by HKDF (§6).

Verification is constant-time (`src/primitives/commitment.ts:39-46`, `src/internal/runtime.ts:46-53`) and is performed **before** AEAD decryption (`src/envelope/v1.ts:132-135`). A failed commitment throws before any AEAD work runs — this is the partitioning-oracle defence (Len, Grubbs, Ristenpart, USENIX 2021; see `doc/crypto.md`).

## 5. AAD construction

AAD is the UTF-8 bytes of the RFC 8785 canonicalisation of:

```
{ "alg": <enc.alg>, "id": <id>, "kid": <enc.kid>, "v": 1 }
```

(`src/aad.ts:19-21`, RFC 8785 canonicalisation in `src/canonical-json.ts`.)

**Crucial invariant: the `v` field in AAD is always `1`, even when the envelope is serialised as v2 CBOR.** The wire-format version (`v: 1` JSON vs `v: 2` CBOR) is a re-encoding of the same cryptographic object; the AAD is bound at encrypt time and never recomputed when the envelope changes wire format. See `src/envelope/v1.ts:61` (encrypt) and `src/envelope/v1.ts:137` (decrypt) — both pass literal `1`. Consequence: the wire-format `v` field is **not** integrity-protected, but flipping it only affects which parser runs; the cryptographic object is identical and the parser routes back through the same decrypt path. See `doc/tier-upgrade.md` for full discussion.

RFC 8785 canonicalisation produces sorted-key, no-whitespace JSON with deterministic string and number escaping. For the AAD inputs (alg, id, kid all ASCII strings; v=1 a small integer) the canonical form is:

```
{"alg":"<alg>","id":"<id>","kid":"<kid>","v":1}
```

with no spaces. UTF-8-encoding gives the byte sequence bound by the AEAD.

## 6. HKDF key schedule

Both the content-encryption key (CEK) and the commitment key are derived from a 32-byte master key via HKDF-SHA-256 (RFC 5869) with **distinct info strings** (`src/primitives/hkdf.ts:10-12`):

| derived key  | length | HKDF info (UTF-8 string)        |
|--------------|--------|---------------------------------|
| CEK          | 32 B   | `crypto-envelope/v1/content`    |
| commitKey    | 32 B   | `crypto-envelope/v1/commit`     |

Salt is empty (`src/primitives/hkdf.ts:43`); IKM is the 32-byte master key. Distinct info strings give cryptographically independent outputs from the same IKM, defeating key confusion between CEK and commitKey.

The fingerprint exposed by `EnvelopeClient.keyFingerprint` (`src/message-counter.ts:85-90`) is `HMAC-SHA-256(commitKey, "crypto-envelope/v1/keyfp")` truncated to 16 bytes. It is not used for cryptographic binding; it exists for rotation-policy bookkeeping in keyring.

## 7. v2 wire format (CBOR)

A v2 envelope (`src/envelope/v2.ts:20-39`) is the byte sequence:

```
+--------+--------------------------+
|  CKB   |       CBOR(envelope)     |
+--------+--------------------------+
  3 B            variable
```

The 3-byte magic prefix is the ASCII bytes `0x43 0x4B 0x42` ("CKB"). It distinguishes a v2 envelope from a v1 JSON envelope at parse time — JSON envelopes start with `{` (`0x7B`), so the first byte alone is sufficient to disambiguate (`src/envelope/v2.ts:120-127`).

The CBOR body encodes a map with major type 5 (`cborg` library defaults to compact, deterministic encoding). The map keys are text strings; binary fields are CBOR byte strings (major type 2), eliminating the ~33 % base64 overhead of v1.

Schema:

```
{
  v: 2,                              // CBOR uint
  id: <text>,                        // CBOR text string
  ts: <text>,                        // CBOR text string (ISO 8601)
  enc: {
    alg:    <text>,                  // "XChaCha20-Poly1305" | "AES-256-GCM"
    kid:    <text>,
    ct:     <bytes>,                 // nonce ‖ ciphertext ‖ tag
    commit: <bytes>                  // HMAC-SHA-256 output, 32 B
  }
}
```

Notable v1↔v2 differences:

- `enc['ct.len']` is **omitted** in v2 — CBOR byte strings carry their length intrinsically, so the defensive length field is redundant.
- `ct` and `commit` are CBOR byte strings, not base64 text.
- All other fields and semantics are identical to v1.

The cryptographic object — `nonce`, `ciphertext`, `tag`, `commitment`, AAD — is bit-for-bit identical between v1 and v2. `upgradeToV2` and `downgradeToV1` (`src/envelope/v2.ts:90-118`) are pure re-encodings.

## 8. Versioning rules

The `v` field on the wire is the **wire-format** version, not the cryptographic-object version. Today there are two wire formats (1 and 2) for one cryptographic object.

A new `v` value is required if:

- A new wire encoding is added (e.g. msgpack, length-prefixed binary). A new `v` value is allocated; the cryptographic object stays the same; the AAD continues to bind `v: 1`.
- A field is added or removed from the cryptographic object (alg, kid, id, commitment construction). This breaks AAD compatibility and requires a new AAD-bound `v`. See §9.

The cryptographic object is frozen for v1.x (CLAUDE.md priority #1). Any change that alters the bytes written by `encrypt()` is a breaking change requiring a major version bump.

A future v3 might reasonably introduce:

- A new AAD layout binding additional fields (e.g. an `aad_v` separate from the wire-format `v`).
- A different commitment construction (e.g. context-committing per Bellare-Hoang 2022 rather than only key-committing).
- A new AEAD algorithm with different nonce semantics (e.g. Argon2-derived nonces).

A change to *only* the wire encoding (a hypothetical msgpack v3) would allocate a new wire-format `v` but reuse the v1 AAD and existing `(nonce, ct, tag, commit)` bytes — exactly the v1↔v2 pattern.

## 9. Decryption algorithm (informative)

Reference decoder, in order (`src/envelope/v1.ts:107-145`):

1. Reject unknown wire-format version (`v` not in {1, 2}).
2. Reject unknown algorithm (`enc.alg` not in {`XChaCha20-Poly1305`, `AES-256-GCM`}).
3. Decode `enc.ct` to bytes; validate `length >= nonceWidth(alg) + 16`.
4. (v1 only) validate `enc['ct.len']` matches actual decoded length.
5. Compute `expected = HMAC-SHA-256(commitKey, utf8(id) ‖ ct)`. Constant-time compare to `enc.commit`. Reject on mismatch.
6. Slice `ct` into `(nonce, ciphertext, tag)` per §3.
7. Construct `aad = utf8(rfc8785({alg, id, kid, v: 1}))`.
8. AEAD-decrypt `(ciphertext, tag)` under `cek` with `nonce` and `aad`. Reject on tag failure.
9. UTF-8-decode plaintext bytes and JSON-parse.

Each step throws on failure; no silent fallback, no partial result.

## 10. Encoder requirements (normative summary)

A conforming encoder MUST:

- Generate `nonce` from a CSPRNG; nonce width is fixed by `enc.alg`.
- Construct AAD as in §5 with `v: 1` regardless of wire format.
- Compute the commitment as in §4 over `utf8(id) ‖ ct`.
- Verify-after-encrypt: re-decrypt the produced ciphertext and constant-time-compare to the input plaintext bytes (`src/envelope/v1.ts:73-76`). On any mismatch, abort and surface an error rather than emit the envelope.
- Emit `enc['ct.len']` in v1 envelopes equal to the byte length of the decoded `ct`.
- Emit the `CKB` magic prefix in v2 envelopes.
- Reject input plaintext that is not a plain JSON object (`src/canonical-json.ts:16-19`); arrays and primitives are not envelope-encryptable.

A conforming decoder MUST follow §9 strictly. In particular: commitment verification before AEAD; constant-time comparisons for both commitment and AEAD-tag-derived secrets; no silent decryption-failure path that returns plaintext-shaped garbage.
