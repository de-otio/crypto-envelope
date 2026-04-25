# Documentation

Design documents for `@de-otio/crypto-envelope`.

- [`envelope-spec.md`](./envelope-spec.md) — wire-format specification (v1 JSON and v2 CBOR), AAD construction, HKDF schedule, commitment derivation, decryption algorithm. Sufficient for a third party to build an interoperable implementation.
- [`crypto.md`](./crypto.md) — cryptographic primitives chosen, with citations to RFCs and academic literature. Argues why each choice is the one in the source.
- [`tier-upgrade.md`](./tier-upgrade.md) — v1↔v2 conversion semantics. Explains the `v: 1` AAD invariant and why `upgradeToV2`/`downgradeToV1` are pure re-encodings.
- [`mistakes-prevented.md`](./mistakes-prevented.md) — negative space. Maps each "What this package protects against" bullet from the README to the source file:line that enforces it.
- [`bedrock-cost-controls.md`](./bedrock-cost-controls.md) — operational note on AWS Bedrock cost guardrails (unrelated to crypto; see file).

Test vectors live alongside the code in [`test/vectors/`](../test/vectors).
