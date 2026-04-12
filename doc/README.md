# Documentation

Design documents for `@de-otio/crypto-envelope` will live here once the extraction from chaoskb completes.

Planned documents:

- `envelope-spec.md` — formal wire-format specification with test vectors (ported from `chaoskb/doc/design/envelope-spec.md`)
- `crypto.md` — cryptographic design overview (adapted from chaoskb's equivalent)
- `tier-upgrade.md` — the two-tier model and upgrade protocol
- `mistakes-prevented.md` — design justification: each common application-level crypto mistake and how the package prevents it

In the meantime, the full analysis driving this package lives in the private [skybber](https://github.com/de-otio/skybber) repository under `analysis/crypto-envelope-package/`.
