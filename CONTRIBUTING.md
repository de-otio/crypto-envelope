# Contributing

Thanks for considering a contribution. A few things to read first, since this is a small-org, primarily-internal project.

## Scope

This package is maintained for [chaoskb](https://github.com/de-otio/chaoskb), [trellis](https://github.com/de-otio/trellis), and other de-otio projects. Public availability is for transparency and reference; see the [maintenance posture in README](./README.md#maintenance-posture).

**Practical consequence:** feature requests beyond what de-otio projects need may be politely declined. This is not a rejection of your idea — forking is encouraged and the MIT license makes it easy. If your proposal is driven by a specific use case that aligns with the package's goals, say so; alignment with the existing design philosophy carries weight.

## Reporting issues

- **Security issues** — do not open a public issue. See [SECURITY.md](./SECURITY.md) for the private disclosure process.
- **Bugs** — open an issue with a minimal reproduction. What you expected, what you got, the version/commit, the platform.
- **Design questions or proposals** — open an issue first, before writing the code. Wire-format changes and public-API changes need discussion; patches without prior discussion may be closed as out-of-scope.

## Code changes

**Never break the wire format within a major version.** A v1.x release must decrypt envelopes produced by any prior v1.x. This is the most important rule in the project. Any change that touches byte-level encoding needs review against this constraint.

Other guidelines:

- **TypeScript strict mode** is required. The `tsconfig.json` is authoritative.
- **Tests are required** for functional changes. Use `vitest`. Aim for meaningful coverage of the change, not just numerical coverage.
- **Biome** handles formatting and linting. Run `npm run lint:fix` before committing.
- **Commit messages** should be descriptive. `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:` prefixes are appreciated but not enforced.
- **No dependencies added without discussion.** The runtime dependency graph is deliberately small. Each dependency is a supply-chain attack surface and a long-term maintenance cost.
- **No new algorithms without documented threat model analysis.** See [`05-mistakes-prevented.md` in the skybber analysis docs](https://github.com/de-otio/skybber/blob/main/analysis/crypto-envelope-package/05-mistakes-prevented.md) (private) for the kind of justification expected.

## Pull requests

- Fork, branch, PR against `main`.
- The PR template prompts for the information the reviewer needs; please fill it in.
- Automated checks will run: build, test, lint, CodeQL, dependency scan, secrets scan, and an AI security review of the diff.
- A human reviewer will look at non-trivial changes. Response is best-effort — see the maintenance posture.

## Test vectors

Changes to the envelope wire format, AEAD parameters, AAD construction, or key derivation require updated test vectors in `test/vectors/`. Any new vector must be reproducible from the documented algorithm — if you can't describe how to generate it, it doesn't belong in the file.

## Code of conduct

Participation is subject to the [Code of Conduct](./CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contribution will be licensed under the [MIT License](./LICENSE).
