# Changelog

All notable changes to `@de-otio/crypto-envelope` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Scaffolding

- Initial repository structure
- TypeScript dual ESM/CJS build configuration
- CI, security review, dependency scan, secrets scan workflows
- SECURITY.md with honest disclosure posture
- CONTRIBUTING.md and CODE_OF_CONDUCT.md
- Placeholder `src/` structure pending extraction from chaoskb

### Planned for v0.1

- Extract envelope, AEAD, HKDF, Argon2id, commitment, AAD, canonical JSON, SecureBuffer from chaoskb's `src/crypto/`
- Two-tier KeyRing (Standard SSH-wrap, Maximum passphrase)
- Test vectors covering all `alg`/`kid` combinations
- Internal consumption by chaoskb and trellis
