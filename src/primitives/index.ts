/**
 * @de-otio/crypto-envelope/primitives
 *
 * Advanced sub-entry exposing the low-level primitives for callers who want
 * envelope-style discipline on a non-default shape. Stability contract is
 * weaker here than the main entry — breaking changes still require a major
 * bump, but we reserve the right to reshape these more aggressively.
 *
 * Placeholder. Implementation extracted from chaoskb pending.
 */

// TODO: Export aead (XChaCha20-Poly1305 encrypt/decrypt)
// TODO: Export hkdf (HKDF-SHA256 Extract+Expand)
// TODO: Export argon2 (Argon2id KDF with OWASP-2023 params)
// TODO: Export commitment (key commitment HMAC)
// TODO: Export canonicalJson (RFC 8785)
// TODO: Export constructAAD
