## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Documentation / non-code change
- [ ] Refactor (non-functional change)
- [ ] Breaking change (API change or wire-format change — requires a major version bump)

## Wire format

- [ ] This change does NOT alter the bytes produced by `encrypt()` (compatibility preserved within v1.x)
- [ ] This change DOES alter the wire format (must be explicitly proposed as a v2 change)

## Testing

- [ ] Existing tests pass locally (`npm test`)
- [ ] New tests added for this change
- [ ] Test vectors updated if the change affects wire format, AEAD parameters, AAD construction, or key derivation

## Security review checklist

- [ ] Nonces still come from CSPRNG only; no user-supplied or deterministic nonces
- [ ] AAD is still mandatory and binds `v`, `id`, `alg`, `kid`
- [ ] Key separation is preserved (encryption key vs. commitment key)
- [ ] No secret comparison with non-constant-time operators
- [ ] No new runtime dependencies (or: new dependencies are justified below)
- [ ] No new network fetches in library code

## Related issues

<!-- Closes #123, part of #456, etc. -->

## Additional notes
