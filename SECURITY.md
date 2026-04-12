# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes — while in pre-release. No backward-compat guarantees across minor versions. |
| &lt; 0.x | N/A — no releases yet |

Once v1.0.0 ships, the wire format is frozen: a v1.x release must always decrypt envelopes produced by any prior v1.x release. Breaking the wire format will be a v2.0.0 release with at least 12 months' notice.

## Reporting a vulnerability

**Please do not report security issues through public GitHub issues, discussions, or pull requests.**

Use [GitHub's private vulnerability reporting](https://github.com/de-otio/crypto-envelope/security/advisories/new) to submit a report. If that tooling is unavailable to you, email `security@de-otio.org`.

## What to include

A good report includes:

- A clear description of the issue and the conditions under which it triggers
- Affected version(s), commit SHA, or package version on npm
- A proof of concept (code, envelope bytes, or reproduction steps) when possible
- The impact you believe the issue has, in your own words
- Whether you want credit in the changelog (default: yes, with your preferred attribution)

## What to expect

This project is small-org and does not maintain 24/7 security response capacity. The commitment is honest communication, not a staffed SLA.

- **Acknowledgement:** best-effort, typically within a few business days.
- **Initial assessment:** whether the report is in-scope, severity, and a tentative timeline — within 14 days of acknowledgement, usually sooner.
- **Fix or mitigation:** depends on severity and complexity. A plan will be shared with the reporter; if a fix will take significant time, mitigation guidance is shared first.
- **Coordinated disclosure:** 90-day default window, negotiable. If a fix cannot be prepared within the window, the advisory is published with whatever mitigation the project can offer (pin an earlier version, avoid a specific code path, switch algorithms).
- **CVE issuance** via GitHub's security advisory tooling when warranted.
- **Credit** in the release notes and changelog, unless you prefer otherwise.

If the issue is actively exploited in the wild or otherwise time-sensitive, say so in the report; the response prioritisation reflects real urgency.

## Scope

In scope:

- Any cryptographic weakness in the encrypt/decrypt paths (confidentiality, integrity, authenticity)
- Failure to meet documented threat-model claims (key commitment, AAD binding, nonce uniqueness, verify-after-encrypt)
- Logic bugs leading to key leakage, silent plaintext exposure, or authentication bypass
- Bypasses of the `SecureBuffer` or constant-time comparison invariants
- Deserialisation or parser bugs that could cause denial of service or worse
- Vulnerabilities in our own dependencies that materially affect this package's security claims

Out of scope:

- Security of the underlying cryptographic primitives (`@noble/*`, libsodium, platform AEAD) — report those upstream
- Attacks requiring physical access to the device holding the key material
- Compromised host OS, malicious browser extensions, or other endpoint-compromise scenarios
- Vulnerabilities in third-party consumers of this package (report those to them)
- Theoretical weaknesses that do not lead to a practical exploit path against the documented threat model

## Safe-harbour

Good-faith security research that follows this policy will not result in legal action from the project or its maintainers. Disclosure must remain private until the project has published an advisory or 90 days have passed, whichever comes first.

## What this policy does not promise

- A specific response-time SLA
- Paid bounties
- A dedicated security team
- Audit reports on demand

Those are not things a small-org project can honestly promise. Overclaiming security capacity is itself a security anti-pattern — it gives reporters false expectations and produces worse outcomes than honest communication.
