# Security Policy

Bouclier.ai sits in your network path and decrypts AI API traffic on
your machine. We take vulnerability reports seriously and ask that you
disclose them responsibly so we can ship a fix before details become
public.

## Supported versions

We provide security fixes for the latest `0.x` minor release on the
`main` branch. Older `0.x` releases are not patched; please update.
A semver `1.0` will introduce a longer support window.

| Version | Supported           |
| ------- | ------------------- |
| 0.4.x   | ✅                  |
| ≤ 0.3.x | ❌ (please upgrade) |

## Reporting a vulnerability

Please **do not** open a public issue, discussion, or pull request for
a suspected vulnerability.

Use one of the following private channels, in order of preference:

1. GitHub Security Advisories — open a private report at
   <https://github.com/SuperstellarLLC/ilvarion/security/advisories/new>.
2. Email `security@bouclier.ai` with the details below.

Please include:

- A clear description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept payload.
- The affected version (`Bouclier.ai → About` or `git rev-parse HEAD`).
- macOS version and CPU architecture (Apple Silicon / Intel).

Encrypt sensitive details with our PGP key if you prefer — fingerprint
and public key are available on request from `security@bouclier.ai`.

## Response targets

We will acknowledge your report within **2 business days**, share an
initial assessment within **5 business days**, and aim to ship a fix
within **30 days** for high/critical issues. Coordinated public
disclosure is the default; we will agree on a timeline with the
reporter.

## Scope

Bouclier.ai's threat model is documented in
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md). In scope:

- Bypasses of the prompt-injection or PII scanners (including
  detection-evasion payloads).
- Memory-safety issues in the TLS proxy or System Extension.
- Issues that allow plaintext request content to be persisted or
  exfiltrated despite the privacy invariants in the threat model.
- Code-signing, notarization, or update-channel weaknesses (Sparkle
  appcast tampering, downgrade, replay).
- Logic bugs that cause the proxy to fail open (e.g., forwarding a
  flagged payload unchanged).

Out of scope:

- Findings that require the attacker to have physical or
  administrator-level access to the user's Mac.
- Social engineering, phishing, or attacks against `bouclier.ai`
  marketing assets unrelated to the proxy or the app itself.
- Best-effort detection coverage gaps for novel attack patterns —
  please open a regular issue or pull request with a regression test.

## Bug bounty

We do not currently run a paid bounty program. Researchers who report
in good faith and follow this policy will be credited in release notes
unless they request anonymity.
