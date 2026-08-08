# Security Policy

Bouclier.ai runs a local gateway that your AI agent's SDK points at
(`ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`) and scrubs managed secrets from
outbound requests before re-issuing them to the real provider. We take
vulnerability reports seriously and ask that you disclose them
responsibly so we can ship a fix before details become public.

## Supported versions

We provide security fixes for the latest `0.x` minor release on the
`main` branch. Older `0.x` releases are not patched; please update.
A semver `1.0` will introduce a longer support window.

| Version | Supported           |
| ------- | ------------------- |
| 0.9.x   | ✅                  |
| ≤ 0.8.x | ❌ (please upgrade) |

## Reporting a vulnerability

Please **do not** open a public issue, discussion, or pull request for
a suspected vulnerability.

Use one of the following private channels, in order of preference:

1. GitHub Security Advisories — open a private report at
   <https://github.com/SuperstellarLLC/bouclier-ai/security/advisories/new>.
2. Email `apps@superstellar.io` with the details below.

Please include:

- A clear description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept payload.
- The affected version (`Bouclier.ai → About` or `git rev-parse HEAD`).
- macOS version and CPU architecture (Apple Silicon / Intel).

Encrypt sensitive details with our PGP key if you prefer — fingerprint
and public key are available on request from `apps@superstellar.io`.

## Response targets

We will acknowledge your report within **2 business days**, share an
initial assessment within **5 business days**, and aim to ship a fix
within **30 days** for high/critical issues. Coordinated public
disclosure is the default; we will agree on a timeline with the
reporter.

## Scope

Bouclier.ai's threat model is documented in
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md). In scope:

- Bypasses of the secret scrub/restore invariant (a managed secret's real
  value reaching the model provider, or a corrupted restore leaking a
  placeholder to the agent).
- Memory-safety issues in the gateway.
- Issues that allow plaintext request content or secret values to be
  persisted or exfiltrated despite the privacy invariants in the threat
  model.
- Code-signing, notarization, or update-channel weaknesses (Sparkle
  appcast tampering, downgrade, replay).
- Logic bugs that cause the gateway to fail open in a way that leaks a
  secret (e.g., forwarding a request that should have been scrubbed).

Out of scope:

- Findings that require the attacker to have physical or
  administrator-level access to the user's Mac.
- Social engineering, phishing, or attacks against `bouclier.ai`
  marketing assets unrelated to the gateway or the app itself.
- The dormant prompt-injection/PII detection engine (`packages/patterns`,
  `InjectionFilter`, the multimodal scanners) — it isn't wired into any
  live request path since extreme mode's removal, so it isn't a live
  attack surface. General bugs there are welcome as a regular issue.

## Bug bounty

We do not currently run a paid bounty program. Researchers who report
in good faith and follow this policy will be credited in release notes
unless they request anonymity.
