<div align="center">
  <img src="apps/site/public/images/logo-256.png" alt="Bouclier.ai" width="128" height="128" />

  <h1>Bouclier.ai</h1>

  <p><strong>A local-only macOS proxy that stops prompt injections and stops PII from leaking to LLMs — in text, images, PDFs, and audio.</strong></p>

  <p>
    <a href="https://github.com/SuperstellarLLC/bouclier-ai/actions/workflows/ci.yml"><img src="https://github.com/SuperstellarLLC/bouclier-ai/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
    <a href="https://github.com/SuperstellarLLC/bouclier-ai/releases"><img src="https://img.shields.io/github/v/release/SuperstellarLLC/bouclier-ai?display_name=tag" alt="Latest release"></a>
    <img src="https://img.shields.io/badge/platform-macOS%2015%2B-lightgrey" alt="macOS 15+">
    <img src="https://img.shields.io/badge/status-beta-orange" alt="Beta">
  </p>

  <p><a href="https://www.bouclier.ai">Website</a> · <a href="ARCHITECTURE.md">Architecture</a> · <a href="docs/THREAT_MODEL.md">Threat model</a> · <a href="CHANGELOG.md">Changelog</a></p>
</div>

---

> **Beta software.** Bouclier.ai is a prototype intended for evaluation, research,
> and personal experimentation. Detection is best-effort and probabilistic —
> false positives and false negatives will occur. **Not** intended for
> production, regulated workloads, or environments where a detection failure
> could cause harm. See [Terms](https://www.bouclier.ai/terms) before installing.

## What it does

Bouclier.ai is a System Extension that routes traffic to AI APIs through a
local TLS-terminating proxy on your Mac. Every outbound request is inspected
before it reaches the provider, every streaming response is scanned for
exfiltration, and nothing ever leaves the machine for inspection.

- **Prompt-injection scanner.** 150+ patterns across 20+ attack categories,
  fused with Meta Llama Prompt Guard 2 running on-device for a probabilistic
  second opinion.
- **PII redaction.** Emails, IBANs, NHS numbers, SIRET/SIREN/NIR, NINO,
  postcodes, NPI, AWS keys, JWTs, IPs, and 50+ secret detectors. Replaced
  with reversible per-connection placeholders so the model still answers
  correctly.
- **Multimodal inspection.** Outbound images, PDFs, and audio clips are
  opened on-device with Apple Vision (OCR + face detection), PDFKit, and
  SFSpeechRecognizer (`requiresOnDeviceRecognition`). Flagged attachments
  are stripped before the request leaves your Mac.
- **Local only.** No cloud calls, no telemetry, no accounts. The audit log
  records type and offsets, never cleartext.

## Quickstart

Download the signed DMG from <https://www.bouclier.ai>, drag the app to
`/Applications`, and grant the System Extension on first launch. The menu
bar icon goes green when interception is live.

```bash
# Verify it's intercepting:
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
# Check Bouclier.ai → Activity log.
```

Build from source:

```bash
git clone https://github.com/SuperstellarLLC/bouclier-ai.git
cd bouclier-ai
pnpm install
cd apps/desktop && swift build -c release
swift run Bouclier
```

A full developer setup is in [CONTRIBUTING.md](CONTRIBUTING.md).

## How it works

```
┌─────────────┐    HTTPS    ┌─────────────────────┐    HTTPS    ┌──────────┐
│ AI client   │ ──────────► │  Bouclier.ai proxy  │ ──────────► │ Provider │
│ (Cursor,    │             │  (local, on Mac)    │             │ (OpenAI, │
│  ChatGPT,   │ ◄────────── │                     │ ◄────────── │  Claude, │
│  curl, …)   │             │  ┌───────────────┐  │             │  Gemini) │
└─────────────┘             │  │ Injection scan│  │             └──────────┘
                            │  │ Multimodal    │  │
                            │  │ PII redact    │  │
                            │  │ Audit log     │  │
                            │  └───────────────┘  │
                            └─────────────────────┘
                                      │
                                      ▼
                            ~/Library/Application Support/
                            ai.bouclier.app/audit.db
                            (no cleartext, 30-day TTL)
```

The proxy generates a per-machine root CA stored in the macOS Keychain, used
solely to decrypt AI API hosts. All other traffic is untouched. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the request-handling pipeline,
session model, and persistence layer.

## Repository layout

```
apps/
├── desktop/       Swift menubar app + TLS proxy + System Extension
└── site/          Next.js marketing & docs site (bouclier.ai)

packages/
└── patterns/      Shared injection + PII detection rules (TypeScript)

docs/
├── THREAT_MODEL.md
└── PII_PROTOCOL_COMPATIBILITY.md
```

## Status and stability

Bouclier.ai is **0.x**. The on-disk format, public APIs, and detection-rule
schema may change between minor releases. We follow
[Semantic Versioning](https://semver.org/) and document every user-visible
change in [CHANGELOG.md](CHANGELOG.md).

The detection coverage and tested providers are listed in
[`docs/PII_PROTOCOL_COMPATIBILITY.md`](docs/PII_PROTOCOL_COMPATIBILITY.md).

## Contributing

Bug reports, missed-detection reports, pattern contributions, and core
proxy work are all welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md)
for the dev setup, and see the
[detection-miss template](https://github.com/SuperstellarLLC/bouclier-ai/issues/new/choose)
if Bouclier let something through it shouldn't have.

For security issues, follow [SECURITY.md](.github/SECURITY.md) — do not
open a public issue.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).

The bundled Meta Llama Prompt Guard 2 model is governed by the Llama 4
Community License (`LICENSES/Llama-4-Community-License.txt`); see
[NOTICE.txt](NOTICE.txt) for attribution.

Built with Llama. Bouclier.ai uses Meta Llama Prompt Guard 2 locally on
your Mac for on-device prompt-attack detection.
