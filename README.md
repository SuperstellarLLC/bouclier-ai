<div align="center">
  <img src="apps/site/public/images/logo-256.png" alt="Bouclier.ai" width="128" height="128" />

  <h1>Bouclier.ai</h1>

  <p><strong>A local-only macOS proxy that keeps your API keys and other secrets out of the model — scrubbed before the request reaches the provider, restored in the response. No certificate to install.</strong></p>

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

> [!WARNING]
> **Beta — research prototype. Not for live use.**
>
> Bouclier.ai is published for evaluation, security research, academic study,
> and personal experimentation only. It is **not a commercial product**, is
> **not sold or supported**, and is **not meant to be used live** — that is,
> not in production, not as a security control anyone or anything relies on,
> and not in regulated workloads (healthcare, payments, identity, fraud
> prevention, anything safety-critical). Secret scrubbing is best-effort;
> false positives and false negatives will occur. APIs and behaviour may
> change without notice between releases.
>
> If a failure could cause harm, financial loss, or regulatory consequence
> in your environment, do not deploy Bouclier. See
> [Terms](https://www.bouclier.ai/terms) before installing.

## What it does

Bouclier.ai runs a local gateway on your Mac. You point your agent's SDK at
it (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`) instead of the provider
directly; it re-issues each request to the real provider over TLS and
streams the response back.

- **Secret keeper.** Managed secrets (API keys, tokens) are stored in your
  macOS Keychain behind an opaque placeholder. Before a request reaches the
  model provider, any real secret value is scrubbed to its placeholder; the
  matching response is restored so your local tools still see the real
  value. The model vendor never sees the secret.
- **No certificate to install.** The gateway is a plaintext-loopback →
  TLS-upstream relay, not a TLS-terminating proxy — there's no root CA, no
  system-trust change, and nothing else on your Mac is affected.
- **Text prompts and headers untouched.** Prompt bodies and HTTP request
  headers (`Authorization`, `x-api-key`, custom trace IDs, `User-Agent`)
  traverse the gateway byte-for-byte except for the secret-scrub
  substitution described above. Pinned by an end-to-end test so a future
  change can't drift.
- **Local only.** No cloud calls, no telemetry, no accounts.

## Quickstart

Download the signed DMG from <https://www.bouclier.ai>, drag the app to
`/Applications`, and click "Enable Protection". Add a managed secret from
the menu bar, open a new terminal to pick up the env vars, and your agent's
requests route through the gateway automatically.

```bash
# Verify it's running:
curl http://127.0.0.1:8484/livez
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
┌─────────────┐  HTTP (loopback)  ┌─────────────────────┐    HTTPS    ┌──────────┐
│ AI client   │ ────────────────► │  Bouclier.ai gateway │ ──────────► │ Provider │
│ (Claude     │                   │  (local, on Mac)     │             │ (OpenAI, │
│  Code,      │ ◄──────────────── │                       │ ◄────────── │  Claude, │
│  Cursor, …) │                   │  ┌─────────────────┐  │             │  Gemini) │
└─────────────┘                   │  │ Secret scrub /   │  │             └──────────┘
                                   │  │ restore          │  │
                                   │  └─────────────────┘  │
                                   └───────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the request-handling pipeline,
session model, and persistence layer.

## Repository layout

```
apps/
├── desktop/       Swift menubar app + gateway
└── site/          Next.js marketing & docs site (bouclier.ai)

packages/
└── patterns/      Injection + PII pattern library (dormant — see
                    ARCHITECTURE.md; not currently invoked on live traffic)

docs/
└── THREAT_MODEL.md
```

## Status and stability

Bouclier.ai is **0.x**. The on-disk format and public APIs may change
between minor releases. We follow
[Semantic Versioning](https://semver.org/) and document every user-visible
change in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Bug reports and core gateway/secret-keeper work are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup.

For security issues, follow [SECURITY.md](.github/SECURITY.md) — do not
open a public issue.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).

The repository still bundles the Meta Llama Prompt Guard 2 model weights
(part of the dormant detection engine — see [ARCHITECTURE.md](ARCHITECTURE.md)).
They're governed by the Llama 4 Community License
(`LICENSES/Llama-4-Community-License.txt`); see [NOTICE.txt](NOTICE.txt) for
attribution.
