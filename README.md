<div align="center">
  <img src="apps/site/public/images/logo-256.png" alt="Bouclier.ai" width="128" height="128" />

  <h1>Bouclier.ai</h1>

  <p><strong>A local-only macOS prompt-injection firewall for AI coding agents. It reads every tool result on its way into the model and refuses the request when a fetched page, a README, or an MCP response is trying to give your agent orders. Your own prompts are never touched. No certificate to install.</strong></p>

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
> and personal experimentation. It is **not a commercial product**, is **not
> sold or supported**, and is **pre-1.0** — not for production or regulated
> workloads (healthcare, payments, identity, fraud prevention, anything
> safety-critical).
>
> Treat it the way you treat a WAF: **defence in depth, never your only
> control.** Injection detection is best-effort and evadable by a determined
> attacker; secret scrubbing is best-effort; false positives and false
> negatives will occur. A clean pass is not evidence of safety. APIs and
> behaviour may change without notice between releases.
>
> If a failure could cause harm, financial loss, or regulatory consequence
> in your environment, do not rely on Bouclier as the control that prevents
> it. See [Terms](https://www.bouclier.ai/terms) before installing.

## What it does

Bouclier.ai runs a local gateway on your Mac. You point your agent's SDK at
it (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`) instead of the provider
directly; it re-issues each request to the real provider over TLS and
streams the response back.

- **Prompt-injection firewall.** 161 detection patterns across 21
  categories run on every request body. When an instruction shows up in
  content your agent fetched by itself, the request is refused before it
  reaches the provider.
- **Provenance decides the action — this is the whole design.** Bouclier
  splits each request by where the text came from:
  - **Untrusted** — `tool_result` blocks (Anthropic), `role: "tool"`
    messages (OpenAI chat), `function_call_output` items (OpenAI
    Responses). Nobody in your session typed these, so an instruction
    here is an attack by definition and the request is **refused** with a
    `403` naming the pattern and the JSON path.
  - **Principal** — your prompt and your system prompt. Scanned so the
    activity log stays useful, then **forwarded byte-for-byte no matter
    what they say**. You are allowed to discuss jailbreaks with your own
    model. Pinned by an end-to-end test.
- **Nothing is ever rewritten.** A request is forwarded unmodified or
  refused outright. Earlier versions spliced a redaction notice into
  flagged prompts; that broke prompt caching and tripped provider abuse
  detection, and it is gone for good.
- **Secret keeper (opt-in).** Managed secrets are stored in your macOS
  Keychain behind an opaque placeholder, scrubbed on the way out and
  restored in the response — so if an injection does get through, the
  credentials it wants were never in the model's context. Off by default;
  enable under Settings → Secrets.
- **No certificate to install.** The gateway is a plaintext-loopback →
  TLS-upstream relay, not a TLS-terminating proxy — there's no root CA, no
  system-trust change, and nothing else on your Mac is affected. Detection
  used to require a CA and a System Extension; as of v0.9.0 it doesn't.
- **Local only.** No cloud calls, no telemetry, no accounts.

### What this does not claim

Prompt injection is not solved, and a pattern engine is not a solution to
it. The defences that hold are structural — constraining what a hijacked
agent can reach, keeping untrusted input away from privileged actions.
Bouclier is defence in depth on the untrusted leg: it raises the cost of
the easy attacks and shows you when one arrives. Treat it the way you
treat a WAF, not the way you treat a proof.

The on-device ML tier (Meta Prompt Guard 2) is **not bundled** — the
weights were removed in v0.7.0 to keep the download at ~6 MB instead of
~600 MB. The fused regex + ML + entropy scorer and the CoreML loader are
intact, so supplying a model locally lights the ML tier back up.

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
┌─────────────┐  HTTP (loopback)  ┌────────────────────────┐  HTTPS   ┌──────────┐
│ AI client   │ ────────────────► │ Bouclier.ai gateway    │ ───────► │ Provider │
│ (Claude     │                   │ (local, on Mac)        │          │ (OpenAI, │
│  Code,      │                   │                        │          │  Claude, │
│  Cursor, …) │ ◄──────────────── │ ┌────────────────────┐ │ ◄─────── │  Gemini) │
└─────────────┘   403 if refused  │ │ Injection pass     │ │          └──────────┘
                                  │ │  untrusted → block │ │
                                  │ │  principal → log   │ │
                                  │ └────────────────────┘ │
                                  │ ┌────────────────────┐ │
                                  │ │ Secret scrub /     │ │
                                  │ │ restore (opt-in)   │ │
                                  │ └────────────────────┘ │
                                  └────────────────────────┘
```

The injection pass runs **before** the secret scrub: a refused request
never had secrets substituted into it, and scoring sees the untouched
body. Both passes sit behind a cheap trigger gate, so a request with no
tool output and no managed secret in it is forwarded byte-for-byte
without either pass running.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the request-handling pipeline,
session model, and persistence layer.

## Repository layout

```
apps/
├── desktop/       Swift menubar app + gateway
└── site/          Next.js marketing & docs site (bouclier.ai)

packages/
└── patterns/      Injection + PII pattern library. The injection tier is
                    live: `pnpm --filter @bouclier-ai/patterns build` then
                    `apps/desktop/scripts/sync-patterns.sh` regenerates the
                    161-pattern patterns.json the app compiles. The PII
                    tier is dormant — see ARCHITECTURE.md.

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

The repository retains the Meta Llama Prompt Guard 2 integration code and
tokenizer (the weights themselves are not bundled — see
[ARCHITECTURE.md](ARCHITECTURE.md)).
They're governed by the Llama 4 Community License
(`LICENSES/Llama-4-Community-License.txt`); see [NOTICE.txt](NOTICE.txt) for
attribution.
