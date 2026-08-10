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
> attacker; false positives and false negatives will occur. A clean pass is
> not evidence of safety. APIs and behaviour may change without notice
> between releases.
>
> If a failure could cause harm, financial loss, or regulatory consequence
> in your environment, do not rely on Bouclier as the control that prevents
> it. See [Terms](https://www.bouclier.ai/terms) before installing.

## What it does

Bouclier.ai runs a local gateway on your Mac. You point your agent's SDK at
it (`ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`) instead of the provider
directly; it re-issues each request to the real provider over TLS and
streams the response back.

- **Prompt-injection firewall.** 161 regex patterns across 21 categories
  **plus an on-device ML classifier** (Meta Prompt Guard 2) run on every
  request body, fused into one score with false-positive dampeners. When
  an instruction shows up in content your agent fetched by itself, the
  request is refused before it reaches the provider.
- **Provenance decides the action — this is the whole design.** Bouclier
  splits each request by where the text came from:
  - **Untrusted** — `tool_result` blocks (Anthropic), `role: "tool"`
    messages (OpenAI chat), `function_call_output` items (OpenAI
    Responses), and **retrieved content**: `document` / `search_result`
    blocks and anything wrapped in the `<document>` RAG convention, even
    when it arrives inside a user turn. Nobody in your session typed
    these, so an instruction here is an attack by definition and the
    request is **refused** with a `403` naming the pattern and the JSON
    path.
  - **Principal** — your prompt and your system prompt. Scanned so the
    activity log stays useful, then **forwarded byte-for-byte no matter
    what they say**. You are allowed to discuss jailbreaks with your own
    model. Pinned by an end-to-end test.
- **Benign context isn't punished.** A match inside a security advisory,
  a tutorial, a quoted payload, or a fenced code block is dampened and
  forwarded, not blocked — so an agent reading about attacks all day
  doesn't trip the filter.
- **Monitor by default, enforce when you opt in.** Out of the box the
  gateway inspects and logs but forwards everything — so it can't break
  normal agent work on a false positive. Turn on blocking (per install or
  via MDM) when you want refusals.
- **Nothing is ever rewritten.** A request is forwarded unmodified or
  refused outright. Earlier versions spliced a redaction notice into
  flagged prompts; that broke prompt caching and tripped provider abuse
  detection, and it is gone for good.
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

The on-device ML tier (Meta Prompt Guard 2, 86M) is **bundled** as of
v0.9.1 — it runs fully on-device (CoreML, no network), which is the point:
your traffic never leaves the machine to be classified. The tradeoff is a
larger download (~300 MB vs ~6 MB). Even so, Prompt Guard 2 is a small
classifier, not a frontier judge: it lifts recall on novel/multilingual
attacks but is still evadable under adaptive/encoding attacks. The model
is gated (Meta HuggingFace) and produced at release time by
`scripts/ensure-model.sh`; it is not committed to the repo.

## Quickstart

Download the signed DMG from <https://www.bouclier.ai>, drag the app to
`/Applications`, and click "Enable Protection". Open a new terminal to pick
up the env vars, and your agent's requests route through the gateway
automatically.

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
                                  └────────────────────────┘
```

The injection pass sits behind a cheap trigger gate, so a request with no
untrusted tool output in it is forwarded byte-for-byte without the pass
running. The gateway never rewrites a request — it forwards it unmodified
or refuses it.

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

Bug reports and core gateway/detection work are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup.

For security issues, follow [SECURITY.md](.github/SECURITY.md) — do not
open a public issue.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).

Release builds bundle the Meta Llama Prompt Guard 2 model (converted to
CoreML by `scripts/ensure-model.sh`; the weights are gitignored and
fetched from Meta's gated HuggingFace repo at release time, not committed
— see [ARCHITECTURE.md](ARCHITECTURE.md)). They're governed by the Llama 4
Community License (`LICENSES/Llama-4-Community-License.txt`); see
[NOTICE.txt](NOTICE.txt) for attribution.
