<div align="center">
  <img src="apps/site/public/images/logo-256.png" alt="Bouclier.ai" width="128" height="128" />

  <h1>Bouclier.ai</h1>

  <p><strong>A local-only macOS prompt-injection firewall for AI coding agents. It reads tool results on their way into the model — a fetched page, a README, an MCP response — and flags anything trying to give your agent orders (and refuses it outright once you turn blocking on). It monitors by default, so it does not break your work on a false positive. Your own prompts are never blocked in normal mode. No certificate to install.</strong></p>

  <p>
    <a href="https://github.com/SuperstellarLLC/bouclier-ai/actions/workflows/ci.yml"><img src="https://github.com/SuperstellarLLC/bouclier-ai/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
    <a href="https://www.bouclier.ai"><img src="https://img.shields.io/badge/download-macOS-black?logo=apple&logoColor=white" alt="Download for macOS"></a>
    <img src="https://img.shields.io/badge/platform-macOS%2015%2B-lightgrey" alt="macOS 15+">
    <img src="https://img.shields.io/badge/architecture-Apple%20silicon-lightgrey" alt="Apple silicon">
    <img src="https://img.shields.io/badge/status-beta-orange" alt="Beta">
  </p>

  <p><a href="https://www.bouclier.ai">Website</a> · <a href="ARCHITECTURE.md">Architecture</a> · <a href="docs/THREAT_MODEL.md">Threat model</a> · <a href="CHANGELOG.md">Changelog</a></p>
</div>

---

> [!WARNING]
> **Beta — experimental, pre-1.0 software.**
>
> Bouclier.ai's source code is open source under Apache 2.0; signed release
> builds also include Meta Prompt Guard 2 under the separate Llama 4 Community
> License. The project comes without an SLA or commercial support. It has not
> been independently validated or certified for regulated or safety-critical
> workloads. Treat it the way you treat a WAF: **defence in depth, never your
> only control.** Injection detection is best-effort and evadable by a
> determined attacker; false positives and false negatives will occur. A clean
> pass is not evidence of safety. APIs and behaviour may change without notice
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

- **Prompt-injection firewall.** 186 regex patterns across 21 categories
  **plus an on-device ML classifier** (Meta Prompt Guard 2) inspect
  model-visible content, fused into one score with false-positive
  dampeners. Findings are logged in Monitor mode; with Blocking enabled,
  a high-confidence instruction in external content is refused before it
  reaches the provider.
- **Provenance decides the action — this is the whole design.** Bouclier
  splits each request by where the text came from:
  - **Untrusted** — external `tool_result` blocks (Anthropic), `role:
"tool"` messages (OpenAI chat), `function_call_output` items (OpenAI
    Responses), and **retrieved content**: `document` / `search_result`
    blocks and anything wrapped in the `<document>` RAG convention, even
    when it arrives inside a user turn. In Blocking mode, a finding here
    at or above the refusal threshold is **refused** with a `422` naming
    the pattern and JSON path; lower-scoring findings remain visible but
    are allowed.
  - **Attributed local reads** — only a `Read` / `NotebookRead` result linked
    to a canonical, non-vendored path under the active workspace is classified
    as `.authored`; it is inspected and logged, but not blocked in normal mode.
    Missing or ambiguous attribution, downloads, temp/vendor paths, and paths
    outside the workspace stay untrusted. This is not authorship proof:
    Bouclier does not track file taint or write history across requests, so
    attacker-controlled bytes silently saved into an otherwise eligible path
    can receive the authored classification on a later read. Disable authored
    trust or enable managed strict mode to police every tool result.
  - **Principal** — your prompt and your system prompt. They are
    **not rewritten**; when they appear beside inspected tool output they
    may be scored for context, but they cannot trigger a refusal in normal
    mode. Managed strict mode deliberately changes that policy. You are
    allowed to discuss jailbreaks with your own model. Pinned by an
    end-to-end test.
- **Benign context is dampened.** Matches inside security advisories,
  tutorials, quoted payloads, and fenced code are scored down using their
  context. This reduces false refusals but cannot eliminate them; Monitoring
  remains the default, and Blocking users can release a false-positive span
  from the activity feed.
- **Monitor by default, enforce when you opt in.** Out of the box the
  gateway logs detector findings without refusing them, so a false positive
  does not break normal agent work. Transport validation and hard body limits
  still apply. Turn on blocking (per install or via MDM) when you want
  detector-driven refusals.
- **Model-visible content is never rewritten.** The request body is
  forwarded unchanged or the request is refused outright. The gateway
  adjusts only proxy framing (for example `Host` / `Content-Length` and
  hop-by-hop headers). Earlier versions spliced a redaction notice into
  flagged prompts; that broke prompt caching and tripped provider abuse
  detection, and it is gone for good.
- **No certificate to install.** The gateway is a plaintext-loopback →
  TLS-upstream relay, not a TLS-terminating proxy — there's no root CA, no
  system-trust change, and nothing else on your Mac is affected. Detection
  used to require a CA and a System Extension; as of v0.9.0 it doesn't.
- **Local by default.** No accounts or automatic telemetry. An optional
  false-positive report is sent only after you review and submit it.

### What this does not claim

Prompt injection is not solved, and a pattern engine is not a solution to
it. The defences that hold are structural — constraining what a hijacked
agent can reach, keeping untrusted input away from privileged actions.
Bouclier is defence in depth on the untrusted leg: it raises the cost of
the easy attacks and shows you when one arrives. Treat it the way you
treat a WAF, not the way you treat a proof.

Signed release builds **bundle** the on-device ML tier (Meta Prompt Guard 2,
86M) as of v0.9.1 — it runs fully on-device (CoreML, no network), which is the point:
your traffic never leaves the machine to be classified. The tradeoff is a
larger download (~300 MB vs ~6 MB). Even so, Prompt Guard 2 is a small
classifier, not a frontier judge: it lifts recall on novel/multilingual
attacks but is still evadable under adaptive/encoding attacks. The model
is gated (Meta HuggingFace) and produced at release time by
[`apps/desktop/scripts/ensure-model.sh`](apps/desktop/scripts/ensure-model.sh);
it is not committed to the repo. The upstream model
revision, complete conversion environment, and generated runtime files are
pinned and hash-verified before a signed build can include them.

## Quickstart

On an Apple silicon Mac running macOS 15 or later, download the signed DMG
from <https://www.bouclier.ai>, drag the app to `/Applications`, and click
"Enable Protection". Bouclier starts in Monitor mode; choose Blocking in
Settings when you want suspicious requests refused. Open a new terminal to
pick up the environment variables, and compatible agents route through the
gateway automatically. Existing custom provider base URLs are preserved and
continue to bypass Bouclier until you remove or change them.

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
│  Code, SDK, │                   │                        │          │ Anthropic)│
│  curl, …)   │ ◄──────────────── │ ┌────────────────────┐ │ ◄─────── │          │
└─────────────┘  422 when blocked │ │ Injection pass     │ │          └──────────┘
                                  │ │ untrusted → flag/ │ │
                                  │ │  optional block  │ │
                                  │ │  principal → log   │ │
                                  │ └────────────────────┘ │
                                  └────────────────────────┘
```

The injection pass sits behind a cheap trigger gate, so a request with no
untrusted tool output in it bypasses scoring. The gateway never rewrites
the model-visible request body — it forwards those bytes unchanged or
refuses the request.

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
                    186-pattern patterns.json the app compiles. The PII
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
CoreML by
[`apps/desktop/scripts/ensure-model.sh`](apps/desktop/scripts/ensure-model.sh);
the weights are gitignored and
fetched from Meta's gated HuggingFace repo at release time, not committed
— see [ARCHITECTURE.md](ARCHITECTURE.md)). They're governed by the Llama 4
Community License (`LICENSES/Llama-4-Community-License.txt`); see
[NOTICE.txt](NOTICE.txt) for attribution. **Built with Llama.**
