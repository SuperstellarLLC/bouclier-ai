# Architecture

This document describes how Bouclier.ai is put together, what each
component does, and the invariants we hold the implementation to. It
complements [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), which
covers what we are defending against.

The intended audience is contributors who want to make a meaningful
change to the gateway, the injection engine, or the persistence layer.

## Process layout

Bouclier.ai is a single process on disk plus shared on-disk state:

```
┌────────────────────────┐
│  Bouclier (menu bar)   │
│  - UI, settings, logs  │
│  - Sparkle updater     │
│  - Loopback gateway    │
└─────────┬──────────────┘
          │
          ▼
┌────────────────────┐
│  audit.db          │
│  (SQLite/GRDB)      │
└────────────────────┘
```

- **`Bouclier`** is a `LSUIElement` menu-bar app. It owns the user-facing
  state — settings, activity log — and runs the loopback gateway
  in-process. Source: `apps/desktop/Sources/Bouclier`.
- **`audit.db`** is a SQLite database opened by the app via GRDB. Stores
  per-request metadata (timestamp, host, status) and per-day aggregates.
  **No request body content is written**; the schema only carries
  hash-prefix and count fields.

A small auxiliary executable ships alongside:

- **`bouclier-ai-mcp-wrapper`** — a stdio wrapper for Model Context
  Protocol clients that want to route MCP server traffic through the
  same gateway.

## What was removed

Earlier versions ran two proxy modes: **standard** (the loopback
base-URL gateway described below) and **extreme** — a CA-based
TLS-terminating proxy (`TLSProxy`) paired with a `NETransparentProxyProvider`
System Extension (`BouclierExtension`) that redirected AI-host traffic to
it system-wide. Extreme mode was removed entirely: no CA is generated or
installed, no System Extension ships, and there is no system-wide network
filter. The gateway is now the only proxy path.

Extreme mode was also, until v0.9.0, the only thing that ever called the
prompt-injection detection engine (`PatternManager`, `InjectionFilter`,
`MLClassifier`). That coupling was an accident of how the engine was
first wired, not a technical requirement: the loopback gateway already
sees every request body in plaintext before re-issuing it upstream, which
is all the visibility detection ever needed.

**As of v0.9.0 the injection engine is live again, on the gateway.**
`InjectionInspectionPass` (`Sources/Bouclier/Proxy/`) is the caller —
see "Injection inspection" below. Nothing about the CA or the System
Extension came back; they remain removed.

Still dormant, with no caller on the live path:

- The **PII tier** — `PIIScanner`, `PIIClassifier`, `PIINativeDetector`
  and the multimodal image/PDF/audio scanners. Text-prompt PII rewriting
  was withdrawn in v0.6.0 for cause (it tripped provider abuse
  detection); the attachment path went with extreme mode in v0.7.0. The
  code still compiles and its unit tests exercise it directly.
- `HTTPRequestInspector.inspect(...)` and `SSEStreamInspector` — the
  extreme-mode inspection entry points. Note that both, and
  `InjectionFilter.scan`'s own `sanitized` output, implement the old
  **rewrite** behaviour: matched spans replaced with a redaction notice,
  and on an ML/entropy-only hit the _entire_ body replaced with that
  notice. `InjectionInspectionPass` deliberately ignores `sanitized` and
  never mutates a body — the gateway forwards unmodified or refuses. Do
  not reintroduce the rewrite path without revisiting v0.6.0's reasoning.

Installs that had extreme mode active before this removal are migrated
automatically on first launch of the new version
(`ProxyManager.migrateAwayFromExtremeModeIfNeeded`): the CA is uninstalled
from Keychain, the System Extension is deactivated, and any stale PAC
configuration is swept. `CertificateAuthority` and `ExtensionManager` were
stripped down to cleanup-only remnants for exactly this purpose — see
their doc comments.

## Request lifecycle

The hot path for an outbound LLM request, end to end:

```
inbound HTTP (loopback) ─► GatewayServer.GatewayHandler
                               │
                               ▼
                           Route resolution (GatewayRoute.resolve)
                               │  - path prefix / auth-header sniff
                               │    decides Anthropic vs OpenAI
                               ▼
                           Injection inspection
                               │  - InjectionInspectionPass.hasTrigger:
                               │    raw substring scan for tool_result /
                               │    role:"tool" / function_call_output.
                               │    No marker ⇒ pass skipped entirely.
                               │  - .inspect: spans split by provenance,
                               │    scored by the live InjectionFilter.
                               │  - untrusted + critical (or fused ≥ .60)
                               │    ⇒ 403, request never leaves the box
                               │  - principal ⇒ logged, forwarded as-is
                               ▼
                           forwardUpstream
                               │  - Re-issued over TLS to the real
                               │    provider. Headers (Authorization,
                               │    x-api-key, custom trace IDs,
                               │    User-Agent) forwarded unchanged.
                               │
outbound HTTPS ◄───────────────┘
```

Inbound response handling:

- The response is relayed verbatim — no body rewriting, no buffering.
  Zero-copy: `GatewayRelayHandler` streams upstream bytes straight back to
  the client, keep-alive preserved. The gateway never modifies a response.

## Injection inspection

`InjectionInspectionPass` is the gateway's detection hook. Two properties
define it.

**Provenance, not content, decides the action.** The pass parses the
request body and tags every model-visible span:

| Origin       | Source                                                                      | Action on detection                            |
| ------------ | --------------------------------------------------------------------------- | ---------------------------------------------- |
| `.untrusted` | `tool_result` blocks, `role: "tool"` messages, `function_call_output` items | **Refuse** — 403, request never leaves the box |
| `.principal` | the operator's prompt text and system prompt                                | **Log only** — forwarded byte-for-byte         |

Scanning "the prompt" undifferentiated is what makes guardrails unusable:
a developer who pastes an OWASP advisory or types _"ignore previous
instructions"_ into their own agent is the principal, and blocking them
is a false positive by construction. It is also what drove this project's
retreat from text rewriting in v0.6.0. `injectionStrict` (MDM, off by
default) opts a managed fleet into blocking principal text too.

A span is `.untrusted` when it is a `tool_result` / `role:"tool"` /
`function_call_output`, a `document` / `search_result` block, or text
inside a `<document>` RAG wrapper embedded in an otherwise-principal
turn — retrieved content the operator did not author. Everything else in
a user/system turn is `.principal`.

**A cheap independent gate runs first**: a raw substring search for the
untrusted-shape markers. No marker, no JSON parse, no scoring — so ordinary
chat traffic is provably untouched and a bug in the scoring path cannot
corrupt it.

Thresholds: an untrusted span blocks on a **dampened** fused score ≥ 0.60.
The fused score is `regex 0.50 + ML 0.40 + entropy 0.10` with a
strong-signal short-circuit at 0.85, and false-positive dampeners
(OWASP/tutorial/quoted/fenced-code context) multiply the regex weight
down — so a genuine critical match short-circuits to a block while the
same phrase inside benign context is flagged-and-forwarded. As of v0.9.1
the on-device ML tier (Prompt Guard 2) is bundled and contributes to the
score, so an untrusted span can also block on model confidence alone
(≥ 0.85), catching novel/multilingual attacks the regex set misses.
Fail-open throughout — if `InjectionFilter.active.current()` is nil
because the engine hasn't loaded, requests forward unmodified, per the
v0.5.2 rule that Bouclier being unavailable must never break the user's
agent.

## Scope: what we modify and what we don't

**Bouclier never modifies outbound traffic.** A request is forwarded
byte-for-byte — including the full header set (`Authorization`, `x-api-key`,
custom trace IDs, `User-Agent`, …) — or refused outright with a 403. There
is no rewrite path.

The injection pass enforces this: it is a _binary_ control. It never edits
a body, and deliberately ignores `FilterResult.sanitized`, which still
carries the withdrawn v0.2-era rewrite. Enforcement is opt-in — the gateway
defaults to monitor mode (inspect, log, forward), and blocking is enabled
via `FeatureFlags.injectionBlock`. Both invariants are pinned by the E2E
gateway tests: one sends a matching payload as the operator's own prompt
and asserts byte-identical delivery upstream, another sends poisoned tool
output in monitor mode and asserts it still reaches the upstream.

## Persistence

GRDB-managed SQLite at `~/Library/Application Support/ai.bouclier.app/`:

| Table         | Purpose                                 | Retention |
| ------------- | --------------------------------------- | --------- |
| `request_log` | Per-request metadata, hash prefix       | 30 days   |
| `daily_stats` | Day-bucketed counts for the menu bar UI | 365 days  |

Migrations live in `StorageManager.swift`. Schema changes are forward-only
and use GRDB's `DatabaseMigrator` — no destructive migrations.

## Concurrency model

The gateway itself is `swift-nio` on a `MultiThreadedEventLoopGroup`.
Per-channel handlers stay on the event loop for the hot synchronous
work (routing, injection inspection). GRDB writes hop into
Swift Concurrency with `Task { … } in eventLoop.execute { … }`.

We compile with **Swift 6 strict-concurrency**. Types crossing isolation
boundaries are `Sendable`. Where the underlying framework predates
`Sendable`, we wrap with `@unchecked Sendable` and document the
invariant. The pattern is consistent across the gateway: any new
handler should follow the existing convention rather than introduce a
new isolation model.

## Update channel

Releases are distributed via the [Sparkle](https://sparkle-project.org/)
framework. The appcast is hosted on `bouclier.ai` and signed with an
Ed25519 key. Updates require the user to approve before installing. The
update path is documented at length in `scripts/release.sh` and
`scripts/publish-update.sh`.

## What we deliberately keep simple

- **No central server.** No accounts, telemetry, or cloud detection
  service. The gateway is a single binary, and its only network calls
  are forwarding user traffic and fetching the Sparkle appcast.
- **No plugin system.** No third-party code execution paths are exposed
  to end users.
- **No request-content storage.** This is a hard invariant — see the
  threat model. Any PR that adds logging or persistence of cleartext is
  held to it in review.

## Pointers

- Gateway + request handling: `apps/desktop/Sources/Bouclier/Proxy/GatewayServer.swift`
- Injection inspection (live): `InjectionInspectionPass.swift`, `InjectionFilter.swift`, `EntropyAnalyzer.swift`, `MLClassifier.swift`, `Patterns/PatternManager.swift`
- Pattern source of truth: `packages/patterns/src/` → `apps/desktop/scripts/sync-patterns.sh` → `Sources/Bouclier/Resources/patterns.json`
- Dormant (not in the live request path): `HTTPRequestInspector.inspect`, `SSEStreamInspector.swift`, `PIIScanner.swift`, `MultimodalPIIInspector.swift` and neighbours
- Persistence: `apps/desktop/Sources/Bouclier/Utilities/StorageManager.swift`
