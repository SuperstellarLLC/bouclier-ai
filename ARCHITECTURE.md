# Architecture

This document describes how Bouclier.ai is put together, what each
component does, and the invariants we hold the implementation to. It
complements [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), which
covers what we are defending against.

The intended audience is contributors who want to make a meaningful
change to the gateway, the injection engine, or the persistence layer.

## Process layout

Bouclier.ai has one long-running app process, two on-demand read-only
helpers, and shared on-disk state:

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
│  bouclier-ai.sqlite│
│  (SQLite/GRDB)      │
└────────────────────┘
```

- **`Bouclier`** is a `LSUIElement` menu-bar app. It owns the user-facing
  state — settings, activity log — and runs the loopback gateway
  in-process. Source: `apps/desktop/Sources/Bouclier`.
- **`bouclier-ai.sqlite`** is a SQLite database opened by the app via GRDB. Stores
  per-request metadata (timestamp, host, status) and per-day aggregates.
  **No request body content is written**; the schema only carries
  hash-prefix and count fields.

Two small auxiliary executables ship inside the app bundle. Neither can
change settings or read request content:

- **`bouclier-cli`** — the implementation behind the optional `bouclier`
  command. It reads the app's short-lived `status.json` snapshot.
- **`bouclier-ai-mcp-wrapper`** — a read-only stdio MCP server exposing a
  single `bouclier_status` tool backed by the same snapshot. It reports
  gateway and enforcement state; it does not proxy MCP traffic.

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
sees each request body routed through it in plaintext before re-issuing it
upstream, which is the visibility the detector needs. Clients that do not
honor the configured provider base URL bypass this path entirely.

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
                               │    cheap raw gate for tool_result,
                               │    role:"tool", function_call_output,
                               │    document/search_result blocks, and
                               │    explicit RAG document wrappers.
                               │    No marker ⇒ pass skipped entirely.
                               │  - .inspect: spans split by provenance,
                               │    scored by the live InjectionFilter.
                               │  - untrusted + critical (or fused ≥ .60)
                               │    ⇒ log + forward in Monitor mode
                               │    ⇒ 422 in Blocking mode
                               │  - principal ⇒ any finding is log-only;
                               │    body bytes remain unchanged
                               │  - over 8 MiB ⇒ at most 24 untrusted
                               │    windows sampled off-loop; a clean or
                               │    inconclusive sample is logged as partial
                               │    coverage and forwarded
                               ▼
                           forwardUpstream
                               │  - Re-issued over TLS to the real
                               │    provider. Headers (Authorization,
                               │    x-api-key, custom trace IDs,
                               │    User-Agent) preserved. Host/framing and
                               │    hop-by-hop headers are proxy-normalized.
                               │
outbound HTTPS ◄───────────────┘
```

Inbound response handling:

- The response is relayed verbatim in bounded chunks — no body rewriting or
  whole-response accumulation. `GatewayRelayHandler` writes each upstream
  `ByteBuffer` straight to the client. A 256/512 KiB downstream write
  watermark pauses upstream reads after TLS when a local client falls behind;
  five minutes without nonempty decrypted bytes and a fixed two-hour maximum
  lifetime close both legs. Each downstream connection carries exactly one
  exchange and the upstream request asks the provider to close afterward;
  this bounds retained request memory and keeps request/response provenance
  unambiguous. The gateway never modifies a response.

## Injection inspection

`InjectionInspectionPass` is the gateway's detection hook. Two properties
define it.

**Provenance, not content, decides the action.** The pass parses the
request body and tags every model-visible span:

| Origin       | Source                                                                                                    | Action on detection                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `.untrusted` | External/unattributable tool output, retrieved documents, and RAG wrappers                                | **Monitor:** log + allow. **Blocking:** refuse at/above the threshold; log + allow below it |
| `.authored`  | `Read`/`NotebookRead` positively attributed to a canonical, non-vendored path under the session workspace | **Normal:** log + allow. **Managed strict:** may refuse                                     |
| `.principal` | The operator's prompt text and system prompt                                                              | **Normal:** log only, never rewritten. **Managed strict:** may refuse                       |

Scanning "the prompt" undifferentiated is what makes guardrails unusable:
a developer who pastes an OWASP advisory or types _"ignore previous
instructions"_ into their own agent is the principal, and blocking them
is a false positive by construction. It is also what drove this project's
retreat from text rewriting in v0.6.0. `injectionStrict` (MDM, off by
default) opts a managed fleet into blocking principal text too.

A span is `.untrusted` when it is an external or unattributable
`tool_result` / `role:"tool"` / `function_call_output`, a `document` /
`search_result` block, or text inside a `<document>` RAG wrapper embedded in
an otherwise-principal turn. A linked local `Read`/`NotebookRead` result is
`.authored` only when its canonical path is under a workspace root declared
by one unambiguous recognized system `<env>` metadata block and outside
vendored/download/temp paths;
missing or ambiguous provenance fails closed to `.untrusted`. Other text in a
user/system turn is `.principal`.

`.authored` is a request-local classification, not verified authorship.
Bouclier does not track file taint, writes, or content origin across requests.
If an external payload is silently saved into an otherwise eligible workspace
path, a later linked `Read`/`NotebookRead` can therefore be classified
`.authored`. A fetch is inspected at ingress only when its output itself appears
as supported untrusted content in a routed model request; silent shell writes
cannot be inferred. Managed deployments that need every tool result enforced
must disable `injectionTrustAuthoredReads` or enable `injectionStrict`.

**A cheap independent gate runs first**: a raw substring search for the
untrusted-shape markers. No marker, no JSON parse, no scoring — so ordinary
chat traffic is provably untouched and a bug in the scoring path cannot
corrupt it.

Thresholds: with Blocking enabled, an untrusted span blocks on a
**dampened** fused score ≥ 0.60. In the default Monitor mode, the same
finding is logged and forwarded.
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

**The refusal is a 422, not a 403.** A detector-driven block comes back as
`422 Unprocessable Entity` with a provider-shaped JSON error body naming
the offending span. An unsupported-`Content-Encoding` coverage refusal uses
the same non-retryable status but explicitly says that no detector verdict was
produced and tells the client how to retry. Oversized supported envelopes get
a bounded sample instead: a sampled blocking finding receives the ordinary
detector 422, while a clean or inconclusive sample is forwarded with a visible
partial-coverage record. 401 and 403 are avoided on purpose: Claude Code and
the Anthropic SDK it is built on read both as an authentication failure and
prompt the user to run `/login`, mislabelling a policy refusal as a credential
problem. Retryable statuses (408/409/429/5xx) are avoided too because the
local policy result is deterministic and an SDK retry would loop forever.

## Scope: what we modify and what we don't

**Bouclier never modifies model-visible outbound content.** The request body
is forwarded byte-for-byte or the request is refused outright with a 422.
End-to-end headers such as `Authorization`, `x-api-key`, custom trace IDs,
and `User-Agent` are preserved. As required of an HTTP proxy, Bouclier
rewrites `Host` for the upstream authority, regenerates `Content-Length`,
and removes hop-by-hop and proxy-authentication headers.

The injection pass enforces this: it is a _binary_ control. It never edits
a body, and deliberately ignores `FilterResult.sanitized`, which still
carries the withdrawn v0.2-era rewrite. Enforcement is opt-in — the gateway
defaults to monitor mode (inspect and log without detector-driven refusal), and blocking is enabled
via `FeatureFlags.injectionBlock`. Both invariants are pinned by the E2E
gateway tests: one sends a matching payload as the operator's own prompt
and asserts byte-identical body delivery upstream, another sends poisoned tool
output in monitor mode and asserts it still reaches the upstream.

## Persistence

GRDB-managed SQLite at `~/Library/Application Support/ai.bouclier.app/`:

| Store                 | Purpose                                                   | Retention                            |
| --------------------- | --------------------------------------------------------- | ------------------------------------ |
| `scan_logs`           | Per-request metadata and detector scores; no request body | 30 days                              |
| `daily_stats`         | Day-bucketed counts for the menu bar UI                   | 365 days                             |
| `block-samples.jsonl` | Opt-in flagged excerpts and explanations                  | Newest 100 samples; operator-cleared |

Migrations live in `StorageManager.swift`. Schema changes are forward-only
and use GRDB's `DatabaseMigrator` — no destructive migrations.

## Concurrency model

The gateway itself is `swift-nio` on a `MultiThreadedEventLoopGroup`.
Per-channel handlers keep routing, framing, and state transitions on their
event loop. CPU- and allocation-heavy request inspection runs on one shared,
process-lifetime `NIOThreadPool`, bounded to at most two workers. The channel
hands the worker an immutable `ByteBuffer` snapshot and resumes forwarding or
local refusal on the originating event loop when inspection completes. This
keeps JSON decoding, detector work, and optional block-sample persistence off
the event loop while bounding concurrent large-body allocations. GRDB access
uses its own serialized writer through `StorageManager`.

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

- **No required central service.** There are no accounts, automatic product
  telemetry, or cloud detection dependency. Normal operation forwards routed
  provider traffic and fetches the Sparkle appcast. An administrator may
  configure a SIEM webhook, and a user may explicitly review and submit a
  false-positive report; both are optional and disclosed.
- **No plugin system.** No third-party code execution paths are exposed
  to end users.
- **No routine request-content storage.** Scan/audit rows never contain bodies
  or URIs. The sole local exception is the off-by-default, size-capped block
  sample used for tuning and false-positive review; the setting discloses the
  content capture and the operator can clear it. See the threat model.

## Pointers

- Gateway + request handling: `apps/desktop/Sources/Bouclier/Proxy/GatewayServer.swift`
- Injection inspection (live): `InjectionInspectionPass.swift`, `InjectionFilter.swift`, `EntropyAnalyzer.swift`, `MLClassifier.swift`, `Patterns/PatternManager.swift`
- Pattern source of truth: `packages/patterns/src/` → `apps/desktop/scripts/sync-patterns.sh` → `Sources/Bouclier/Resources/patterns.json`
- Dormant (not in the live request path): `HTTPRequestInspector.inspect`, `SSEStreamInspector.swift`, `ResponseActionInspector.swift`, `PIIScanner.swift`, `MultimodalPIIInspector.swift` and neighbours
- Persistence: `apps/desktop/Sources/Bouclier/Utilities/StorageManager.swift`
