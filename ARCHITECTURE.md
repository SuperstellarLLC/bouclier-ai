# Architecture

This document describes how Bouclier.ai is put together, what each
component does, and the invariants we hold the implementation to. It
complements [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), which
covers what we are defending against.

The intended audience is contributors who want to make a meaningful
change to the gateway, the secret keeper, or the persistence layer.

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

Extreme mode was also the only thing that ever called the prompt-injection
and PII detection engine (`PatternManager`, `InjectionFilter`,
`MLClassifier`, the multimodal image/PDF/audio scanners under
`Sources/Bouclier/Proxy/`) — the loopback gateway never did and still
doesn't invoke any of it. Rather than delete that engine outright, it was
left in the tree, unmodified and dormant: it still compiles, its unit
tests still exercise it directly, and it remains available if
destination-bound detection is ever wired into the gateway as a
deliberate follow-up. It is not part of the request path today and
nothing in the shipped product currently uses it. The same applies to
`SecretInjectionPass` — destination-bound secret injection into a
third-party host, which only ever ran through `TLSProxy`. `SecretRule`
still validates and stores host bindings, but nothing currently acts on
them; only scrub→restore (below) is live.

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
                           Secret scrub (if secrets configured)
                               │  - SecretRedactionPass.apply: managed
                               │    real values → placeholders
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

- When secrets are configured, `GatewayRestoreHandler` restores
  placeholder→real value in the response body (straddle-safe across
  chunk boundaries) so the agent's local tool calls see the real value.
  This changes the response framing to connection-close (Content-Length
  can't be known in advance), so keep-alive is only available on
  connections with no secrets configured.
- With no secrets configured, the response is relayed verbatim — no body
  rewriting, no buffering. Zero-copy for the common case.

## Scope: what we modify and what we don't

Bouclier touches outbound traffic in exactly one way: **secret scrub**.
When a managed secret's real value appears in a request bound for the
model provider, it's replaced with its placeholder before the request
leaves the gateway; the matching response is restored so local tooling
still works. Everything else is forwarded byte-for-byte, including the
header set (`Authorization`, `x-api-key`, custom trace IDs, `User-Agent`,
…). **Bouclier does not modify prompt bodies beyond secret placeholders.**
The no-modification invariant (outside the scrub/restore path) is pinned
by the E2E gateway tests.

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
work (routing, header rewriting, secret scrub). GRDB writes hop into
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
- Secret scrub/restore: `SecretRedactionPass.swift`, `SecretRestore.swift`, `SecretRule.swift`, `SecretStore.swift`
- Dormant detection engine (not in the live request path): `HTTPRequestInspector.swift`, `InjectionFilter.swift`, `MLClassifier.swift`, `MultimodalPIIInspector.swift` and neighbors
- Persistence: `apps/desktop/Sources/Bouclier/Utilities/StorageManager.swift`
