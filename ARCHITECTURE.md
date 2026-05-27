# Architecture

This document describes how Bouclier.ai is put together, what each
component does, and the invariants we hold the implementation to. It
complements [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), which
covers what we are defending against.

The intended audience is contributors who want to make a meaningful
change to the proxy, the detectors, or the persistence layer.

## Process layout

Bouclier.ai is two processes on disk and one shared on-disk state:

```
┌────────────────────────┐        XPC          ┌────────────────────────┐
│  Bouclier (menu bar)   │ ◄────────────────► │  BouclierExtension     │
│  - UI, settings, logs  │                     │  - System Extension    │
│  - Sparkle updater     │                     │  - NEFilterDataProvider│
│  - Pattern compiler    │                     │  - Routes AI hosts to  │
│                        │                     │    the local proxy     │
└─────────┬──────────────┘                     └─────────┬──────────────┘
          │                                              │
          │              ┌────────────────┐              │
          └──────────►   │  audit.db      │   ◄──────────┘
                         │  (SQLite/GRDB) │
                         └────────────────┘
```

- **`Bouclier`** is a `LSUIElement` menu-bar app. It owns the user-facing
  state — settings, pause, activity log, redaction report. It runs the
  TLS proxy in-process and houses every detector. Source: `apps/desktop/Sources/Bouclier`.
- **`BouclierExtension`** is a `NetworkExtension` System Extension that
  redirects flows for the AI-API hosts to `127.0.0.1:<port>` where the
  in-process proxy listens. Source: `apps/desktop/Sources/BouclierExtension`.
- **`audit.db`** is a SQLite database opened by both processes via
  GRDB. Stores per-request metadata (timestamp, host, status, detection
  signals) and per-day aggregates. **No request body content is
  written**; the schema only carries type + offsets + a hash prefix.

Two small auxiliary executables ship alongside:

- **`bouclier-ai-mcp-wrapper`** — a stdio wrapper for Model Context
  Protocol clients that want to route MCP server traffic through the
  same proxy.
- **`bouclier-ai-env`** — a one-shot helper that prints the environment
  variables AI SDKs need to trust the local CA.

## Request lifecycle

The hot path for an outbound LLM request, end to end:

```
inbound CONNECT ─► TLSProxy.HTTPHandler.head
                       │
                       ▼
                   HTTPRequestInspector.inspect (sync, on event loop)
                       │  - URI scan: regex + ML on query params
                       │  - Body scan: regex + ML + entropy fusion
                       │  - Returns InspectionResult { detected, bodyRewritten, sanitizedBody, … }
                       ▼
                   guard policy + flags + body-rewritten:
                       │
                       ▼
                   MultimodalPIIInspector.inspect (async, budgeted)
                       │  - Extract: walks JSON tree + parses multipart
                       │  - Inspect: Vision OCR + faces, PDFKit + Vision,
                       │             SFSpeechRecognizer (on-device)
                       │  - Returns Report { findings, latencyMs, … }
                       ▼
                   MultimodalRewriter.stripFlaggedImages
                       │  - Replaces flagged attachment blocks with a
                       │    plain-English text description; unscannable
                       │    attachments are stripped, never silently
                       │    forwarded
                       ▼
                   forwardUpstream
                       │  - Text bodies forwarded byte-for-byte. Bouclier
                       │    does NOT modify outbound prompts. Headers
                       │    (Authorization, x-api-key, custom trace IDs,
                       │    User-Agent) are forwarded unchanged.
                       │
outbound HTTPS ◄───────┘
```

Inbound response handling:

- `SSEStreamInspector` runs on streaming response chunks to catch
  exfiltration mid-stream.
- Non-SSE responses are relayed verbatim. No body rewriting, no
  buffering, no Content-Length adjustment — the response path is
  effectively zero-copy for the common JSON case.

## Detector stack

Detectors are organised in tiers so the cheap pass runs first:

1. **Regex + structural validators** — `InjectionFilter`, `PIIScanner`,
   `PIIValidators`. Synchronous, deterministic, runs on the proxy's
   event loop. Patterns are compiled at startup from
   `packages/patterns/`.
2. **Native macOS detectors** — `PIINativeDetector` uses
   `NSDataDetector` (phone, address) and other system primitives where
   they beat hand-rolled regex.
3. **Entropy heuristic** — `EntropyAnalyzer` flags high-entropy blobs
   in key-value context as probable secrets even when no provider
   pattern matches.
4. **On-device ML classifiers** — `MLClassifier` runs CoreML inference
   for Meta Llama Prompt Guard 2 (prompt injection) and `PIIClassifier`
   runs Piiranha for PII categories regex can't see (PERSON, USERNAME,
   DOB, licence numbers, …). Models are too large for git; see
   `scripts/convert-*.py` to regenerate.
5. **Multimodal pipeline** — extractor + per-media scanners (image,
   PDF, audio), behind a 30 s wall-clock budget. Apple frameworks
   only; nothing leaves the Mac.

Scores fuse via `FilterResult.fusedScore` so a strong ML signal can
escalate an otherwise-weak regex match and vice versa.

## Scope: what we modify and what we don't

Bouclier touches outbound traffic in exactly two ways:

1. **Prompt-injection blocking.** When the injection scanner matches a
   pattern in the body or URI, the request is rewritten to neutralise
   the payload (or rejected outright when the match is high-severity).
2. **Attachment PII inspection.** When multimodal inspection is enabled
   and an outbound request carries an image / PDF / audio attachment
   containing PII, the attachment's content block is replaced with a
   plain-English description ("This image contained an email address
   and was removed by Bouclier"). The model receives normal text and
   can still answer; the cleartext attachment never leaves the Mac.

Everything else is forwarded byte-for-byte. **Bouclier does not modify
text prompt bodies.** Earlier versions ran a reversible PII tokeniser
on prompts — that was removed in v0.6 because (a) the placeholder
shape tripped Anthropic's abuse heuristics and (b) the JSON-blind
rewriter risked touching `user`, `metadata.user_id`, and other
provider analytics fields. The header set (Authorization, x-api-key,
custom trace IDs, User-Agent, …) is also never modified. The
no-modification invariant is pinned by `E2EProxyTests`.

## Persistence

GRDB-managed SQLite at `~/Library/Application Support/ai.bouclier.app/`:

| Table              | Purpose                                                    | Retention |
| ------------------ | ---------------------------------------------------------- | --------- |
| `request_log`      | Per-request metadata, detection signals, hash prefix       | 30 days   |
| `daily_stats`      | Day-bucketed counts for the menu bar UI                    | 365 days  |
| `pii_redactions`   | Per-finding `{type, hash}` rows for PII inside attachments | 30 days   |
| `multimodal_audit` | Per-attachment `{kind, status, latency}` rows              | 30 days   |

Migrations live in `StorageManager.swift`. Schema changes are forward-only
and use GRDB's `DatabaseMigrator` — no destructive migrations.

## Concurrency model

The proxy itself is `swift-nio` on a `MultiThreadedEventLoopGroup`.
Per-channel handlers stay on the event loop for the hot synchronous
work (CONNECT parsing, regex, header rewriting). Anything async
(ML inference, multimodal, GRDB writes) hops into Swift Concurrency
with `Task { … } in eventLoop.execute { … }`.

We compile with **Swift 6 strict-concurrency**. Types crossing isolation
boundaries are `Sendable`. Where the underlying framework predates
`Sendable`, we wrap with `@unchecked Sendable` and document the
invariant. The pattern is consistent across the proxy: any new
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
  service. The proxy is a single binary, and its only network calls
  are forwarding user traffic, fetching the Sparkle appcast, and (if
  enterprise-configured) sending SIEM webhooks.
- **No plugin system (yet).** Detectors are statically compiled in.
  Hot-reloading patterns is gated behind a feature flag and used in
  development; we don't expose third-party code execution paths to
  end users.
- **No request-content storage.** This is a hard invariant — see the
  threat model. Any PR that adds logging or persistence of cleartext is
  held to it in review.

## Pointers

- Request inspection pipeline: `apps/desktop/Sources/Bouclier/Proxy/HTTPRequestInspector.swift`
- TLS interception + connection handlers: `apps/desktop/Sources/Bouclier/Proxy/TLSProxy.swift`, `CertificateAuthority.swift`
- Multimodal pipeline: `MultimodalPIIInspector.swift`, `MultimodalImageExtractor.swift`, `MultimodalRewriter.swift`, `MultipartMediaScanner.swift`, `MediaPIIScanner.swift`, `PDFPIIScanner.swift`, `AudioPIIScanner.swift`
- Patterns: `packages/patterns/src/`
- Persistence: `apps/desktop/Sources/Bouclier/Utilities/StorageManager.swift`
- System Extension: `apps/desktop/Sources/BouclierExtension/`
