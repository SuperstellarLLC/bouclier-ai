# Bouclier.ai Threat Model

**Status:** v3 (rewritten following the removal of the secret keeper)
**Scope:** Bouclier.ai macOS menubar app + loopback gateway + on-device prompt-injection inspection. Covers the request path from an AI client's local SDK call, through the gateway, to the upstream AI provider.
**Audience:** Bouclier.ai engineering, security reviewers, third-party auditors.

This document enumerates the assets, trust boundaries, adversaries, and
mitigations of Bouclier.ai. It uses the STRIDE taxonomy (Spoofing,
Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege) and cross-references existing code paths and
test coverage.

**What changed from v2.** v2 covered two features: the prompt-injection
firewall and a "secret keeper" that scrubbed managed credential values
out of outbound requests and restored them in the response. The secret
keeper has been **removed** — no `SecretStore`, no Keychain-backed secret
values, no scrub/restore, no agent-facing secret-request IPC. The gateway
now preserves model-visible request-body bytes: its policy action is to
inspect a request for prompt injection and either forward that body
unchanged or refuse the request. Proxy routing/framing headers are normalized
as described below. This document is a from-scratch threat model of that gateway.

**Earlier removal (v1 → v2):** Bouclier previously shipped a CA-based
TLS-terminating "extreme mode" paired with a system
`NETransparentProxyProvider`. That was removed too — no CA, no System
Extension, no system-wide network filter. The **PII** tier (`PIIScanner`,
`PIIClassifier`, the multimodal scanners) remains in the tree but is not
reachable from the live request path and stays out of scope — see
`ARCHITECTURE.md`'s "What was removed" section.

---

## 1. System overview

```
┌──────────────────────────────┐
│  AI client / agent           │   (Claude Code, compatible SDKs, curl, …)
└──────────────┬───────────────┘
               │  HTTP (plaintext, loopback only)
               ▼
┌──────────────────────────────┐
│ Bouclier.ai menubar app (host)  │
│  - GatewayServer (swift-nio) │   (127.0.0.1 bind; never 0.0.0.0)
│  - InjectionInspectionPass   │   (untrusted-span detection, refuse-or-forward)
│  - InjectionFilter / PatternManager │ (shipped pattern set + optional CoreML tier)
│  - StorageManager (GRDB)     │   (app-support SQLite, WAL; metadata only)
│  - AuditLogger               │   (os_log + optional webhook)
│  - StatusPublisher           │   (read-only status.json for CLI + MCP helper)
└──────────────┬───────────────┘
               │  HTTPS (client TLS to the real provider)
               ▼
┌──────────────────────────────┐
│  Upstream AI provider        │   (api.openai.com, api.anthropic.com, …)
└──────────────────────────────┘
```

The gateway is reached only by setting `ANTHROPIC_BASE_URL` /
`OPENAI_BASE_URL` to `http://127.0.0.1:<port>`
— there is no transparent, system-wide redirection. A process that
doesn't point at the gateway simply talks to the provider directly and
is entirely outside Bouclier's reach; this is a deliberate scope
reduction, not an oversight — see §4.

### 1.1 Assets

| #   | Asset                                            | Sensitivity                  |
| --- | ------------------------------------------------ | ---------------------------- |
| A1  | User prompts & chat completions (in flight)      | Confidential                 |
| A2  | SQLite scan log (`bouclier-ai.sqlite`, metadata) | Confidential                 |
| A3  | Opt-in flagged excerpts (`block-samples.jsonl`)  | Confidential                 |
| A4  | Audit webhook URL and bearer (if MDM-configured) | Confidential                 |
| A5  | Sparkle update feed signing keys (EdDSA)         | Critical                     |
| A6  | Code-signing identity + notarization credentials | Out of scope (Apple-managed) |

### 1.2 Trust boundaries

1. **Local process ↔ gateway** — any local process can dial
   `127.0.0.1:<port>`; the gateway has no allowlist of which local
   processes may connect (there's no system-level redirection to police
   this — see §4's accepted risk). A DNS-rebinding guard
   (`GatewayWire.isLoopbackHostHeader`) rejects requests whose `Host`
   header isn't a loopback literal, closing the "malicious webpage POSTs
   to 127.0.0.1" variant of this boundary.
2. **Gateway ↔ upstream AI provider** — client TLS, full certificate
   verification (`certificateVerification = .fullVerification`), pinned
   to HTTP/1.1 upstream so header casing survives.
3. **Gateway ↔ disk** (SQLite) — Application Support directory,
   user-scoped perms. Metadata only — never request bodies.
4. **Gateway ↔ Sparkle update feed** — HTTPS + EdDSA signature.
5. **Gateway ↔ optional MDM webhook** — only configured via managed
   profile, never user input.

### 1.3 Adversary profiles

| ID  | Actor                                          | Capabilities                                                                             |
| --- | ---------------------------------------------- | ---------------------------------------------------------------------------------------- |
| T1  | Prompt-injected / misbehaving agent            | Untrusted tool output carries instructions aimed at the model; the agent may act on them |
| T2  | Malicious local app (same user)                | Can open sockets to `127.0.0.1:<port>`, read user files w/o TCC                          |
| T3  | Co-resident malware w/ admin                   | Can install launchd agents                                                               |
| T4  | MITM on coffee-shop Wi-Fi                      | Full L3/4 interception between the gateway and the upstream provider, can spoof DNS      |
| T5  | Hostile upstream AI provider                   | Returns attacker-chosen content in responses                                             |
| T6  | Malicious MDM administrator                    | Pushes hostile config profiles                                                           |
| T7  | Malicious webpage (via a browser-driven agent) | Can attempt DNS-rebinding style requests to `127.0.0.1:<port>`                           |

---

## 2. STRIDE analysis

### 2.1 Spoofing

| S1 | **Fake upstream provider via DNS hijack / rogue CA.** Attacker poisons DNS or installs a rogue root on the Mac, replies to `api.openai.com`. | `GatewayServer.connectToUpstream` pins with `certificateVerification = .fullVerification` in `NIOSSLContext`. Real-world mitigation depends on the user/enterprise not having rogue roots. |
| S2 | **DNS-rebinding: malicious webpage resolves a hostname to `127.0.0.1` and POSTs to the gateway.** | `GatewayWire.isLoopbackHostHeader` rejects any request whose `Host` header isn't a loopback literal (`127.0.0.1`, `localhost`, `::1`) with `421 Misdirected Request`. |
| S3 | **Forged Sparkle update.** | Sparkle EdDSA signature on appcast items. |

### 2.2 Tampering

| T1 | **Tampering with the SQLite scan log.** A co-resident process with the same user could rewrite the WAL file. | GRDB WAL file under `~/Library/Application Support/ai.bouclier.app/`. A configured SIEM webhook provides an external structured-event mirror; without one, the local database is not tamper-evident against same-user malware. |
| T2 | **Tampering with a request body in flight to hide an injection.** | The gateway forwards model-visible body bytes unchanged or refuses the request. Inspection reads the body and returns a decision only; it has no content-mutation path. The proxy separately normalizes `Host`, framing, hop-by-hop, and proxy-authentication headers. |

### 2.3 Repudiation

| R1 | **User denies a request was inspected/blocked.** | On-disk aggregate stats count completed inspections. Blocks, Monitoring findings, and inspection skips are shown in the activity feed and written to `os_log`; clean inspected requests are intentionally not added to either. Ordinary detector blocks can also be mirrored to the optional enterprise SIEM webhook. Coverage-limit and Monitoring-only events currently remain local, so SIEM is not a complete audit trail. None of these local records is tamper-evident against a same-user process (T1). |
| R2 | **Diagnostic bundle tampered before submission.** | Diagnostics export is JSON, not signed. Out of scope for this version; follow-up: add an EdDSA signature over `DiagnosticsExport.Bundle`. |

### 2.4 Information disclosure

| I1 | **Prompt/response bodies persisted to disk.** | Routine scan logs **never contain request bodies or URIs** — only metadata (host, byte counts, event kind). The explicit, off-by-default “Capture blocked content for tuning” setting is the sole exception: it stores a capped flagged excerpt and classifier window in `block-samples.jsonl`, keeps at most 100 samples, is disclosed in Settings, and can be cleared locally. Responses are never persisted. |
| I2 | **Webhook URL leak via diagnostics bundle.** | `DiagnosticsExport` does not include the webhook URL. Only structured metrics + logs. |
| I3 | **Header fidelity leaks credentials to the wrong upstream.** | Production origins are fixed to `api.openai.com` and `api.anthropic.com`. Routes match exact or slash-delimited API segments rather than raw prefixes. Every `Authorization` and `x-api-key` field contributes provider evidence; mixed Anthropic/OpenAI evidence — including duplicate or combined fields — is rejected before connecting. Each downstream connection then accepts one request, constructs one exact upstream host-and-port authority, and sends `Connection: close`, so a later request cannot reuse a credential-bearing connection for another provider. |

### 2.5 Denial of service

| D1 | **Oversized request body** — OOM via multi-GB payload. | `GatewayHandler.channelRead` enforces `HTTPRequestInspector.maxBodyBytes` (64 MiB) during body accumulation, returning `413 Payload Too Large` on overflow. Full inspection is capped at 8 MiB, which covers the serialized envelope of typical 1M-token text sessions. Above that bound, a linear structural gate runs on a two-thread worker pool. Valid envelopes with a supported untrusted shape receive an evenly distributed sample of at most 24 detector windows; a sampled blocking finding is enforceable, while a clean or inconclusive sample is forwarded with a visible/audited partial-coverage warning in either product mode. Large requests without a supported shape also remain fail-open and visibly uninspected. |
| D2 | **Event-loop or heap saturation via many simultaneous connections.** | `GatewayServer.start()` binds on `127.0.0.1` only (no remote attack surface), admits at most 32 live downstream channels process-wide, limits each connection to one request and each body to 64 MiB, and caps aggregate retained raw request bodies at 128 MiB before buffering or queueing inspection. Saturation receives a deterministic `503`; body reservations remain charged through inspection and upstream-write completion even if the client disconnects. Inspection runs on a shared two-thread pool. Response relay uses a 256/512 KiB downstream write watermark to pause/resume upstream reads after TLS setup, a five-minute read-idle timeout that resets on streamed bytes, and a two-hour absolute response lifetime. A same-user process can still consume the finite connection/body allowance and temporarily deny service, but cannot turn accepted work into unbounded gateway memory growth. |
| D3 | **Upstream unreachable / slow.** | TCP setup has a ten-second deadline and setup failures return an honest `502 Bad Gateway`. Once connected, five minutes without nonempty decrypted response bytes closes both legs; streamed bytes reset that idle deadline, while the independent two-hour maximum lifetime remains fixed. A timeout after raw response bytes have begun closes the stream instead of corrupting it with a second HTTP status. |

### 2.6 Elevation of privilege

| E1 | **Agent turns off the firewall that guards it.** | The bundled product surfaces are read-only: the `bouclier` CLI exposes status plus a print-only install helper, and the MCP server exposes only `bouclier_status`. This is not a same-user tamper boundary. An agent with ordinary shell/process control can still kill the app, unset or bypass the base URL, or alter unmanaged preferences. Managed deployments must pair Bouclier's in-app continuity locks with endpoint policy that restricts those operations. |
| E2 | **Local LPE via the gateway.** | The gateway runs as the user, binds loopback only, and performs no privileged operation on the request path (no CSR/cert-issuance flow — that existed only for the removed extreme mode's CA). |

### 2.7 Injection inspection (the primary control)

The pass is a _detector_, and detectors are evadable. The threats worth
enumerating are mostly about what a failure does, not whether one occurs.
Enforcement is **opt-in**: the gateway defaults to monitor mode, where a
detector finding is logged but does not itself refuse the request. Ordinary
HTTP failures, the 64 MiB transport ceiling, and upstream errors still apply.
Blocking is enabled via `injectionBlock`.

| ID  | Threat                                                                          | Mitigation / accepted position                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| J1  | **Evasion — a crafted payload in tool output is not matched.**                  | Accepted and expected; see §4. Normalization (NFKC, homoglyph folding, zero-width stripping) raises the bar on the cheap obfuscations, and 186 patterns cover the published families, but an adaptive attacker wins. Detection is defence in depth on the untrusted leg, never the sole control.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| J2  | **False positive refuses legitimate work.**                                     | Bounded by design: monitor mode (the default) never blocks, and in normal blocking mode only `.untrusted` spans can cause a refusal. The operator's own prompt cannot trigger a normal-mode refusal, so the classic guardrail failure — blocking a security engineer discussing attacks — is avoided. Pinned by `principalPromptNeverFiltered`. Provenance tiering (`injectionTrustAuthoredReads`, default on) extends that availability policy to a `tool_result` positively linked to `Read`/`NotebookRead` of an eligible non-vendored workspace path. This request-local `.authored` classification is not proof that the developer wrote the file; its accepted taint/history limitation is explicit in J8. Managed fleets can opt into `injectionStrict`, which deliberately removes the principal/authored exception and accepts the resulting availability tradeoff.                                                                                                                                                                                                                                                                                                            |
| J3  | **The pass corrupts an ordinary request.**                                      | Structurally prevented. `hasTrigger` is an independent raw-byte gate: no untrusted marker ⇒ the pass never runs. And the pass has no mutation path at all — it returns a decision, never a body. The gateway forwards model-visible body bytes unchanged or refuses.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| J4  | **A refused request leaks the payload upstream anyway.**                        | Inspection runs _before_ any upstream connection is opened; a refusal returns locally. Pinned by `blocksInjectionArrivingAsToolOutput`, which asserts the upstream recorder saw nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| J5  | **Detector becomes the attack surface** — ReDoS via a pathological tool result. | Each detector invocation is capped at `maxSpanScanChars` (64 KiB); longer spans are covered end-to-end by bounded overlapping windows under the 8 MiB full-inspection ceiling. Regex/entropy inspect every window there, while CoreML is sampled evenly across at most 24 windows per request. The pattern set was ReDoS-audited. Above the ceiling, JSON extraction is confined to the bounded worker pool and regex/entropy/ML work is capped to an evenly distributed 24-window sample as described in D1.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| J6  | **Silent engine failure — patterns fail to load and nothing detects.**          | This has happened before: a stale `patterns.json` and an ICU-incompatible regex both silently shrank the live set. `bundledPatternsCompile` now fails the build if any pattern fails to compile or the count regresses; the menu bar surfaces the live pattern count. Fail-open is deliberate (J7) but must be _visible_.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| J7  | **Fail-open leaves traffic unprotected.**                                       | Accepted. If the engine hasn't loaded, requests forward unmodified rather than break the user's agent. A firewall that bricks Claude Code when it can't load a regex file will be uninstalled, and an uninstalled firewall protects nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| J8  | **Request-local authored attribution admits attacker-planted local content.**   | Accepted trade for J2, with a fail-closed attribution boundary. A `tool_result` is classified `.authored` only when linked (via `tool_use_id`) to `Read`/`NotebookRead` of an **absolute, standardized, symlink-resolved** path that is both (a) outside the vendored/download/temp denylist (`node_modules`, `vendor`, `Downloads`, `tmp`, …) and (b) **under a canonical session workspace root**. The root must come from exactly one recognized system `<env>` metadata block; duplicate, conflicting, unscoped, malformed, or root-filesystem declarations are rejected. Missing or ambiguous provenance remains `.untrusted`. This is not file-origin proof: Bouclier does **not** track taint, writes, or content history across requests. An attacker-controlled payload silently written into an otherwise eligible workspace path can be classified `.authored` by a later linked read. An earlier fetch is inspected only when its output itself appeared as supported untrusted content in a routed model request; shell redirects and other silent writes cannot be inferred. Set `injectionTrustAuthoredReads` off (or `injectionStrict` on) to police every tool result. |

---

## 3. Defense-in-depth summary

| Layer                | Mechanism                                                                                                                                    |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Network boundary     | 127.0.0.1-only bind; no system-wide redirection                                                                                              |
| Request parsing      | NIO `HTTPRequestDecoder`, body cap, DNS-rebinding `Host` guard                                                                               |
| Injection inspection | Trigger-gated `InjectionInspectionPass`, provenance tiering (principal / authored / untrusted), refuse-or-forward                            |
| Engine integrity     | Patterns are count/sync checked; Prompt Guard source, toolchain, and runtime files are pinned and hash-verified; live tier health is visible |
| Upstream routing     | Production origins pinned to OpenAI/Anthropic; exact path segments; contradictory provider credentials rejected                              |
| Cross-host safety    | One exchange per downstream/upstream connection; exact host-and-port authority gate                                                          |
| Storage              | User-scoped SQLite with metadata only; optional capped block samples are disclosed and off by default                                        |
| Observability        | os_log + optional MDM webhook + in-memory metrics actor                                                                                      |
| Updates              | Sparkle EdDSA-signed appcast; packaged resources, dependencies, and portable runtime links are verified before signing                       |
| Code signing         | Developer ID + notarization; bundle integrity via Gatekeeper                                                                                 |

---

## 4. Accepted risks

- **Root-level malware** can tamper with any Mac app; Bouclier.ai does
  not claim protection against this tier.
- **The gateway is opt-in per process**, not system-wide. Any process
  that doesn't set `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` (or isn't
  captured by `ShellEnvInjector`'s dotfile/launchctl wiring) bypasses
  Bouclier entirely and is outside its reach. This is a deliberate
  trade-off: no CA, no System Extension, and no ability to see traffic
  from a process that doesn't voluntarily route through the gateway.
- **Prompt-injection detection is evadable and always will be.** The
  pattern engine catches published attack families and the cheap
  obfuscations around them. It does not stop an attacker who is adapting
  to it, and no deployed detector does — the 2026 consensus is that the
  defences that hold are structural (constraining what a hijacked agent
  can reach), not classificatory. Bouclier raises attacker cost and makes
  an arriving attack visible. Anyone treating a clean pass as evidence of
  safety has misunderstood the control.
- **Detection sees only what crosses the gateway.** Injected content that
  reaches the model by any other route — a process not pointed at the
  gateway, an attachment, content the agent summarises before sending —
  is not inspected.
- **Monitor mode is the default.** Out of the box the gateway logs but does
  not block; a fleet that wants prevention opts into `injectionBlock` (per
  install or via MDM). A monitor-mode install detects and records but does
  not stop an injection.
- **User manually disabling the gateway** is a legitimate action.
  Enforcement requires MDM configuration profile + compliance tooling.
- **Diagnostics bundle tampering in transit** before reaching support —
  not signed.

---

## 5. Follow-ups

- [ ] Sign `DiagnosticsExport.Bundle` with the Sparkle EdDSA key for tamper-evident support handoff.
- [ ] Expand protocol fuzzing for the read-only MCP status server.
