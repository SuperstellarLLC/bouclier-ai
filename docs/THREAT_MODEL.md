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
is now a byte-faithful transparent relay whose only action is to inspect
each request for prompt injection and either forward it unmodified or
refuse it. This document is a from-scratch threat model of that gateway.

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
│  AI client / agent           │   (Claude Code, Cursor, curl, …)
└──────────────┬───────────────┘
               │  HTTP (plaintext, loopback only)
               ▼
┌──────────────────────────────┐
│ Bouclier.ai menubar app (host)  │
│  - GatewayServer (swift-nio) │   (127.0.0.1 bind; never 0.0.0.0)
│  - InjectionInspectionPass   │   (untrusted-span detection, refuse-or-forward)
│  - InjectionFilter / PatternManager │ (161 patterns + optional CoreML tier)
│  - StorageManager (GRDB)     │   (app-support SQLite, WAL; metadata only)
│  - AuditLogger               │   (os_log + optional webhook)
│  - StatusPublisher           │   (read-only status.json for the CLI)
└──────────────┬───────────────┘
               │  HTTPS (client TLS to the real provider)
               ▼
┌──────────────────────────────┐
│  Upstream AI provider        │   (api.openai.com, api.anthropic.com, …)
└──────────────────────────────┘
```

The gateway is reached only by setting `ANTHROPIC_BASE_URL` /
`OPENAI_BASE_URL` (or an MCP client's proxy config) at `http://127.0.0.1:<port>`
— there is no transparent, system-wide redirection. A process that
doesn't point at the gateway simply talks to the provider directly and
is entirely outside Bouclier's reach; this is a deliberate scope
reduction, not an oversight — see §4.

### 1.1 Assets

| #   | Asset                                            | Sensitivity                  |
| --- | ------------------------------------------------ | ---------------------------- |
| A1  | User prompts & chat completions (in flight)      | Confidential                 |
| A2  | SQLite scan log (`bouclier.sqlite`)              | Confidential                 |
| A3  | Audit webhook URL and bearer (if MDM-configured) | Confidential                 |
| A4  | Sparkle update feed signing keys (EdDSA)         | Critical                     |
| A5  | Code-signing identity + notarization creds       | Out of scope (Apple-managed) |

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
| S4 | **Upstream override SSRF: `*_TARGET_API_URL` repointed at loopback or cloud metadata.** | `UpstreamOverrides.parseTarget` rejects loopback (`CorporateProxy.isLoopbackHost`) and cloud-metadata (`NetworkGuards.isCloudMetadataHost`) targets. |

### 2.2 Tampering

| T1 | **Tampering with the SQLite scan log.** A co-resident process with the same user could rewrite the WAL file. | GRDB WAL file under `~/Library/Application Support/ai.bouclier.app/`. Tamper-evident via audit webhook mirror (`AuditLogger` sends structured JSON to the MDM-configured SIEM endpoint in real time). |
| T2 | **Tampering with a request in flight to hide an injection.** | The gateway forwards a request byte-for-byte or refuses it — it never rewrites. There is no mutation path an attacker could subvert; inspection reads the body and returns a decision only. |

### 2.3 Repudiation

| R1 | **User denies a request was inspected/blocked.** | Every inspected request and every refusal is logged (`ProxyManager.handleRequestLog`) to the activity feed, `os_log`, on-disk stats, and optionally the enterprise SIEM webhook (`AuditLogger`). |
| R2 | **Diagnostic bundle tampered before submission.** | Diagnostics export is JSON, not signed. Out of scope for this version; follow-up: add an EdDSA signature over `DiagnosticsExport.Bundle`. |

### 2.4 Information disclosure

| I1 | **Prompt/response bodies persisted to disk.** | Scan logs **never contain request bodies or URIs** — only metadata (host, byte counts, event kind). The gateway holds a body in memory only for the duration of one request. |
| I2 | **Webhook URL leak via diagnostics bundle.** | `DiagnosticsExport` does not include the webhook URL. Only structured metrics + logs. |
| I3 | **Header fidelity leaks credentials to the wrong host.** | A keep-alive connection is pinned to its first upstream host; a later request resolving to a different host is refused with `421 Misdirected Request` rather than reusing the connection (and its auth) cross-provider. |

### 2.5 Denial of service

| D1 | **Oversized request body** — OOM via multi-GB payload. | `GatewayHandler.channelRead` enforces `HTTPRequestInspector.maxBodyBytes` during body accumulation, returning `413 Payload Too Large` on overflow. Injection scanning is additionally capped (`InjectionInspectionPass.maxScanBytes`) — larger bodies forward without inspection rather than block on a huge scan. |
| D2 | **Event-loop saturation via many simultaneous connections.** | `GatewayServer.start()` binds on `127.0.0.1` only (no remote attack surface) and uses `MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)`. |
| D3 | **Upstream unreachable / slow.** | Connection failures return an honest `502 Bad Gateway` rather than hanging the client indefinitely. |

### 2.6 Elevation of privilege

| E1 | **Agent turns off the firewall that guards it.** | The agent-facing surface (the `bouclier` CLI, the injection MCP) is read-only: `status` and `install` are the only commands. There is no agent-reachable code path that disables protection — the human does that in the app UI. |
| E2 | **Local LPE via the gateway.** | The gateway runs as the user, binds loopback only, and performs no privileged operation on the request path (no CSR/cert-issuance flow — that existed only for the removed extreme mode's CA). |

### 2.7 Injection inspection (the primary control)

The pass is a _detector_, and detectors are evadable. The threats worth
enumerating are mostly about what a failure does, not whether one occurs.
Enforcement is **opt-in**: the gateway defaults to monitor mode (inspect
and log, forward everything). Blocking is enabled via `injectionBlock`.

| ID  | Threat                                                                          | Mitigation / accepted position                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| J1  | **Evasion — a crafted payload in tool output is not matched.**                  | Accepted and expected; see §4. Normalization (NFKC, homoglyph folding, zero-width stripping) raises the bar on the cheap obfuscations, and 161 patterns cover the published families, but an adaptive attacker wins. Detection is defence in depth on the untrusted leg, never the sole control.                                                                                                                                                                                                                                                                                                                                                                                                                    |
| J2  | **False positive refuses legitimate work.**                                     | Bounded by design: monitor mode (the default) never blocks, and even with enforcement on, only `.untrusted` spans can cause a refusal. The operator's own prompt is never blocked, so the classic guardrail failure — blocking a security engineer discussing attacks — cannot occur. Pinned by `principalPromptNeverFiltered`. Provenance tiering (`injectionTrustAuthoredReads`, default on) extends this to the developer's own files: a `tool_result` attributed to a local read (`Read`/`NotebookRead`) of a non-vendored workspace path is trusted like principal, so reading your own docs, research notes, or agent instructions — content that legitimately instructs the model — cannot refuse a request. |
| J3  | **The pass corrupts an ordinary request.**                                      | Structurally prevented. `hasTrigger` is an independent raw-byte gate: no untrusted marker ⇒ the pass never runs. And the pass has no mutation path at all — it returns a decision, never a body. The gateway forwards byte-for-byte or refuses.                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| J4  | **A refused request leaks the payload upstream anyway.**                        | Inspection runs _before_ any upstream connection is opened; a refusal returns locally. Pinned by `blocksInjectionArrivingAsToolOutput`, which asserts the upstream recorder saw nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| J5  | **Detector becomes the attack surface** — ReDoS via a pathological tool result. | Per-span scan input capped at `maxSpanScanChars` (64 KiB), whole-body scan capped by `maxScanBytes`, and the pattern set was ReDoS-audited. A regression here degrades latency on one request, not availability of the gateway.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| J6  | **Silent engine failure — patterns fail to load and nothing detects.**          | This has happened before: a stale `patterns.json` and an ICU-incompatible regex both silently shrank the live set. `bundledPatternsCompile` now fails the build if any pattern fails to compile or the count regresses; the menu bar surfaces the live pattern count. Fail-open is deliberate (J7) but must be _visible_.                                                                                                                                                                                                                                                                                                                                                                                           |
| J7  | **Fail-open leaves traffic unprotected.**                                       | Accepted. If the engine hasn't loaded, requests forward unmodified rather than break the user's agent. A firewall that bricks Claude Code when it can't load a regex file will be uninstalled, and an uninstalled firewall protects nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| J8  | **Trusting a local read admits attacker-planted local content.**                | Bounded, and the deliberate trade for J2. Only a `tool_result` positively attributed (via `tool_use_id`) to `Read`/`NotebookRead` of a path _outside_ the vendored/download/temp denylist (`node_modules`, `vendor`, `Downloads`, `tmp`, …) is downgraded to `.authored`; web/search/shell/external-MCP output, retrieved documents, and any unattributable result stay `.untrusted`. The web→file→read laundering path is still caught at ingress — the fetch is itself an inspected `tool_result`. Residual: a file the user manually downloaded outside the denylist and then reads. Set `injectionTrustAuthoredReads` off (or `injectionStrict` on) to police every tool_result regardless of source.           |

---

## 3. Defense-in-depth summary

| Layer                | Mechanism                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Network boundary     | 127.0.0.1-only bind; no system-wide redirection                                                                   |
| Request parsing      | NIO `HTTPRequestDecoder`, body cap, DNS-rebinding `Host` guard                                                    |
| Injection inspection | Trigger-gated `InjectionInspectionPass`, provenance tiering (principal / authored / untrusted), refuse-or-forward |
| Engine integrity     | Build fails if patterns don't compile or the count regresses; live count shown in the menu bar                    |
| SSRF guards          | Loopback + cloud-metadata rejection on upstream overrides                                                         |
| Cross-host safety    | Keep-alive connection pinned to its first upstream host (`421` otherwise)                                         |
| Storage              | User-scoped SQLite, no request bodies persisted                                                                   |
| Observability        | os_log + optional MDM webhook + in-memory metrics actor                                                           |
| Updates              | Sparkle EdDSA-signed appcast                                                                                      |
| Code signing         | Developer ID + notarization; bundle integrity via Gatekeeper                                                      |

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
- [ ] Threat-model the MCP wrapper binary separately.
