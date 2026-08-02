# Bouclier.ai Threat Model

**Status:** v2 (rewritten following the removal of extreme mode)
**Scope:** Bouclier.ai macOS menubar app + loopback gateway + secret keeper. Covers the request path from an AI client's local SDK call, through the gateway, to the upstream AI provider, and the Keychain-backed secret storage that backs it.
**Audience:** Bouclier.ai engineering, enterprise security reviewers, third-party auditors.

This document enumerates the assets, trust boundaries, adversaries, and
mitigations of Bouclier.ai. It uses the STRIDE taxonomy (Spoofing,
Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege) and cross-references existing code paths and
test coverage.

**What changed from v1.** Bouclier previously shipped a second proxy
mode ("extreme"): a CA-based TLS-terminating proxy paired with a system
`NETransparentProxyProvider` extension that redirected AI-host traffic
to it system-wide, plus a prompt-injection/PII detection engine that
only ran through that path. Extreme mode has been removed — no CA, no
System Extension, no system-wide network filter. This document is a
from-scratch threat model of the loopback gateway and the secret keeper.

**What changed in v0.9.0.** The prompt-injection engine is live again,
called from the gateway by `InjectionInspectionPass` rather than from the
removed extreme mode. Its threats are covered in §2.7 below. The **PII**
tier (`PIIScanner`, `PIIClassifier`, the multimodal scanners) and
`SecretInjectionPass` remain dormant and unreachable from the live
request path, and stay out of scope — see `ARCHITECTURE.md`'s "What was
removed" section.

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
│  - SecretRedactionPass       │   (real value → placeholder, outbound)
│  - GatewayRestoreHandler     │   (placeholder → real value, inbound)
│  - SecretStore (Keychain)    │   (per-secret real value, login keychain)
│  - SecretRequestResponder    │   (agent-proposed secret requests, IPC)
│  - StorageManager (GRDB)     │   (app-support SQLite, WAL)
│  - AuditLogger               │   (os_log + optional webhook)
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
reduction from extreme mode's system-wide interception, not an
oversight — see §4.

### 1.1 Assets

| #   | Asset                                               | Sensitivity                  |
| --- | --------------------------------------------------- | ---------------------------- |
| A1  | Managed secret real values (in Keychain)            | Critical                     |
| A2  | Secret placeholder ↔ real-value mapping (in memory) | Critical                     |
| A3  | User prompts & chat completions (in flight)         | Confidential                 |
| A4  | SQLite scan log (`bouclier.sqlite`)                 | Confidential                 |
| A5  | Audit webhook URL and bearer (if MDM-configured)    | Confidential                 |
| A6  | Sparkle update feed signing keys (EdDSA)            | Critical                     |
| A7  | Code-signing identity + notarization creds          | Out of scope (Apple-managed) |

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
3. **Gateway ↔ Keychain** — secret real values stored
   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, login keychain only.
4. **Gateway ↔ agent (secret request/approval IPC)** — an agent can
   _propose_ enabling protection or requesting a secret via
   `SecretRequestResponder`/`ProtectionApprovalCoordinator`; only the
   human, via the app UI, can approve. The agent never has a code path
   to unilaterally grant itself a secret or flip protection on.
5. **Gateway ↔ disk** (SQLite) — Application Support directory,
   user-scoped perms.
6. **Gateway ↔ Sparkle update feed** — HTTPS + EdDSA signature.
7. **Gateway ↔ optional MDM webhook** — only configured via managed
   profile, never user input.

### 1.3 Adversary profiles

| ID  | Actor                                          | Capabilities                                                                                                                 |
| --- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| T1  | Prompt-injected / misbehaving agent            | Can attempt to have the model instruct the agent to exfiltrate a secret, or probe the gateway for placeholder↔value mappings |
| T2  | Malicious local app (same user)                | Can open sockets to `127.0.0.1:<port>`, read user files w/o TCC                                                              |
| T3  | Co-resident malware w/ admin                   | Can install launchd agents, read Keychain if unlocked                                                                        |
| T4  | MITM on coffee-shop Wi-Fi                      | Full L3/4 interception between the gateway and the upstream provider, can spoof DNS                                          |
| T5  | Hostile upstream AI provider                   | Returns attacker-chosen content in responses                                                                                 |
| T6  | Malicious MDM administrator                    | Pushes hostile config profiles                                                                                               |
| T7  | Malicious webpage (via a browser-driven agent) | Can attempt DNS-rebinding style requests to `127.0.0.1:<port>`                                                               |

---

## 2. STRIDE analysis

### 2.1 Spoofing

| S1 | **Fake upstream provider via DNS hijack / rogue CA.** Attacker poisons DNS or installs a rogue root on the Mac, replies to `api.openai.com`. | `GatewayServer.connectToUpstream` pins with `certificateVerification = .fullVerification` in `NIOSSLContext`. Real-world mitigation depends on the user/enterprise not having rogue roots. |
| S2 | **DNS-rebinding: malicious webpage resolves a hostname to `127.0.0.1` and POSTs to the gateway.** | `GatewayWire.isLoopbackHostHeader` rejects any request whose `Host` header isn't a loopback literal (`127.0.0.1`, `localhost`, `::1`) with `421 Misdirected Request`. |
| S3 | **Forged Sparkle update.** | Sparkle EdDSA signature on appcast items (unchanged from v1). |
| S4 | **Upstream override SSRF: `*_TARGET_API_URL` repointed at loopback or cloud metadata.** | `UpstreamOverrides.parseTarget` rejects loopback (`CorporateProxy.isLoopbackHost`) and cloud-metadata (`NetworkGuards.isCloudMetadataHost`) targets. |

### 2.2 Tampering

| T1 | **Tampering with the SQLite scan log.** A co-resident process with the same user could rewrite the WAL file. | GRDB WAL file under `~/Library/Application Support/ai.bouclier.app/`. Tamper-evident via audit webhook mirror (`AuditLogger` sends structured JSON to the MDM-configured SIEM endpoint in real time). |
| T2 | **Tampering with the in-memory placeholder↔value mapping via a crafted request.** | The mapping is derived server-side from `SecretStore` on each connection (`connectionRules`), never accepted from the client. A request can't inject or alter it. |
| T3 | **A prompt-injected agent tricked into echoing a placeholder back verbatim to bypass scrub.** | Scrub runs on every outbound request regardless of prior turns — there's no "already scrubbed, skip" state a compromised turn could exploit. |
| T4 | **Config change mid-connection: secrets added/removed while a keep-alive connection is open.** | `connectionRules` is pinned at the first request on a connection; if live config diverges from the pinned set, the connection is refused with `503 Service Unavailable` rather than silently scrubbing against a stale rule set — see `GatewayServer.forwardUpstream`. |

### 2.3 Repudiation

| R1 | **User denies a secret was scrubbed/injected/blocked.** | Every secret-keeper event is logged (`ProxyManager.handleSecretEvent`) to the activity feed, `os_log`, on-disk stats, and optionally the enterprise SIEM webhook (`AuditLogger`). |
| R2 | **Diagnostic bundle tampered before submission.** | Diagnostics export is JSON, not signed. Out of scope for this version; follow-up: add an EdDSA signature over `DiagnosticsExport.Bundle`. |

### 2.4 Information disclosure

| I1 | **Real secret value reaches the model provider.** The core invariant — see `docs/secret-injection.md`. | `SecretRedactionPass.apply` scrubs the real value to its placeholder before the request leaves the gateway, gated on `SecretRedactionPass.hasTrigger` so clean traffic with no secret material is provably byte-faithful. Pinned by `E2EProxyTests`-equivalent gateway E2E tests. |
| I2 | **Secret real value exfil.** | Stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` in the login keychain. Never written to disk in plaintext, never logged. |
| I3 | **Scan logs capture request/response bodies.** | Scan logs **never contain request bodies or URIs** — only metadata (host, byte counts, event kind). |
| I4 | **Webhook URL leak via diagnostics bundle.** | `DiagnosticsExport` does not include the webhook URL. Only structured metrics + logs. |
| I5 | **A safety-invariant regression silently ships secrets in cleartext.** | `SecretKeeperMonitor.runSelfTest()` runs on every launch, before any traffic flows; on failure it trips a circuit breaker that disables secret injection/scrub entirely and forwards everything untouched, rather than risk a corrupted scrub/restore pipeline. |

### 2.5 Denial of service

| D1 | **Oversized request body** — OOM via multi-GB payload. | `GatewayHandler.channelRead` enforces `HTTPRequestInspector.maxBodyBytes` during body accumulation, returning `413 Payload Too Large` on overflow. Secret-scan itself is additionally capped by `GatewayServer.maxSecretScanBytes` (1 MiB) — larger bodies skip scrub/restore and forward untouched rather than block on a huge scan. |
| D2 | **Event-loop saturation via many simultaneous connections.** | `GatewayServer.start()` binds on `127.0.0.1` only (no remote attack surface) and uses `MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)`. |
| D3 | **Upstream unreachable / slow.** | Connection failures return an honest `502 Bad Gateway` rather than hanging the client indefinitely. |

### 2.6 Elevation of privilege

| E1 | **Agent grants itself a secret or turns on protection unilaterally.** | The agent-facing MCP/status surface is read-only + propose-only: `ProtectionApprovalCoordinator.onEnable` and the secret-request flow require the human to approve via the app UI. There is no agent-reachable code path that performs either action directly. |
| E2 | **Local LPE via Keychain prompt abuse.** | Secret values are stored/retrieved via the standard Keychain API with no custom CSR/cert-issuance flow (that flow existed only for extreme mode's CA and was removed along with it). |

### 2.7 Injection inspection (v0.9.0)

The pass is a _detector_, and detectors are evadable. The threats worth
enumerating are mostly about what a failure does, not whether one occurs.

| ID  | Threat                                                                          | Mitigation / accepted position                                                                                                                                                                                                                                                                                            |
| --- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| J1  | **Evasion — a crafted payload in tool output is not matched.**                  | Accepted and expected; see §4. Normalization (NFKC, homoglyph folding, zero-width stripping) raises the bar on the cheap obfuscations, and 161 patterns cover the published families, but an adaptive attacker wins. Detection is defence in depth on the untrusted leg, never the sole control.                          |
| J2  | **False positive refuses legitimate work.**                                     | Bounded by design: only `.untrusted` spans can cause a refusal. The operator's own prompt is never blocked (default), so the classic guardrail failure — blocking a security engineer discussing attacks — cannot occur unless a fleet opts into `injectionStrict`. Pinned by `principalPromptNeverFiltered`.             |
| J3  | **The pass corrupts an ordinary request.**                                      | Structurally prevented. `hasTrigger` is an independent raw-byte gate: no untrusted marker ⇒ the pass never runs. And the pass has no mutation path at all — it returns a decision, never a body. Same discipline as `SecretRedactionPass`.                                                                                |
| J4  | **A refused request leaks the payload upstream anyway.**                        | Inspection runs _before_ the secret scrub and before any upstream connection is opened; a refusal returns locally. Pinned by `blocksInjectionArrivingAsToolOutput`, which asserts the upstream recorder saw nothing.                                                                                                      |
| J5  | **Detector becomes the attack surface** — ReDoS via a pathological tool result. | Per-span scan input capped at `maxSpanScanChars` (64 KiB), whole-body scan capped at 1 MiB, and the pattern set was ReDoS-audited in `e089deb`. A regression here degrades latency on one request, not availability of the gateway.                                                                                       |
| J6  | **Silent engine failure — patterns fail to load and nothing detects.**          | This has happened before: a stale `patterns.json` and an ICU-incompatible regex both silently shrank the live set. `bundledPatternsCompile` now fails the build if any pattern fails to compile or the count regresses; the menu bar surfaces the live pattern count. Fail-open is deliberate (J7) but must be _visible_. |
| J7  | **Fail-open leaves traffic unprotected.**                                       | Accepted. If the engine hasn't loaded, requests forward unmodified rather than break the user's agent — the same rule as v0.5.2's fail-open shell. A firewall that bricks Claude Code when it can't load a regex file will be uninstalled, and an uninstalled firewall protects nothing.                                  |

---

## 3. Defense-in-depth summary

| Layer                | Mechanism                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------- |
| Network boundary     | 127.0.0.1-only bind; no system-wide redirection                                                               |
| Request parsing      | NIO `HTTPRequestDecoder`, body cap, DNS-rebinding `Host` guard                                                |
| Secret scrub/restore | Trigger-gated `SecretRedactionPass`/`SecretRestore`, per-connection rule pinning, fail-closed on config drift |
| Self-test            | `SecretKeeperMonitor` circuit breaker on every launch                                                         |
| SSRF guards          | Loopback + cloud-metadata rejection on upstream overrides and secret host bindings                            |
| Storage              | User-scoped SQLite, no request bodies persisted                                                               |
| Observability        | os_log + optional MDM webhook + in-memory metrics actor                                                       |
| Updates              | Sparkle EdDSA-signed appcast                                                                                  |
| Code signing         | Developer ID + notarization; bundle integrity via Gatekeeper                                                  |
| Secret storage       | Keychain (login, `WhenUnlockedThisDeviceOnly`)                                                                |

---

## 4. Accepted risks

- **Root-level malware** can tamper with any Mac app; Bouclier.ai does
  not claim protection against this tier.
- **The gateway is opt-in per process**, not system-wide. Any process
  that doesn't set `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` (or isn't
  captured by `ShellEnvInjector`'s dotfile/launchctl wiring) bypasses
  Bouclier entirely and is outside its reach. This is a deliberate
  trade-off made when extreme mode's system-wide network filter was
  removed: no CA, no System Extension, and no ability to see traffic
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
- **User manually disabling the gateway** is a legitimate action.
  Enforcement requires MDM configuration profile + compliance tooling.
- **Diagnostics bundle tampering in transit** before reaching support —
  not signed.

---

## 5. Follow-ups

- [ ] Sign `DiagnosticsExport.Bundle` with the Sparkle EdDSA key for tamper-evident support handoff.
- [ ] Threat-model the MCP wrapper binary separately.
- [ ] If destination-bound secret injection (`SecretInjectionPass`, currently dormant) is ever wired into the gateway, threat-model that path before it ships live.
