# Bouclier.ai Threat Model

**Status:** v1 (2026-04-05)
**Scope:** Bouclier.ai macOS menubar app + System Extension + shared pattern database. Covers the injection-firewall path from application network request through the inspecting TLS proxy to the upstream AI provider.
**Audience:** Bouclier.ai engineering, enterprise security reviewers, third-party auditors.

This document enumerates the assets, trust boundaries, adversaries, and mitigations of the Bouclier.ai prompt-injection firewall. It uses the STRIDE taxonomy (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and cross-references existing code paths and test coverage.

---

## 1. System overview

```
┌──────────────────────────────┐
│  Mac end user / LLM client   │   (chatgpt, cursor, claude cli, curl, …)
└──────────────┬───────────────┘
               │  HTTPS CONNECT
               ▼
┌──────────────────────────────┐
│ Bouclier.ai menubar app (host)  │
│  - CertificateAuthority      │   (CA key in Keychain, login keychain only)
│  - TLSProxy (swift-nio)      │   (127.0.0.1 bind; never 0.0.0.0)
│  - HTTPRequestInspector      │   (request scan + sanitize)
│  - SSEStreamInspector        │   (streaming response scan)
│  - InjectionFilter           │   (161 patterns + 8 dampeners)
│  - StorageManager (GRDB)     │   (app-support SQLite, WAL)
│  - AuditLogger               │   (os_log + optional webhook)
│  - Metrics (actor)           │   (in-memory counters)
└──────────────┬───────────────┘
               │  HTTPS (re-encrypted)
               ▼
┌──────────────────────────────┐
│  Upstream AI provider        │   (api.openai.com, api.anthropic.com, …)
└──────────────────────────────┘
```

The **System Extension** (NETransparentProxyProvider) redirects the allowlisted provider domains to the menubar app's local proxy. All other traffic bypasses Bouclier.ai untouched.

### 1.1 Assets

| #   | Asset                                            | Sensitivity                  |
| --- | ------------------------------------------------ | ---------------------------- |
| A1  | Bouclier.ai root CA private key                  | Critical                     |
| A2  | User prompts & chat completions (in flight)      | Confidential                 |
| A3  | Pattern database (`patterns.json`)               | Integrity-critical           |
| A4  | SQLite scan log (`bouclier.sqlite`)              | Confidential                 |
| A5  | Audit webhook URL and bearer (if MDM-configured) | Confidential                 |
| A6  | Sparkle update feed signing keys (EdDSA)         | Critical                     |
| A7  | Code-signing identity + notarization creds       | Out of scope (Apple-managed) |

### 1.2 Trust boundaries

1. **User ↔ menubar app** — any local process can dial `127.0.0.1:<proxy>`. The System Extension + PAC arrangement ensures only allowlisted provider hostnames are redirected, but any local tool can still CONNECT manually.
2. **Menubar app ↔ System Extension** — XPC channel between host and NE provider.
3. **App ↔ upstream AI provider** — terminated TLS on both sides.
4. **App ↔ Keychain** — CA key stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, login keychain only.
5. **App ↔ disk** (SQLite, patterns.json) — Application Support directory, user-scoped perms.
6. **App ↔ Sparkle update feed** — HTTPS + EdDSA signature.
7. **App ↔ optional MDM webhook** — only configured via managed profile, never user input.

### 1.3 Adversary profiles

| ID  | Actor                                | Capabilities                                             |
| --- | ------------------------------------ | -------------------------------------------------------- |
| T1  | Remote attacker via prompt injection | Can place text anywhere a model sees (docs, emails, web) |
| T2  | Malicious local app (same user)      | Can open sockets, read user files w/o TCC                |
| T3  | Co-resident malware w/ admin         | Can install launchd agents, tamper with patterns.json    |
| T4  | MITM on coffee-shop Wi-Fi            | Full L3/4 interception, can spoof DNS                    |
| T5  | Hostile upstream AI provider         | Returns attacker-chosen content in responses             |
| T6  | Malicious MDM administrator          | Pushes hostile config profiles                           |

---

## 2. STRIDE analysis

### 2.1 Spoofing

| S1 | **Fake upstream provider via DNS hijack / rogue CA.** Attacker poisons DNS or installs a rogue root on the Mac, replies to `api.openai.com`. | `TLSProxy` pins upstream with `certificateVerification = .fullVerification` in `NIOSSLContext` (TLSProxy.swift). Real-world mitigation depends on the user/enterprise not having rogue roots. |
| S2 | **Fake Bouclier.ai CA injected into other users' trust stores.** The CA is generated per-install and not shipped; every install has a unique key. Key only imported into **login keychain** and marked `kSecUseDataProtectionKeychain = false` for user-level trust. |
| S3 | **CONNECT target smuggling** — attacker sends `CONNECT evil.com:443\r\nHost: api.openai.com:443` to bypass the allowlist. | `HTTPRequestInspector.parseConnectTarget` rejects any CR/LF, control bytes, whitespace, `@`, or non-hostname characters. See `HTTPRequestInspectorTests.rejectsCRLFInjection`. |
| S4 | **Prompt spoofing an allowlisted host in the SNI while CONNECT-ing to an attacker IP.** | Out of scope — NIOSSL verifies the presented certificate against the SNI hostname. Mismatch closes the channel. |
| S5 | **Forged Sparkle update.** | Sparkle EdDSA signature on appcast items (existing mitigation). |

### 2.2 Tampering

| T1 | **Tampering with `patterns.json` on disk.** A co-resident process with the same user could rewrite the bundle resource. | Patterns are loaded from the signed app bundle (`Bundle.main.url`). The bundle is code-signed; Gatekeeper quarantines modifications. Runtime SHA-256 of the loaded file is logged (`InjectionFilter.loadAndVerifyPatterns`) so tampering is observable in diagnostics/webhooks. |
| T2 | **Tampering with in-memory regexes via FS.** | Not prevented; requires root + SIP disabled. Out of scope. |
| T3 | **Tampering with the SQLite scan log.** | GRDB WAL file under `~/Library/Application Support/ai.bouclier.app.ai/`. Tamper-evident via audit webhook mirror (AuditLogger sends structured JSON to the MDM-configured SIEM endpoint in real time). |
| T4 | **Tampering with the request body after redaction.** Malicious client sees redaction, resubmits bypassing Bouclier.ai. | Not in threat model — Bouclier.ai is a defense-in-depth layer. Bypass requires the user to manually route traffic around the proxy, which is detectable by the System Extension. |

### 2.3 Repudiation

| R1 | **User denies issuing a blocked prompt.** | Every detection is logged to `scan_logs` table (timestamp, host, pattern ids, severity, match count) and mirrored to `os_log` (collectable by Jamf/Kandji) and optionally to the enterprise SIEM webhook. |
| R2 | **Diagnostic bundle tampered before submission.** | Diagnostics export is JSON, not signed. Out of scope for v1; follow-up: add ed25519 signature over `DiagnosticsExport.Bundle`. |

### 2.4 Information disclosure

| I1 | **User prompts captured in scan logs.** This would be worse than the problem it solves. | Scan logs **never contain request bodies or URIs** — only match metadata (pattern ids, category, severity, match count, body length). See `StorageManager.recordScan` and `ScanLogRow`. The privacy policy is enforced by test `DiagnosticsExportTests.encodes` which asserts the bundle does not contain the word `prompt`. |
| I2 | **CA private key exfil.** | Stored `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` in the login keychain. Not exported. Never written to disk in plaintext. |
| I3 | **Webhook URL leak via diagnostics bundle.** | `DiagnosticsExport` does not include the webhook URL. Only structured metrics + logs. |
| I4 | **Side-channel leak via match count.** Rare cases where match count alone reveals prompt contents (e.g. uniqueness attacks). | Accepted risk — match count is required for meaningful metrics. |
| I5 | **Request URI logged when host is not allowlisted.** | `DiagnosticsExport.buildBundle` strips `targetHost` from log rows whose host is not on the allowlist. See `DiagnosticsExportTests.stripsUnlistedHost`. |
| I6 | **Recent log rows leak in crash reports.** | `ScanLogRow` does not contain body content. Objective-C exception reporter is not customized. |

### 2.5 Denial of service

| D1 | **Slow-loris CONNECT** — attacker opens a TCP connection and drips bytes so the proxy never completes the CONNECT line. | `ConnectHandler` enforces `HTTPRequestInspector.maxConnectHeaderBytes = 8 KiB` and returns `431 Request Header Fields Too Large` on overflow. |
| D2 | **Oversized request body** — OOM via multi-GB payload. | `HTTPInspectionHandler` enforces `HTTPRequestInspector.maxBodyBytes = 10 MiB` both during chunk accumulation and at final inspection; returns `413 Payload Too Large`. Covered by `ProxyPipelineTests.rejectsStreamedOversize`. |
| D3 | **Regex catastrophic backtracking.** | All bundled patterns were authored without unbounded backreferences and have been benchmark-tested (`packages/patterns/src/__tests__/benchmark.test.ts` runs 442 attacks + 240 benign samples in ≤200ms; any regression blows up this test). NSRegularExpression uses ICU which is generally linear for the regex features we use. |
| D4 | **SSE stream DoS** — attacker responds from an upstream with an endless trickle. | `SSEStreamInspector` holds a rolling 4096-char window; unbounded text does not grow its buffer. Client-side timeouts close the connection. |
| D5 | **Event-loop saturation via many simultaneous connections.** | `TLSProxy.start()` binds on `127.0.0.1` only (no remote attack surface) and uses `MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)`. |

### 2.6 Elevation of privilege

| E1 | **Pattern-driven RCE** via a crafted regex string in a future hot-reload file. | `FilterPattern.init?(from:)` compiles via `NSRegularExpression` which has no code-generation capability. Pattern files are loaded from bundled resources signed by Apple Developer ID. Hot-reload from `~/Library/Application Support/.../patterns.json` is gated on a SHA-256 integrity check against a pinned baseline. |
| E2 | **System Extension compromise.** | NE provider has no entitlements beyond `com.apple.developer.networking.networkextension` (transparent-proxy) and runs outside the app sandbox; it is a separate signed binary. No RPC from host to extension other than config pushes through the documented NEAppProxyProvider API. |
| E3 | **Local LPE via Keychain prompt abuse.** Earlier Bouclier.ai builds used openssl CSR flow that triggered spurious Keychain prompts; corrected to Keychain Access native workflow for cert issuance. |

---

## 3. Defense-in-depth summary

| Layer                | Mechanism                                                              |
| -------------------- | ---------------------------------------------------------------------- |
| Network boundary     | 127.0.0.1-only bind; allowlist of 10 built-in + MDM-configurable hosts |
| CONNECT parsing      | Strict hostname/port validation, CRLF rejection, 8 KiB header cap      |
| HTTP request parsing | NIO `HTTPRequestDecoder`, 10 MiB body cap, Content-Type gate           |
| Injection detection  | 161 regex patterns across 21 categories + 8 FP dampeners               |
| Response detection   | `SSEStreamInspector` with rolling window, frame-boundary safe          |
| Storage              | User-scoped SQLite, no request bodies persisted                        |
| Observability        | os_log + optional MDM webhook + in-memory metrics actor                |
| Updates              | Sparkle EdDSA-signed appcast                                           |
| Code signing         | Developer ID + notarization; bundle integrity via Gatekeeper           |
| Secret storage       | Keychain (login, `WhenUnlockedThisDeviceOnly`)                         |

---

## 4. Accepted risks (v1)

- **Root-level malware** can tamper with any Mac app; Bouclier.ai does not claim protection against this tier.
- **User manually disabling the proxy** is a legitimate action. Enforcement requires MDM configuration profile + compliance tooling.
- **Pattern false negatives** on novel jailbreaks. Mitigated by rolling benchmark (442 attacks, TPR ≥ 0.90) but not 100%.
- **Diagnostics bundle tampering in transit** before reaching support — not signed in v1.

---

## 5. Follow-ups

- [ ] Sign `DiagnosticsExport.Bundle` with the Sparkle EdDSA key for tamper-evident support handoff.
- [ ] Add SHA-256 integrity check between bundled and hot-reloaded `patterns.json`.
- [ ] Prometheus `/metrics` endpoint behind a local unix-socket for ops consumption.
- [ ] Extend SSE inspector to detect token-level exfiltration across streams (cross-stream rolling window).
- [ ] Threat-model the MCP wrapper binary separately.
