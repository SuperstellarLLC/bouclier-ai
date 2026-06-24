# Secret keeper

Status: **Shipped, behind `secretInjection` feature flag (off by default).**
Configure under **Settings → Secrets**. Secrets live in the macOS Keychain and
never leave this Mac; every event flows through the activity feed, notifications,
the SIEM audit log, and on-disk stats.

The secret keeper protects managed credentials in **two modes**, chosen by the
**Proxy Mode** setting (Settings → Protection):

|                  | **Standard mode** (`GatewayServer`)                                                 | **Extreme mode** (`TLSProxy`)                                     |
| ---------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Interception     | Non-CA base-URL gateway — agent points `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` at us | MITM TLS, trusted root CA                                         |
| Secret mechanism | **Scrub → restore** on the LLM channel                                              | **Inject** placeholder → real value at the bound third-party host |
| What's protected | The **model provider** never sees the secret                                        | The **agent** never holds the secret                              |
| Also runs        | secrets only                                                                        | injection filtering + file PII + secrets                          |
| CA install       | none                                                                                | required                                                          |

A secret with **no host binding** is _scrub-only_ (standard mode). A secret
**bound to a host** is also _injectable_ in extreme mode. The placeholder format
is the same in both: `__BOUCLIER_SECRET_<name>__` (ASCII, regex-inert, reproduced
verbatim by LLMs).

## Standard mode: scrub → restore (no CA)

The agent legitimately holds real secrets locally (it reads `.env`, calls Stripe
directly). What we blind is the **model vendor**:

```
agent request  →  [scrub: sk_live_… → __BOUCLIER_SECRET_stripe__]  →  Anthropic/OpenAI
model response →  [restore: __BOUCLIER_SECRET_stripe__ → sk_live_…] →  agent (tool calls work)
```

- **Outbound scrub** (`SecretRedactionPass`): replace each managed real value with
  its placeholder before the request reaches the model. Only **key-shaped** values
  (≥16 chars, no whitespace) are scrubbed, so ordinary prose is never corrupted;
  longest value first, so one secret that is a substring of another isn't clobbered.
- **Inbound restore** (`SecretRestore`): replace placeholder → real value in the
  response so the agent's local/third-party tool calls still work. **Exact-match
  only** — deliberately no fuzzy matching, because splicing a _live API key_ in
  place of a hallucinated near-token would be a security hole. Streaming and
  **straddle-safe**: a placeholder split across chunks is reassembled via a
  trailing carry buffer; it operates on raw bytes so multi-byte UTF-8 split across
  chunks is never corrupted.
- **Honest threat model.** Standard mode does **not** hide the secret from the
  agent — the real value _is_ restored into the response the agent consumes, so it
  lives in the local transcript. The guarantee is precise and true: **your
  credential never leaves this machine for the model provider.** (This inverts the
  extreme-mode claim below, where the agent never holds the secret.)
- Framing: restore changes the body length, so the gateway parses the response and
  re-emits it with connection-close framing (and strips `Accept-Encoding` so the
  body is plaintext). Clean traffic with no secrets configured keeps the
  byte-faithful, keep-alive raw relay untouched.

## Using secrets from an AI agent (MCP)

The intentional, non-magical path for an agent (Claude Code, etc.) to _use_
a secret without ever _seeing_ its value. The scrub above is the safety
net; this is the primary mechanism.

**Register the server** (one-time):

```sh
claude mcp add bouclier-secrets -- /Applications/Bouclier.app/Contents/MacOS/bouclier-ai-secrets-mcp
```

### Just-in-time secret requests (the natural flow)

When a secret the agent needs isn't stored yet, the agent **asks for it** and
Bouclier prompts the _user_ to paste it — the agent never sees the value:

```
Claude: request_secrets(["STRIPE_KEY","OPENAI_API_KEY"], reason: "set up payments + LLM")
        → Bouclier shows ONE dialog with a SecureField per name + the reason
        → you paste what you have, hit Provide
        → "The user provided $STRIPE_KEY, $OPENAI_API_KEY — available in new shells."  (NO values)
Claude: Bash `stripe listen`   (fresh shell already has $STRIPE_KEY)
```

This is how you set up a project with many secrets without entering them
one-by-one in Settings and without a `.env` on disk. `request_secret` is the
single-secret form. The values go user keystrokes → app → Keychain, and are
activated for new shells — never through the MCP channel or the model.

How the value stays out of everything (defense in depth):

- **MCP server** writes only a _request file_ (`ipc/requests/<id>.json`:
  names + reason, never a value) and reads a _response file_ (status + which
  names were provided). It never touches the Keychain.
- **App** (`SecretRequestResponder`) watches `ipc/requests/`, validates the
  file (size-capped, env-name-validated, staleness-checked — it's untrusted
  input from any local process), and shows the dialog. The dialog (the only
  place values exist) stores them via `SecretStore` + activates them, then
  writes a names-only response.
- **Reason is shown as the agent's claim** ("verify before pasting") since
  it's attacker-controllable; the human is the gate.
- **Liveness:** the app writes `ipc/responder.pid`; the MCP client probes it
  (`kill(pid,0)`) and fails fast if the app isn't running. Blocking tool call
  with a 120s server-side timeout; cancel/timeout return `isError`.
- **"Keep after this session"** (default on) persists the secret; unchecked
  makes it session-only, purged on next app launch.

Tools: `request_secret(env_var, reason?, generate?)`, `request_secrets(env_vars, reason?, generate?)`.

**Generating new secrets.** With `generate: true` the dialog pre-fills each
field with a fresh random value the user just reviews and approves (a ↻
button regenerates; every field also has one for manual creation). The
value comes from a configurable command — default `openssl rand -base64 32`,
editable in Settings → Secrets. So an agent can _create_ secrets it needs
(a signing key, a session secret) without anyone typing them, and still
never sees them.

**Provisioning many vars to a deployment (e.g. Vercel).** The agent
orchestrates; the shell carries the values:

```
Claude: request_secrets(["DB_URL","STRIPE_KEY","SESSION_SECRET"], generate:true,
                        reason:"provision Vercel env")
        → you approve the generated/pasted values
Claude: for v in DB_URL STRIPE_KEY SESSION_SECRET; do
          printf '%s' "$(eval echo \$$v)" | vercel env add "$v" production
        done
```

The shell expands `$STRIPE_KEY` etc. at runtime — the value flows
shell → `vercel` → Vercel, never into the model's context. **Use the
Vercel CLI with `$VAR` references, not a Vercel MCP tool that takes the
literal value** (a literal value in an MCP tool argument _is_ in the model
context — Bouclier can't help there, since the exposure happens before any
network call).

### Using already-stored secrets

**Flow:**

```
You:    "use bouclier mcp to set the secret values in those env variables"
Claude: list_secrets            → ["stripe → $STRIPE_KEY (agent-usable)", …]   (NO values)
Claude: set_env(["stripe"])     → "Activated: $STRIPE_KEY"                      (NO values)
Claude: Bash `curl -H "Authorization: Bearer $STRIPE_KEY" …`
                                → a NEW shell sources bouclier-ai-env --secrets,
                                  which reads the real value from the Keychain
                                  and exports $STRIPE_KEY for that command only.
```

**The model never sees a value.** Three separation lines enforce this:

1. **The MCP server has no value access.** It reads only rule _metadata_
   (`secret-rules.json`: names, env-var names, `agentAccess`) and writes an
   _active manifest_ of names. Every tool result is names-only. (Unit tests
   assert no value can appear in a response.)
2. **Values live in the Keychain** and are read only by
   `bouclier-ai-env --secrets` (POSIX/zsh/bash) or
   `bouclier-ai-env --secrets --fish` (fish), at shell-init, into the
   subprocess environment — never into the conversation.
3. **The scrub net** still runs: if a command's output accidentally echoes
   the real value back toward the model, standard mode replaces it with the
   placeholder.

**Authorization.** Each secret has an `agentAccess` flag (default on; toggle
in Settings → Secrets). The MCP server refuses `set_env` for a locked
secret. This bounds the blast radius if the agent is prompt-injected; note
that in standard mode Bouclier can't see the agent's _direct_ third-party
traffic, so a determined injected agent could still misuse an unlocked
secret it's allowed to use — lock sensitive secrets, and use extreme mode +
`failClosedEgress` for hard containment.

**Components:** `Sources/BouclierSecretsCore` (shared, dependency-free:
`SecretRuleMeta`, `SecretEnvManifest`, `SecretEnvResolver`, `KeychainSecretReader`,
`SecretsMCPHandler`), `Sources/SecretsMCP` (the stdio server binary),
`Sources/EnvHelper` (`bouclier-ai-env --secrets`). Paths/Keychain service are
overridable via `BOUCLIER_APP_SUPPORT_DIR` / `BOUCLIER_KEYCHAIN_SERVICE` for
tests. No-prompt cross-binary Keychain access requires the helper to share
the app's keychain-access-group entitlement (a packaging/signing step);
without it macOS prompts the user — explicit consent, never silent.

## Extreme mode: destination-bound injection (CA)

The LLM/agent never holds a real secret. It only knows an opaque **placeholder**.
When the agent makes an outbound tool call to a bound host (e.g. `api.stripe.com`),
Bouclier swaps the placeholder for the real secret value at the very last moment —
after all inspection, just before the request bytes go on the wire. The real secret
is in the request for exactly one hop, to exactly one allowed host, and never appears
in any prompt, log, model-provider request, or transcript.

This is the same idea as Infisical Agent Vault / Arcade, but with two properties they
don't combine:

1. **Local-first.** The secret lives in the macOS Keychain on this machine. There is no
   server and no "lock down all egress" requirement — Bouclier already _is_ the egress
   inspector.
2. **Destination-bound + exfil-tripwired.** A secret is injected only for its allowlisted
   host, and an inbound request that already contains a _real_ secret value (meaning the
   agent somehow got the plaintext) is blocked outright. Pure injectors don't inspect for
   exfiltration; pure redactors (LiteLLM, llm-redactor) don't inject. We do both.

## The rule (one rule, applied uniformly)

Everything is the **destination-binding rule**. A secret is bound to a set of hosts; that
binding decides every outcome, with no special-casing of LLM providers:

| Situation                                                  | Outcome                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Placeholder for secret X, request to a host **bound** to X | **Inject** the real value                                                                  |
| Placeholder for X, request to a host **not** bound to X    | **Block** (misdirected injection)                                                          |
| Real value of X, request to a host **bound** to X          | **Forward** — intended destination (e.g. authenticating directly with that provider)       |
| Real value of X, request to a host **not** bound to X      | **Block** — a credential is leaking somewhere it shouldn't, _including to an LLM provider_ |

This is what makes both legitimate cases work while blocking the dangerous one:

- **Authenticate directly with a provider** — bind the provider's own key to the
  provider's host; the placeholder is injected (or the real key, already at the right
  host, is forwarded). Works.
- **Stop a third party's key reaching the model** — a Stripe key showing up in a request
  to `api.anthropic.com` is the real value of a secret bound to `api.stripe.com` arriving
  at a host it isn't bound to → blocked. The model never receives a third party's
  credential.

The plaintext tripwire only arms on **key-shaped values** (≥16 chars, no whitespace), so
ordinary prose in a prompt can never trigger a false-positive block of a real request.

## Flow

```
Agent emits tool call:  POST api.stripe.com  Authorization: Bearer __BOUCLIER_SECRET_stripe__
        │  (HTTPS_PROXY → Bouclier; api.stripe.com is in interceptedDomains, so it's MITM'd)
        ▼
HTTPInspectionHandler  ── injection scan, multimodal PII pass (unchanged) ──┐
        │                                                                    │
        ▼  SecretInjectionPass.apply(host, headers, body, store)            │
        │                                                                    │
   ┌────┴─────────────────────────────────────────────────────────────┐    │
   │ 1. Tripwire: a key-shaped REAL secret value present, heading to a  │    │
   │    host it is NOT bound to?  → BLOCK (leak / third-party-to-LLM).  │    │
   │    Value at its OWN bound host ⇒ forward (intended destination).   │    │
   │ 2. For each rule whose placeholder appears in URI/headers/body:    │    │
   │    • host ∈ rule.allowedHosts ⇒ replace placeholder → real secret  │    │
   │    • host ∉ rule.allowedHosts ⇒ BLOCK (misdirected injection)      │    │
   └────┬─────────────────────────────────────────────────────────────┘    │
        ▼                                                                    │
   re-derive Content-Length, wire-safety check, forward upstream  ◄─────────┘
```

## Components

| File                              | Role                                                                                                                                                                                                                                                                             |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Proxy/SecretRule.swift`          | The rule model: `name`, `placeholder`, `allowedHosts`. `Codable`.                                                                                                                                                                                                                |
| `Proxy/SecretStore.swift`         | Keychain-backed store (mirrors `CertificateAuthority`'s `SecItem` usage). Rule metadata in a JSON file under Application Support; secret _values_ in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). In-memory cache so the event-loop path never blocks on Keychain. |
| `Proxy/SecretInjectionPass.swift` | **Pure, no NIO.** Extreme-mode inject/block: `apply(host:…)` → `Outcome` (`.forward` rewritten / `.block`). Longest-placeholder-first replacement; JSON-string-escapes injected values in JSON bodies.                                                                           |
| `Proxy/SecretRedactionPass.swift` | **Pure, no NIO.** Standard-mode outbound scrub: managed real value → placeholder. Key-shaped values only; longest value first; `hasTrigger` integrity gate.                                                                                                                      |
| `Proxy/SecretRestore.swift`       | **Pure, no NIO.** Standard-mode inbound restore: placeholder → real value. Byte-level, streaming, straddle-safe, exact-match only.                                                                                                                                               |
| `Proxy/GatewayServer.swift`       | The standard-mode non-CA gateway. Scrubs on the request path; `GatewayRestoreHandler` restores on the response path (connection-close framing). Clean traffic uses a byte-faithful keep-alive relay.                                                                             |
| `Proxy/ProxyMode.swift`           | `standard` vs `extreme` resolution (test override → MDM → user default → compile default `extreme`).                                                                                                                                                                             |
| `Proxy/TLSProxy.swift`            | Extreme mode: `HTTPInspectionHandler.forwardUpstream` calls `SecretInjectionPass` before serializing; `.block` → reject the request to the client.                                                                                                                               |
| `Proxy/SystemProxy.swift`         | Rule hosts merge into `interceptedDomains` so they're MITM'd + routed via PAC.                                                                                                                                                                                                   |
| `Utilities/FeatureFlags.swift`    | `secretInjection` flag, off by default.                                                                                                                                                                                                                                          |
| `Views/SettingsView.swift`        | **Settings → Secrets** tab: toggle, add/remove rules, `SecureField` value entry, copy-placeholder, live counters.                                                                                                                                                                |
| `Proxy/ProxyManager.swift`        | `handleSecretEvent` → activity feed, block notification, `AuditLogger`, `StorageManager` (`source: "secret-injection"`), `Metrics`.                                                                                                                                              |
| `Utilities/ManagedConfig.swift`   | `failClosedEgress` + `egressAllowlist` (MDM).                                                                                                                                                                                                                                    |

## Safety guarantees (don't break the user's LLM access; don't damage their machine)

These are enforced in code and covered by tests:

1. **Zero footprint when off / unconfigured.** With `secretInjection` off, the pass never
   runs and no host is added to the intercept set. On with no secrets configured →
   `allHosts()` is empty → `interceptedDomains` is unchanged. Nothing happens until the
   user adds a secret.
2. **Byte-identical passthrough.** A request with no managed placeholder and no key-shaped
   secret value is forwarded byte-for-byte (URI, headers, body). The rebuild path runs
   _only_ when a placeholder was actually injected. So normal traffic to OpenAI /
   Anthropic / Cursor is never altered.
3. **Never breaks a provider you authenticate with.** A provider's own key reaching that
   provider is forwarded, never blocked (host-aware tripwire). Injection into a bound
   provider host is the supported auth path.
4. **No false-positive blocks.** The tripwire arms only on key-shaped values
   (≥16 chars, no whitespace), so prose can't trip it. A block requires the _exact_
   secret to be present heading to the _wrong_ host.
5. **Big LLM requests are never slowed or touched.** Bodies over 1 MiB (vision images,
   file uploads) are not body-scanned — only URI + headers — and the original body is
   forwarded unchanged.
6. **No request smuggling.** Secret values with CR/LF/NUL are rejected at the store; the
   rewritten URI and every header are re-checked for control bytes before forwarding;
   Content-Length is re-derived from the final body.
7. **No SSRF / local-service breakage.** A secret can't be bound to a cloud-metadata
   endpoint, a loopback address, or a malformed host — those are rejected at creation,
   so the secret keeper can never be turned into an SSRF primitive or made to intercept
   local tooling.
8. **Network settings are touched only when already armed.** Adding/removing a secret
   refreshes the PAC _only if the proxy is already running_, on a background thread, with
   the result ignored — so toggling secrets never enables a proxy the user didn't, never
   stalls the UI, and a failed refresh leaves the prior working configuration in place.
   Existing crash/quit handlers already sweep all PAC + manual proxy settings off every
   network service, so no stale state survives.
9. **Fail toward the connection, not against it.** Every unexpected condition forwards the
   original request rather than corrupting it; the only hard stops are the explicit,
   audited exfil blocks above.

## Testing & monitoring (the failure mode is catastrophic, so this is layered)

Breaking a _clean_ LLM request is the unacceptable failure. Three independent layers
guard against it:

1. **Structural gate (runtime).** The rewriter `apply()` runs only when
   `SecretInjectionPass.hasTrigger` — an independent, deliberately-simple check — confirms
   the request actually contains a placeholder or a real secret value. `hasTrigger` is a
   strict superset of every condition under which `apply` acts, so a clean request (no
   secret material) never reaches the rewrite logic at all. A bug in `apply` therefore
   _cannot_ corrupt or block clean traffic — the code that would touch it never runs.

2. **Runtime self-test + circuit breaker (`SecretKeeperMonitor`).** At every launch, a
   battery of canonical vectors is run through the live pass and every invariant is
   verified _in this binary_: clean traffic untouched, provider auth injected, third-party
   leak blocked, own-host value forwarded, misdirected placeholder blocked. If any check
   fails, the breaker trips — the proxy forwards **everything** untouched and the feature
   is disabled — and the user is alerted (Settings → Secrets shows the disabled state).
   Containment over correctness: a broken rewriter is turned off, not left running.

3. **Test suite + CI gate.** Covered by:
   - **Property/fuzz** (`SecretKeeperFuzzTests`): 4,000 randomized requests assert
     _no secret material ⇒ `apply` is a byte-perfect identity_; 1,600 more assert correct
     inject/block routing across random hosts.
   - **End-to-end** (`E2EProxyTests`): real CONNECT + TLS + NIO through the actual proxy
     prove a clean provider request reaches the upstream byte-for-byte (body + auth
     header intact, 200), a leak is blocked (403, upstream sees nothing), a bound
     placeholder is injected, and an over-cap body is forwarded untouched.
   - **Unit**: the pass, store, host/value validation, egress policy, self-test, breaker.

   CI (`build-desktop` on macOS) runs these on every push/PR, with a dedicated
   **"Secret keeper safety invariants (must pass)"** step that fails fast and unmistakably
   if the core guarantees ever regress.

## Why placeholder-replacement (not header-injection)

The LLM emits the placeholder, so the placeholder _is_ the unit of trust it can reason
about. Replacing it is general (works in any header or any JSON field — `curl`, SDKs,
GraphQL) and keeps the exfil model simple: the placeholder appearing anywhere
unexpected is a signal, not a silent no-op.

## Egress enforcement

By default every non-intercepted host is blind-tunnelled, so an agent that talks to an
un-inspected host (or unsets `HTTPS_PROXY`) can still reach the network — the same
caveat Agent Vault states. For regulated deployments, MDM can set:

```xml
<key>failClosedEgress</key><true/>
<key>egressAllowlist</key><array><string>github.com</string></array>
```

With `failClosedEgress` on, any host Bouclier doesn't inspect and isn't on the
allowlist is refused (`403`) instead of tunnelled — closing the un-inspected-host
exfil path. The decision is the pure, unit-tested `SystemProxy.tunnelAllowed`.

## Known limits (honest)

- **MITM of third-party hosts.** Injecting into `api.stripe.com` means terminating TLS
  for it with the Bouclier CA. Fine for a dev's own machine (the CA is already trusted),
  but it widens what the proxy decrypts. Only hosts with a secret rule are added to the
  intercept set — no rule, no MITM. A client that _certificate-pins_ a bound host (some
  SDKs/mobile clients) will reject the Bouclier leaf cert and fail to connect to that
  host — the failure is isolated to the bound host and reversible by removing the secret.
  The Settings UI warns about this when a host is bound.
- **System Extension path.** The transparent System Extension intercepts a fixed AI-host
  list; secret hosts are reached via the PAC / `HTTPS_PROXY` path (which is how CLI
  agents — the target use case — egress). GUI-app traffic to a secret host is not
  injected.
- **Placeholder collision.** Placeholders are namespaced (`__BOUCLIER_SECRET_<name>__`);
  the store rejects rule names that aren't `[a-z0-9_]+`.
- **`HTTPS_PROXY` can be unset** by the agent unless `failClosedEgress` + network
  controls are in place (the inherent credential-proxy caveat).
