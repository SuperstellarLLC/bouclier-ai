# Secret keeper

Status: **Shipped, behind `secretInjection` feature flag (off by default).**
Configure under **Settings → Secrets**. Secrets live in the macOS Keychain and
never leave this Mac; every event flows through the activity feed, notifications,
the SIEM audit log, and on-disk stats.

The secret keeper protects managed credentials via **scrub → restore** on the
LLM channel — the gateway (`GatewayServer`) is the only proxy path (a
previous "extreme mode," a CA-based TLS-intercepting proxy that also
supported destination-bound injection, was removed; see the "Dormant:
destination-bound injection" appendix below). The placeholder format is
`__BOUCLIER_SECRET_<name>__` (ASCII, regex-inert, reproduced verbatim by
LLMs).

## Scrub → restore

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
- **Honest threat model.** The secret keeper does **not** hide the secret from
  the agent — the real value _is_ restored into the response the agent consumes, so
  it lives in the local transcript. The guarantee is precise and true: **your
  credential never leaves this machine for the model provider.**
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
claude mcp add bouclier-secrets -- /Applications/Bouclier-ai.app/Contents/MacOS/bouclier-ai-secrets-mcp
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
   the real value back toward the model, it's replaced with the placeholder.

**Authorization.** Each secret has an `agentAccess` flag (default on; toggle
in Settings → Secrets). The MCP server refuses `set_env` for a locked
secret. This bounds the blast radius if the agent is prompt-injected; note
that Bouclier can't see the agent's _direct_ third-party traffic, so a
determined injected agent could still misuse an unlocked secret it's
allowed to use — lock sensitive secrets you don't want an agent acting on
autonomously.

**Components:** `Sources/BouclierSecretsCore` (shared, dependency-free:
`SecretRuleMeta`, `SecretEnvManifest`, `SecretEnvResolver`, `KeychainSecretReader`,
`SecretsMCPHandler`), `Sources/SecretsMCP` (the stdio server binary),
`Sources/EnvHelper` (`bouclier-ai-env --secrets`). Paths/Keychain service are
overridable via `BOUCLIER_APP_SUPPORT_DIR` / `BOUCLIER_KEYCHAIN_SERVICE` for
tests. No-prompt cross-binary Keychain access requires the helper to share
the app's keychain-access-group entitlement (a packaging/signing step);
without it macOS prompts the user — explicit consent, never silent.

## Components (live path)

| File                              | Role                                                                                                                                                                                                                          |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Proxy/SecretRule.swift`          | The rule model: `name`, `placeholder`, `allowedHosts`. `Codable`. `allowedHosts` still validates and stores host bindings, but nothing currently acts on them (see appendix).                                                 |
| `Proxy/SecretStore.swift`         | Keychain-backed store. Rule metadata in a JSON file under Application Support; secret _values_ in Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). In-memory cache so the event-loop path never blocks on Keychain. |
| `Proxy/SecretRedactionPass.swift` | **Pure, no NIO.** Outbound scrub: managed real value → placeholder. Key-shaped values only; longest value first; `hasTrigger` integrity gate.                                                                                 |
| `Proxy/SecretRestore.swift`       | **Pure, no NIO.** Inbound restore: placeholder → real value. Byte-level, streaming, straddle-safe, exact-match only.                                                                                                          |
| `Proxy/GatewayServer.swift`       | The gateway. Scrubs on the request path; `GatewayRestoreHandler` restores on the response path (connection-close framing). Clean traffic uses a byte-faithful keep-alive relay.                                               |
| `Proxy/ProxyMode.swift`           | Single-case (`standard`) since extreme mode's removal. Kept for status-schema stability rather than deleted outright.                                                                                                         |
| `Utilities/FeatureFlags.swift`    | `secretInjection` flag, off by default.                                                                                                                                                                                       |
| `Views/SettingsView.swift`        | **Settings → Secrets** tab: toggle, add/remove rules, `SecureField` value entry, copy-placeholder, live counters.                                                                                                             |
| `Proxy/ProxyManager.swift`        | `handleSecretEvent` → activity feed, block notification, `AuditLogger`, `StorageManager` (`source: "secret-injection"`), `Metrics`.                                                                                           |

## Safety guarantees (don't break the user's LLM access; don't damage their machine)

These are enforced in code and covered by tests:

1. **Zero footprint when off / unconfigured.** With `secretInjection` off, the pass never
   runs. On with no secrets configured, `SecretStore.shared.rules()` is empty and
   `hasTrigger` never fires. Nothing happens until the user adds a secret.
2. **Byte-identical passthrough.** A request with no key-shaped managed secret value is
   forwarded byte-for-byte (URI, headers, body). The rebuild path runs _only_ when a
   real value was actually scrubbed. So normal traffic to OpenAI / Anthropic / Cursor
   is never altered.
3. **No false-positive scrubs.** The trigger arms only on key-shaped values
   (≥16 chars, no whitespace), so prose can't trip it.
4. **Big LLM requests are never slowed or touched.** Bodies over 1 MiB (vision images,
   file uploads) are not body-scanned — only URI + headers — and the original body is
   forwarded unchanged.
5. **No request smuggling.** Secret values with CR/LF/NUL are rejected at the store; the
   rewritten URI and every header are re-checked for control bytes before forwarding;
   Content-Length is re-derived from the final body.
6. **No SSRF / local-service breakage.** A secret can't be bound to a cloud-metadata
   endpoint, a loopback address, or a malformed host — those are rejected at creation
   (`SecretRule.validatedHost`, `NetworkGuards.isCloudMetadataHost`,
   `CorporateProxy.isLoopbackHost`).
7. **Config changes never desync scrub and restore mid-connection.** The rule set used
   for scrub is pinned at the first request on a keep-alive connection; if live config
   diverges from that pinned set on a later request, the connection is refused with a
   retryable `503` instead of scrubbing against a stale rule set — the client reopens a
   fresh connection that picks up the new config.
8. **Fail toward the connection, not against it.** Every unexpected condition forwards the
   original request rather than corrupting it.

## Testing & monitoring (the failure mode is catastrophic, so this is layered)

Breaking a _clean_ LLM request is the unacceptable failure. Three independent layers
guard against it:

1. **Structural gate (runtime).** The rewriter `apply()` runs only when
   `SecretRedactionPass.hasTrigger` — an independent, deliberately-simple check — confirms
   the request actually contains a real secret value. `hasTrigger` is a strict superset
   of every condition under which `apply` acts, so a clean request (no secret material)
   never reaches the rewrite logic at all. A bug in `apply` therefore _cannot_ corrupt
   clean traffic — the code that would touch it never runs.

2. **Runtime self-test + circuit breaker (`SecretKeeperMonitor`).** At every launch, a
   battery of canonical vectors is run through the live pass and every invariant is
   verified _in this binary_: clean traffic untouched, correct scrub/restore round-trip.
   If any check fails, the breaker trips — the gateway forwards **everything** untouched
   and the feature is disabled — and the user is alerted (Settings → Secrets shows the
   disabled state). Containment over correctness: a broken rewriter is turned off, not
   left running.

3. **Test suite + CI gate.** Covered by:
   - **Property/fuzz** (`SecretKeeperFuzzTests`): thousands of randomized requests assert
     _no secret material ⇒ `apply` is a byte-perfect identity_.
   - **End-to-end** (the `GatewayServerTests` E2E suite, over real TLS): prove a clean
     provider request reaches the upstream byte-for-byte (body + auth header intact,
     200), and a scrub→restore round-trip leaves the model seeing only the placeholder
     while the agent gets the real value back.
   - **Unit**: the pass, store, host/value validation, self-test, breaker.

   CI (`build-desktop` on macOS) runs these on every push/PR, with a dedicated
   **"Secret keeper safety invariants (must pass)"** step that fails fast and unmistakably
   if the core guarantees ever regress.

## Why placeholder-replacement (not header-injection)

The LLM emits the placeholder, so the placeholder _is_ the unit of trust it can reason
about. Replacing it is general (works in any header or any JSON field — `curl`, SDKs,
GraphQL) and keeps the model simple: the placeholder appearing anywhere unexpected is
a signal, not a silent no-op.

## Known limits (honest)

- **Opt-in, not system-wide.** The gateway only sees traffic from processes that point
  at it (`ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`, wired automatically by
  `ShellEnvInjector` for shells that source the generated dotfiles). A process that
  unsets those vars, or was never captured, bypasses the gateway — and the scrub/restore
  protection — entirely.
- **Placeholder collision.** Placeholders are namespaced (`__BOUCLIER_SECRET_<name>__`);
  the store rejects rule names that aren't `[a-z0-9_]+`.

## Dormant: destination-bound injection

Earlier versions supported a second mechanism, live only through "extreme
mode" (a CA-based TLS-intercepting proxy, removed — see `ARCHITECTURE.md`):
when an agent made an outbound tool call to a secret's **bound host** (e.g.
`api.stripe.com`), Bouclier would swap the placeholder for the real value at
that host — the agent never held the real value at all, versus the live
scrub/restore mechanism above where the agent does see the restored value in
its transcript.

This code (`SecretInjectionPass.swift`) is still in the tree, unmodified,
and still exercised directly by unit tests, but it has had **no live caller**
since extreme mode's `TLSProxy`/`HTTPInspectionHandler` — its only production
caller — was removed. `SecretRule.allowedHosts` still validates and stores
host bindings (the Settings UI still lets you bind a secret to a host), but
nothing currently reads that binding to act on it. It remains available if
destination-bound injection is ever wired into the gateway as a deliberate
follow-up; until then, treat `allowedHosts` as inert metadata.
