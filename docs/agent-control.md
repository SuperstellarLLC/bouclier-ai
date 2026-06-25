# Driving Bouclier from an AI agent

Bouclier is built so an AI coding agent (Claude Code, Cursor, …) can **use**
it on its own — check whether protection is on, discover and use secrets,
ask the user for new ones — while never being able to **weaken** it. Two
surfaces, one shared core (so they enforce the same rules):

- **MCP server** — `bouclier-ai-secrets-mcp` (stdio). Register with
  `claude mcp add bouclier -- /Applications/Bouclier.app/Contents/MacOS/bouclier-ai-secrets-mcp`.
- **CLI** — `bouclier` (on `PATH` after `bouclier install`). For agents that
  drive via Bash, and for scripts.

## The guardrail model

Every operation is classified, and the gate lives in the shared Swift core —
not in the model, and not bypassable via `--force`:

| Tier          | Operations                                                                                                         | Who can do it                                                        |
| ------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| 🟢 **GREEN**  | `status`, `list_secrets`, `set_env`/`clear_env`, `request_secret(s)` (use/provision)                               | the agent, freely — no value is ever returned                        |
| 🟡 **YELLOW** | `enable_protection`                                                                                                | the agent _proposes_; the **user approves** in Bouclier's own dialog |
| 🔴 **RED**    | read a secret value · **disable** protection · install a CA / extreme mode · uninstall · set the generator command | **never** via agent — user-only, in the app                          |

The RED tier is the EDR "tamper-protection" principle applied to an AI
firewall: the agent the firewall is watching must not be able to turn the
firewall off. There is deliberately **no** `disable_protection` tool and no
CLI path to it (`bouclier protection disable` exits `7` and tells you to use
the app). And no tool, ever, returns a secret value.

## Typical flow

```bash
bouclier status --json                 # orient: is protection on? which mode? healthy?
# → {"ok":true,"state":"running","status":{...}}  (or "not_running")

bouclier protection enable             # if off: ask the user to turn it on (they approve)
bouclier secrets list                  # see what's available (names only)
bouclier secrets request STRIPE_KEY \  # ask the user to paste/generate one
  --reason "deploying the billing service" --generate
bouclier env set STRIPE_KEY            # activate it for new shells
# … then in a NEW shell: curl -H "Authorization: Bearer $STRIPE_KEY" …
```

The value reaches your subprocess environment via the Keychain at shell
init — it never passes through the MCP channel, the CLI output, or the
model's context.

### Requesting many secrets at once

`request_secrets` accepts any number of env vars. A single approval dialog
is capped for sanity, so large sets are split into as many dialogs as
needed and the results are **aggregated** — nothing is ever silently
dropped. The response (and `--json`) accounts for every var:

- **provided** — the user supplied a value; available in new shells.
- **skipped** — the user deliberately left the field blank.
- **pending** — not resolved because the user stopped/declined or the app
  went away. Re-request _just these_; don't loop.

So `request_secrets(["A",…,"Z", … 80 vars])` completes across multiple
approvals and tells you exactly what landed and what's left — no truncation,
no dead-end error.

## Status snapshot

The app publishes a read-only `status.json` (5s heartbeat) that the MCP
server / CLI read. A stale (>20s) or orphaned snapshot is reported as
**not running** — never trusted as live. Fields are counts only:
`running`, `mode`, `caInstalled`, `secretKeeper{enabled,healthy,circuitBreakerTripped}`,
`secrets{total,agentAccessible,active}`, `activity{…}`. No values.

## MCP tool annotations

Tools carry MCP safety hints so clients prompt appropriately:
`status`/`list_secrets` are `readOnlyHint:true`; `enable_protection`,
`set_env`, `clear_env` are non-destructive + idempotent;
`request_secret(s)` are non-destructive. Everything is `openWorldHint:false`
(all local). Hints are advisory — the real gate is core-enforced.

## CLI exit codes

`0` ok · `2` usage · `4` Bouclier not running · `5` user declined ·
`6` timed out (no human response) · `7` denied (locked secret, or a RED
operation). `status` always exits `0` (a successful read of "not running"
is still a successful read); use the `state` field to branch.

## Install / discovery

`bouclier install` prints the two commands to run: the `sudo ln -s …` to put
`bouclier` on your `PATH` (so Bash agents find it) and the `claude mcp add …`
to register the MCP server. It's print-only by design — the CLI doesn't
mutate `/usr/local/bin` itself (that's a privileged step a human should run).
Afterward, `which bouclier` answers "installed?"; `bouclier status` answers
"running?".
