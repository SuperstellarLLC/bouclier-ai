# Changelog

All user-facing changes to Bouclier.ai. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
follows [semantic versioning](https://semver.org/).

The `[VERSION]` section for each release is extracted verbatim by
`apps/desktop/scripts/publish-update.sh` and injected into the Sparkle
appcast. Write for end users, not for internal engineering notes.

## [0.9.2] — 2026-08-08

### Changed

- **Monitor by default; blocking is opt-in.** The gateway used to refuse a flagged request outright, which meant a false positive on tool output could wedge a normal agent session (the whole conversation is resent each turn, so one benign-but-matching result kept failing on every retry). Bouclier now **detects and logs by default and forwards the request** — it can't break normal work. Turn on enforcement to get refusals: `defaults write ai.bouclier.app injectionBlockEnabled -bool true`, or push it fleet-wide by MDM. Your own prompts are never blocked in either mode.

### Removed

- **The secret keeper is gone.** The feature that stored managed credentials in your Keychain, scrubbed their real values out of outbound requests, and restored them in the response has been removed entirely — along with its agent secret-request flow, the `bouclier secrets` / `bouclier env` / `bouclier protection` CLI commands, and the secrets MCP server. It was off by default, under-tested, and marginal in practice (API keys live in request headers, not prompt bodies). Bouclier is now a focused prompt-injection firewall. The gateway is a byte-faithful transparent relay: it forwards a request unmodified or refuses it, and never rewrites. The `bouclier` CLI is read-only (`status`, `install`); the injection MCP server is unchanged. If you relied on the secret keeper, keep your credentials wherever your tools already read them.

### Security

- The security policy and threat model now describe the live attack surface accurately: the injection firewall is the primary control (they previously described it as dormant), and the secret-scrub invariants are gone. Public contact is `apps@superstellar.io`, and the `/blocked` page and `SECURITY.md` were trimmed to avoid over-exposing detection internals.

## [0.9.1] — 2026-08-03

### Added

- **On-device ML detection is back (Meta Prompt Guard 2).** The 86M classifier is bundled again and fused with the regex tier, so novel, paraphrased, and multilingual injections the pattern set misses get caught — all on-device (CoreML, no network; your traffic never leaves the machine to be classified). The tradeoff is download size (~300 MB vs ~6 MB), which is the price of local-only inference. It's a small classifier, not a frontier judge — it raises recall but is still evadable under adaptive/encoding attacks. The weights are gated (Meta HuggingFace) and produced at release time by `scripts/ensure-model.sh`, not committed to the repo.
- **Retrieved content is treated as untrusted, even inside a user turn.** Previously only `tool_result` / `role:"tool"` / `function_call_output` were untrusted, so a poisoned document or search result pasted into a user message slipped through as "your own text." Now Anthropic `document` and `search_result` blocks — and anything wrapped in the `<document>` RAG convention embedded in principal text — are inspected as untrusted. Your own words around a quoted document are still principal and never blocked.

### Fixed

- **Far fewer false positives on tool output.** The gateway used to refuse a request whenever tool output matched _any_ critical pattern, with no regard for context — so an agent reading an OWASP advisory, a security tutorial, a fenced code block, or a page that merely _quotes_ "ignore all previous instructions" could get a hard 403, and because the whole conversation is resent each turn, one benign-but-matching tool result could wedge the session on every retry. The false-positive dampeners that the pattern benchmark already measures (academic/tutorial/quoted/fenced-code/OWASP-reference context) are now applied on the desktop path too: a match inside benign context has its weight reduced and is **flagged-and-forwarded** instead of blocked. A genuine injection with no such context still blocks. This brings the desktop false-positive rate on the benign corpus from ~4.2% toward the benchmark's ~2.9%.

### Changed

- The untrusted-content block decision is now purely score-based (dampeners apply) rather than "any critical match blocks." An undampened critical pattern still drives the score to a hard block; a dampened one is logged and forwarded.

## [0.9.0] — 2026-08-02

### Added

- **Bouclier is a prompt-injection firewall again.** The detection engine is live for the first time since v0.7.0 — and for the first time ever without a certificate. It now runs inside the loopback gateway, which already sees every request body in plaintext before re-issuing it upstream. No root CA, no System Extension, no system-wide network filter: the machinery that used to be a prerequisite for detection turns out never to have been one.
- **It refuses attacks in tool output, and leaves your own prompts alone.** Bouclier splits each request by where the text came from. Content your agent fetched by itself — `tool_result` blocks, `role: "tool"` messages, `function_call_output` items — is untrusted: an instruction in there came from a web page, a README, or an MCP server, and the request is refused. Your own prompt and system prompt are scanned for the activity log and then **forwarded byte-for-byte, whatever they say**. You can paste an OWASP advisory or test a jailbreak against your own model without Bouclier getting in the way.
- **Refusals explain themselves.** A blocked request returns a `403` with a provider-shaped JSON error naming the pattern that matched and the exact JSON path it came from (`messages[2].content[0].tool_result`), so your SDK raises a readable error instead of dying on a closed socket. Details at <https://www.bouclier.ai/blocked>, which is back.
- **Live playground on the homepage, rebuilt around the provenance split.** Paste anything, flip the origin toggle, and watch the same sentence get refused as tool output and forwarded as your own prompt. The regex tier runs in your browser; nothing is uploaded.
- **Strict mode for managed fleets.** `injectionStrict` (MDM only, off by default) also blocks detections in the operator's own prompt, for organisations that want it and accept the false positives.

### Fixed

- **The shipped pattern file was three months stale.** `patterns.json` in the app's resources still held the 35 patterns generated on 2026-04-04, while the source package had grown to 161 across 21 categories. Release builds resynced it, but every developer build ran on the old set. It is now regenerated and checked in, and a test fails the build if it drifts again.
- **One detector never worked on macOS at all.** `encode-004`, the ASCII-smuggling detector for invisible Unicode Tags characters (U+E0020–U+E007E), was written with JavaScript's `\u{…}` escape. `NSRegularExpression` is ICU, which rejects that syntax outright, and `FilterPattern(from:)` drops any pattern that fails to compile _silently_ — so the detector simply did not exist in the Swift engine. Patterns can now carry an ICU-specific form, and a test asserts all 161 compile.

### Changed

- **Nothing rewrites your prompt. Ever.** The old engine replaced matched spans with a redaction notice — and, when only the ML or entropy signal fired, replaced the _entire_ prompt body with a one-line notice and forwarded it anyway. That behaviour is not coming back with the engine: a request is now either forwarded unmodified or refused outright. This keeps the v0.6.0 promise (text bodies reach the provider untouched) rather than quietly reversing it.
- **Flagged is not blocked in the activity log either.** Detections that don't meet the refusal bar are recorded with their score and pattern names but without the red shield, closing the same honesty gap v0.6.1 fixed for the ML/entropy path.
- Homepage leads with injection defence; the secret keeper is now presented as what it is — the other half of containing a hijacked agent, still opt-in under Settings → Secrets.

### Known limits

- **The on-device ML tier is still not bundled.** Prompt Guard 2's weights were removed in v0.7.0 to get the download from ~600 MB to ~6 MB, and they stay out. Detection is the 161-pattern regex tier plus an entropy heuristic. The fused scorer and the CoreML loader are intact, so supplying a model locally lights the ML tier back up.
- **This is defence in depth, not a solution.** Prompt injection is unsolved, and a pattern engine is evadable by anyone who is trying. The defences that actually hold are structural — constraining what a hijacked agent can reach. Bouclier raises the cost of the easy attacks and shows you when one arrives. Treat it like a WAF, not like a proof.

## [0.8.0] — 2026-07-03

### Added

- **Install the `bouclier` CLI with one click.** Settings → General has a new "Install bouclier command" button that puts `bouclier` on your PATH via the standard macOS administrator-privileges prompt (Touch ID / password) — no more copying a `sudo ln -sf …` command into Terminal. A "Copy Claude Code MCP command" button sits next to it to register the MCP server in one paste.

## [0.7.0] — 2026-07-02

### Removed

- **Extreme mode is gone.** The CA-based "full interception" mode — installing a trusted root certificate and a System Extension to decrypt and inspect all AI traffic system-wide — has been removed entirely. Standard mode (the certificate-free gateway your agent's SDK points at via `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`) is now the only way Bouclier runs. If you had extreme mode enabled, this update automatically uninstalls the CA from your Keychain, deactivates the System Extension, and clears any leftover system proxy configuration — no action needed.
- **Prompt-injection and attachment PII detection are no longer active.** That engine only ever ran through extreme mode's interception path, so removing extreme mode removes it from your outbound traffic too. The secret keeper (scrub real credential values before they reach the model, restore them in the response) is unaffected and remains Bouclier's primary protection. Settings → Privacy (the attachment-scanning toggle and redaction audit) is gone with it.
- **The on-device ML models are no longer bundled.** Nothing has called them since extreme mode's removal, so the app no longer ships ~600MB of model weights it never uses. A typical install is now ~6MB instead of ~600MB.

### Changed

- Settings → Protection is simplified to a single mode: no more mode picker, CA status, or System Extension status. It now shows gateway status, certificate status (not needed), and secret-keeper status.
- Patched all known dependency vulnerabilities (`vitest`, `vite`, `undici`, `esbuild`, `@babel/core`, `js-yaml`).

## [0.6.1] — 2026-05-27

### Fixed

- **"Blocked 0 injection(s):" log mystery.** When the ML classifier or entropy heuristic flagged a request without any specific regex pattern matching, the activity log showed _"Blocked 0 injection(s) → host:"_ with a trailing colon and no detail — read as a bug to anyone watching. The log now surfaces these as _"Flagged by ML/entropy (score 0.55) → host — forwarded unchanged"_ with the red shield reserved for actual regex-driven blocks. The fused score is included in both branches so you can triage at a glance.

## [0.6.0] — 2026-05-27

### Changed

- **Bouclier no longer modifies your text prompts.** Earlier versions replaced detected PII with reversible placeholders before forwarding; that approach was tripping Anthropic's abuse detection and risked touching analytics fields (like OpenAI's `user`) inside JSON bodies. Text bodies now reach the LLM unchanged. A new end-to-end test pins this against future regressions.
- **PII protection is now attachment-focused.** Images, PDFs, and short audio clips you attach to LLM requests are still scanned on-device for PII; flagged attachments are replaced with a plain-English description so the model can still answer.
- **Auth, API keys, and trace headers are forwarded byte-for-byte.** A new regression test sends `Authorization`, `x-api-key`, `X-Trace-ID`, and `User-Agent` through the proxy and asserts the upstream sees them unmodified.
- **Settings → Privacy is one screen.** The text-redaction toggles, preview-before-send, strict-credentials mode, and per-host allow/deny lists are gone — the file-inspection toggle, audit counts, and PDF report stay.

### Removed

- Text-prompt PII redaction, the per-connection token session, the response-path reverser, the SSE stream reverser, the per-host PII policy, the operator pause switch, and the pre-send preview modal. Pre-v0.6 audit rows from these are wiped on first launch; orphan UserDefaults keys are cleared in the same one-shot migration.

## [0.5.3] — 2026-05-25

### Fixed

- **A Bouclier crash no longer leaves your system pointing at a dead proxy.** A small watchdog now runs once a minute in the background, and if Bouclier ever stops responding, it cleans the proxy environment off your session within 60 seconds. Apps you launch from Spotlight/Dock after a crash work normally instead of failing on a stale pointer.

## [0.5.2] — 2026-05-25

### Fixed

- **Quitting Bouclier no longer breaks every CLI tool.** When the proxy isn't running, your shell now skips the proxy env entirely and CLI tools (`git`, `npm`, `curl`, `claude`) talk direct instead of failing with "connection refused."
- **API keys in your prompts aren't redacted on the way to LLMs.** Pasting `OPENAI_API_KEY=…` into a chat to debug it now reaches the model unchanged — Bouclier still strips actual PII (emails, addresses, IDs) but treats keys, tokens, and secrets as functional context the model needs to help. Settings → Privacy → "Also strip credentials (strict mode)" opts back in.

## [0.5.1] — 2026-05-24

### Changed

- Improved PII stripping logic.

## [0.5.0] — 2026-05-24

### Added

- **Command-line AI tools captured automatically.** Bouclier now wires Claude Code, Cursor, the OpenAI / Anthropic Python SDKs, and any other Node or Python CLI through the proxy on its own — no `eval $(bouclier-ai-env)` step. Toggleable from Settings → General if you have a corporate proxy that conflicts.
- **Everything else still goes direct.** Traffic to non-AI hosts (`git`, `npm`, `brew`, `curl`, your dev servers) tunnels straight through Bouclier unmodified. Cloud-instance metadata endpoints stay blocked.

### Changed

- **Protection is on the moment the app launches.** Previously the shield rendered "off" on every restart until you opened the menubar. Now it's armed at launch as soon as you've completed onboarding.

### Fixed

- **"What's new" sheet no longer reappears after dismissal.** Closing via the window's close button now counts the same as the buttons inside.

## [0.4.0] — 2026-05-18

### Added

- **Multimodal PII inspection (beta).** Bouclier now inspects images, PDFs, and audio you attach to AI prompts — OCRs them on-device, transcribes audio with Apple Speech, and strips any attachment that contains PII before forwarding. Works for OpenAI, Anthropic, and Gemini chat APIs, plus the OpenAI and Anthropic Files APIs.
- **Faces in images** are detected and count as PII (GDPR Art. 4).
- **Encrypted PDFs** are stripped automatically because we can't inspect them — never silently forwarded.
- **Body cap raised** from 10 MB to 64 MB so the typical multimodal payload fits inline.

### Changed

- Settings → Privacy toggle is now "Inspect images, PDFs, and audio in outbound multimodal prompts" and actually takes effect for non-MDM users (the underlying flag now reads UserDefaults too).
- A 30-second wall-clock budget caps multimodal inspection so a single pathological request can't blow past your AI client's read timeout.

## [0.3.3] — 2026-05-17

### Added

- **Native phone and address detection.** Uses macOS's built-in `NSDataDetector` — handles international formats and multi-line addresses that regex can't.
- **On-device ML tier (Piiranha).** Catches PERSON, USERNAME, DATE_OF_BIRTH, driver's licence, medical licence, tax and bank account numbers — categories regex can't see. Loads in the background; the rest of the proxy keeps working if the model file isn't bundled yet.

## [0.3.2] — 2026-05-17

### Added

- **50+ new secret detectors.** API keys, OAuth tokens, webhooks, and connection strings — OpenAI, Anthropic, GitHub, Slack, Stripe, Twilio, SendGrid, AWS, GCP, Azure, and 20+ more.
- **PEM and SSH private keys** detected across line boundaries.
- **Generic high-entropy fallback** catches credentials that don't match a provider-specific shape but still look like bearer material in a key-value context.

### Fixed

- Disambiguated `sk-…` provider variants so `sk-ant-…` is no longer misclassified as an OpenAI key.

## [0.3.0] — 2026-05-17

### Added

- **PII redaction.** Sensitive data is replaced with reversible placeholders before prompts leave your Mac, then restored on the response. Off by default — turn it on under Settings → Privacy.
- **Per-domain rules.** Skip redaction for hosts that already enforce compliance or break with placeholders.
- **Pause button.** Snooze redaction from the menu bar for 1, 5, 15, or 60 minutes.
- **Preview before send.** Confirm what's being redacted on your first prompts of each session.
- **Redaction report.** Export a one-page PDF of activity for compliance handoff.
- **Beta branding & Terms of Use.** Bouclier is now clearly labelled a prototype with explicit, defensive terms.

### Changed

- **New tagline.** "Stop prompt injections. Stop PII from leaking to LLMs."

### Fixed

- Span-overlap resolution in the redactor so longer matches always win.

## [0.2.12] — 2026-04-17

### Fixed

- Tokenizer load still failed in v0.2.11 with
  `unsupportedTokenizer("DebertaV2Tokenizer")` — swift-transformers'
  registry doesn't know that class name. The underlying model in
  tokenizer.json is Unigram SPM, which is exactly what T5Tokenizer
  (a trivial `class T5Tokenizer: UnigramTokenizer {}` subclass in
  swift-transformers) routes to. Renamed the `tokenizer_class` label
  to `T5Tokenizer` in tokenizer_config.json so lookup succeeds;
  tokenization behaviour is unchanged because it's driven by
  tokenizer.json. convert-promptguard.py applies the same rewrite
  automatically on future runs.

## [0.2.11] — 2026-04-17

### Fixed

- ML classifier (Meta Prompt Guard 2) still wasn't loading in v0.2.10.
  The tokenizer download script was missing `config.json` from its
  allow-list, so swift-transformers' `AutoTokenizer.from(modelFolder:)`
  threw `configurationMissing("config.json")` — it reads `model_type`
  from that file to dispatch to the right tokenizer class. Added to
  the download script and bundled the file directly so fused detection
  finally lights up.

## [0.2.10] — 2026-04-17

### Fixed

- ML classifier (Meta Prompt Guard 2) still wasn't actually loading in
  v0.2.9. CoreML refuses raw `.mlpackage` files at runtime ("Compile the
  model with Xcode or MLModel.compileModel(at:)") and SwiftPM doesn't
  auto-compile. Release builds now pre-compile to `.mlmodelc` via
  `xcrun coremlcompiler`; dev builds fall back to an on-demand compile
  cached in Application Support. Fused detection (regex + ML + entropy)
  is live for real this time.

### Changed

- ML-error badge in the menu bar is now click-to-copy — clicking copies
  the raw CoreML / tokenizer error string to the clipboard so it can be
  pasted into bug reports without screenshotting a tooltip.

## [0.2.9] — 2026-04-17

### Added

- Version number shown in the bottom-right of the menubar popover, so you
  can see at a glance which build you're running without opening Settings
  → About. Clickable to trigger a manual update check when Sparkle is
  ready.

## [0.2.8] — 2026-04-17

### Fixed

- ML classifier (Meta Llama Prompt Guard 2) never actually loaded in
  shipped builds — the resource lookup pointed at the wrong bundle, so
  every install since v0.2.6 silently ran on regex-only detection. Fused
  detection now activates at launch as intended.
- "Check for Updates…" menu-bar button was permanently disabled because
  the updater flag was never wired to Sparkle's own state.
- Onboarding "Enable Protection" spinner could unblock before the proxy
  was actually running. The spinner now clears when the proxy is ready
  or when setup surfaces an error.

### Added

- "Run detection test" button in the menu bar — sends a synthetic
  injection through the live filter and shows a pass/fail verdict inline.
- Three-state ML classifier badge: active, loading, or unavailable with
  the reason in a tooltip. No more indefinite "loading…" when the model
  can't load.
- Subtle motion across menu-bar state changes — animated stat counters,
  spring transitions on status and alert banners, symbol morphs on the
  ML indicator.

### Changed

- New app icon (clean blue shield) replaces the placeholder.
- Menu-bar popover widened 280pt → 300pt so blocked-event messages stop
  truncating mid-line.

## [0.2.6] — 2026-04-12

Earlier releases — see git history.
