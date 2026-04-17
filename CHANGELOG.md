# Changelog

All user-facing changes to Bouclier.ai. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
follows [semantic versioning](https://semver.org/).

The `[VERSION]` section for each release is extracted verbatim by
`apps/desktop/scripts/publish-update.sh` and injected into the Sparkle
appcast. Write for end users, not for internal engineering notes.

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
