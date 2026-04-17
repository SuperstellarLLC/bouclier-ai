# Changelog

All user-facing changes to Bouclier.ai. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
follows [semantic versioning](https://semver.org/).

The `[VERSION]` section for each release is extracted verbatim by
`apps/desktop/scripts/publish-update.sh` and injected into the Sparkle
appcast. Write for end users, not for internal engineering notes.

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
