# Contributing to Bouclier.ai

Thanks for your interest in improving Bouclier.ai. The project is small
and fast-moving; contributions of any size are welcome — bug reports,
documentation fixes, and core gateway/detection work.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md)
and that your contributions are licensed under
[Apache-2.0](LICENSE).

## Quick links

- Found a security issue → [SECURITY.md](.github/SECURITY.md)
- Have a question → [Discussions](https://github.com/SuperstellarLLC/bouclier-ai/discussions)
- Architecture overview → [ARCHITECTURE.md](ARCHITECTURE.md)
- Threat model → [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## Repository layout

```
apps/
├── desktop/       Swift menubar app + gateway
└── site/          Next.js marketing & docs site

packages/
└── patterns/      Injection + PII pattern library (the injection tier is
                    live via the gateway; see ARCHITECTURE.md)

docs/              Threat model
```

## Development setup

Prerequisites:

- Apple silicon Mac running macOS 15 (Sequoia) or later for the desktop app.
- Xcode 16 + Command Line Tools.
- Node 22 (`.nvmrc` in repo root) and `pnpm` 9.
- `swift --version` must report 6.0 or later.

```bash
git clone https://github.com/SuperstellarLLC/bouclier-ai.git
cd bouclier-ai
pnpm install
```

### Site & shared packages

```bash
pnpm dev --filter site         # http://localhost:3000
pnpm build                     # builds every workspace
pnpm check                     # typecheck + lint + tests + format check
```

### Desktop app

```bash
cd apps/desktop
swift build                    # debug build
swift test                     # full test suite (≈ 2 s)
swift run Bouclier             # run the binary directly
```

The Xcode project is generated from `project.yml` with
[xcodegen](https://github.com/yonaskolb/XcodeGen):

```bash
brew install xcodegen
xcodegen
open Bouclier.xcodeproj
```

The regex detection engine ships in the app. Generated CoreML weights are
not checked into git, and `swift build`/`swift test` do not need them;
`MLClassifier`/`PIIClassifier` degrade gracefully when the resources are
absent. The release pipeline generates and bundles Prompt Guard 2. If you
are working on that classifier tier locally, the model-generation scripts
remain available (the generated artifacts are too large for git and are not
fetched by default):

```bash
apps/desktop/scripts/ensure-model.sh         # downloads + compiles PromptGuard 2
apps/desktop/scripts/convert-promptguard.py  # PromptGuard 2 → CoreML
apps/desktop/scripts/convert-piiranha.py     # Piiranha → CoreML
```

## Pull request workflow

1. Open an issue first for non-trivial work so we can agree on the shape
   before you invest time.
2. Branch from `main`. Keep PRs focused — one concern per branch.
3. Follow [Conventional Commits](https://www.conventionalcommits.org/);
   commitlint runs in `commit-msg` hook.
4. Add or update tests. The Swift suite must stay green
   (`swift test` from `apps/desktop`).
5. Run `pnpm check` before pushing. CI mirrors the same checks.
6. Update `CHANGELOG.md` for user-visible changes only — internal
   refactors do not need an entry.
7. Open the PR using the template and link the issue.

A maintainer will respond within a few business days. PRs that come with
a regression test are reviewed first.

## Adding a detection pattern

Patterns live in `packages/patterns/src/` and are part of the shipped
gateway detector. The TypeScript source is compiled and synchronized into
the desktop bundle; CI rejects drift between the two copies. A pattern change
therefore changes live Monitor/Blocking behavior and needs false-positive as
well as attack coverage.

Each pattern must include:

- A clear name, category, and severity.
- A regex or structural validator.
- At least one **positive** and one **negative** test case in the
  adjacent `__tests__` file.
- A short comment describing the attack class and any
  community / paper / CVE reference, when applicable.

Run `pnpm --filter @bouclier-ai/patterns test`, then
`apps/desktop/scripts/sync-patterns.sh` and `pnpm check` to validate the
shared package and regenerated desktop bundle.

## Coding style

- TypeScript: `prettier` + `eslint`. `pnpm format` autofixes both.
- Swift: ship the standard Apple style — 4-space indent, no trailing
  whitespace. Optional braces for one-liners are fine; prefer
  expressivity over cleverness.
- No comments that restate the code. Only explain _why_ (non-obvious
  constraint, invariant, or workaround).
- Tests describe a behaviour, not a method (`@Test("forwards unchanged
when ...")` rather than `testForward()`).

## Privacy invariants

Routine scan and audit paths must not log, persist, or transmit cleartext
request content. They record bounded metadata and hash prefixes, never the
value. A content-bearing feature requires a narrow, explicit user action,
clear disclosure, review before transmission, strict size/retention limits,
and tests that keep it off the routine path. Today the only such paths are
the opt-in local block sample and the user-confirmed false-positive report.

## Release process

Releases are cut by maintainers using
`apps/desktop/scripts/release.sh`, which builds, signs, notarises, and
publishes the appcast. Contributors do not need to run this. The
release script documents its own steps; environment variables are
described in the script header. After the signed artifacts, version files,
appcast, and matching `CHANGELOG.md` section are committed and pushed, verify
that commit on the remote, tag that exact commit as `vX.Y.Z`, and push the tag.
The tag workflow independently checks all product versions plus both Sparkle
version fields before opening a draft GitHub release. Production site builds
also refuse to deploy copy for a newer runtime until `APP_VERSION` has reached
the declared minimum; preview builds stay available for release QA.
