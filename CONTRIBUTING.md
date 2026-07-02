# Contributing to Bouclier.ai

Thanks for your interest in improving Bouclier.ai. The project is small
and fast-moving; contributions of any size are welcome — bug reports,
documentation fixes, and core gateway/secret-keeper work.

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
└── patterns/      Injection + PII pattern library (dormant — see
                    ARCHITECTURE.md; not currently invoked on live traffic)

docs/              Threat model, secret-keeper design notes
```

## Development setup

Prerequisites:

- macOS 15 (Sequoia) or later for the desktop app. macOS 14 also builds
  but is not the supported release target.
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

The CoreML models for the dormant detection engine (see "Adding a
detection pattern" below) are no longer bundled — the shipped app
doesn't need them, and `swift build`/`swift test` don't either;
`MLClassifier`/`PIIClassifier` degrade gracefully when the resource is
absent. If you're specifically working on that dormant engine and want
to exercise the classifiers locally, the generation scripts are still
available (too large for git, so not fetched by default):

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

## Adding a detection pattern (dormant subsystem)

Patterns live in `packages/patterns/src/`. This detection engine isn't
currently invoked by the shipped app — it was wired only into extreme
mode's TLS-intercepting proxy, which has been removed (see
`ARCHITECTURE.md`). Contributions here still compile, still get exercised
by the pattern package's own test suite, and remain valuable if detection
is ever wired into the gateway as a deliberate follow-up, but don't
expect a pattern PR to change the shipped app's behaviour today.

Each pattern must include:

- A clear name, category, and severity.
- A regex or structural validator.
- At least one **positive** and one **negative** test case in the
  adjacent `__tests__` file.
- A short comment describing the attack class and any
  community / paper / CVE reference, when applicable.

Run `pnpm --filter @bouclier-ai/patterns test` to validate.

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

Bouclier.ai must not log, persist, or transmit cleartext request
content. The audit log records type + offsets + a hash prefix — never
the value. Any PR that adds logging, telemetry, or persistence is held
to that bar in review.

## Release process

Releases are cut by maintainers using
`apps/desktop/scripts/release.sh`, which builds, signs, notarises, and
publishes the appcast. Contributors do not need to run this. The
release script documents its own steps; environment variables are
described in the script header.
