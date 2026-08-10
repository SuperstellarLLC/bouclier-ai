# Getting help

Bouclier.ai is a small project. We don't have a paid support team, but
we read everything that comes in through the channels below.

## Before you ask

- Check [CHANGELOG.md](CHANGELOG.md) — your issue may already be fixed
  in the next release.
- Search existing [issues](https://github.com/SuperstellarLLC/bouclier-ai/issues?q=is%3Aissue)
  and [discussions](https://github.com/SuperstellarLLC/bouclier-ai/discussions).
- Make sure you are on the latest release. The menu bar → About panel
  shows the version.

## Where to ask

| You want to...                   | Use                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------ |
| Report a security vulnerability  | [SECURITY.md](.github/SECURITY.md) (private)                                               |
| Report a reproducible bug        | [Open a bug issue](https://github.com/SuperstellarLLC/bouclier-ai/issues/new/choose)       |
| Propose a feature                | [Feature issue template](https://github.com/SuperstellarLLC/bouclier-ai/issues/new/choose) |
| Ask a question or discuss usage  | [Discussions](https://github.com/SuperstellarLLC/bouclier-ai/discussions)                  |
| Commercial / press / partnership | `hello@bouclier.ai`                                                                        |

## What to include

A useful bug report contains:

- Bouclier.ai version, macOS version, CPU architecture.
- Install source (DMG / source build).
- The AI client you were using when the issue happened
  (ChatGPT desktop app, Cursor, raw `curl`, ...).
- Steps to reproduce, ideally with a synthetic payload.
- Relevant log lines from
  `~/Library/Application Support/ai.bouclier.app/logs/` or
  `Console.app` filtered by `ai.bouclier`. **Redact request content
  before pasting** — the audit log already strips it, but verify.

## Response expectations

This is volunteer time. We aim to respond within a few business days.
Security reports are prioritised — see SECURITY.md for the timelines
we commit to.
