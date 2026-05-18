<!--
Thanks for sending a pull request! Please:

* Use a conventional-commit-style title (e.g. `feat(proxy): ...`, `fix(pii): ...`).
* Link the issue this PR closes with `Closes #123`.
* Keep the diff focused — separate refactors from feature work.
-->

## Summary

<!-- What does this change do, and why? -->

## Test plan

<!-- Concrete steps a reviewer can run. -->

- [ ] `pnpm check` passes
- [ ] `cd apps/desktop && swift test` passes
- [ ] Manual verification of: <describe>

## Notes for reviewers

<!-- Anything non-obvious: trade-offs, follow-ups already filed, related discussions. -->

## Checklist

- [ ] CHANGELOG updated (user-visible changes only)
- [ ] Tests cover the new behavior (unit and/or integration)
- [ ] No secrets, credentials, or personal data in commits
- [ ] Security impact considered — flagged in `Notes for reviewers` if non-trivial
