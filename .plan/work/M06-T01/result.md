## RESULT M06-T01
status: partial
summary: `CHANGELOG.md` `[Unreleased]` is now `[1.5.0] - 2026-11-14`. It covers `CONTRACT_VERSION` `2026-11-11` and what a 1.4.0 reader can and cannot do, keyed per-run pseudonyms with `prepare-key`, middle-initial and title masking and its boundary, the wider Ruff rules, the closed scanner limits and the follow-ups. `pyproject.toml` says `1.5.0` and `SECURITY.md` supports 1.5.x with 1.4.x upgrade-only. No model, Track B or M04-T06 content. verify deferred: heavy slot busy, so `make test` and `make contract-smoke` did not run (the merge gate runs them).
changes: CHANGELOG.md, pyproject.toml, .github/SECURITY.md
verification: the three grep checks (version line, `## [1.5.0]` heading, `| 1.5.x | Yes |` row) pass. `make lint` passes. Negative case: `grep -q '| 1.4.x | Yes |' .github/SECURITY.md` now exits 1. `make test` and `make contract-smoke` were deferred (exit 75; slots held by M02-T21 and CHK-SEAM6).
risks: 1) The heading date 2026-11-14 must equal the day of the tag; if the release is approved on a later day, correct that one line then. 2) The compare links at the foot of `CHANGELOG.md` stop at `[Unreleased]` and `[1.3.0]`, so there are none for 1.4.0 or 1.5.0; that is outside this task's scope. 3) Every claim in the notes comes from the merged docs and commits, not from task titles.
questions_for_g: none
