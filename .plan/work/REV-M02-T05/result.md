## RESULT REV-M02-T05
status: done
summary:
verdict: approve
reviewed: 2316c965a2ed2a2a44d46eb7132727c6aa7a2c8a
The branch adds only `tests/test_docs_paths.py` (+46). It meets every M02-T05 criterion, and the verify command passes (36 tests) once pointed at the main checkout's interpreter.
changes: none (evidence written to `.plan/work/REV-M02-T05/evidence.md`)
verification: `pytest tests/test_docs_paths.py tests/test_architecture_modules.py -p no:cacheprovider -q` using `.venv/bin/python` from the worktree - pass, 36 passed. The literal `.venv/bin/python` form is not runnable here because the worktree has no `.venv`; `merge.sh --verify` is the gate. I also ran a read-only scan of the tracked docs for unknown-root and top-level path references, with no mutation of the tree.
risks: 1) The test calls `git ls-files`, so it fails outside a git checkout, for example from an unpacked sdist; no other test does this. 2) Roots come from tracked paths, so a backticked path with a wholly wrong first segment is not caught. 3) `./scripts/oss-taint-scan.sh` (`docs/development/runbook.md:94`) and top-level file names are skipped.
questions_for_g: none

### Findings
Criteria:
- Met: file list comes from `git ls-files '*.md'`, with no hand-kept list (`tests/test_docs_paths.py:19`). Every first-party Markdown root is covered unless excluded.
- Met: backticked repo-rooted paths (`:33-40`) and relative links, including images and URL-decoded paths (`:41-48`), fail the test when the target is missing.
- Met: the exclusions are `tenant-bootstrap/vendor/`, `tests/` and `.plan/`, with a reason in the comment at `:10-11`. Released CHANGELOG sections are cut off at the first `## [` heading that is not Unreleased, with a reason at `:27` (`:28`).
- Met: the exemptions are explicit with a reason each (`:12-15`). Both are `tests/providers/m365` and the one third-party-notices line, marked `pending G-approved correction (DEC-003, M02-T07)`. Both match real content (`docs/guides/model-development.md:830`, `docs/legal/third-party-notices.md:17`). No other legal-file exemption exists.
- Met: the scope is exactly the files line, `tests/test_docs_paths.py`. There is no scope creep.
- Met: security. No dependencies, no network, no shell injection (`subprocess` is called with a list and a fixed `cwd`), and paths are checked with a `[\w.\-/]+` whitelist.
- DoD: this task contributes to the first M02 DoD item only. That item stays open until M02-T07 removes the `third-party-notices` exemption, as planned.

Required changes: none.

Suggestions (non-blocking):
1. `tests/test_docs_paths.py:19-20`: fall back to a filesystem walk, or skip with a clear reason, when `git ls-files` fails, so the test does not error outside a git checkout.
2. `tests/test_docs_paths.py:32`: accept a leading `./` and strip it, so `./scripts/oss-taint-scan.sh` is checked.
3. Reference-style and HTML links are not detected (the author already noted this).
