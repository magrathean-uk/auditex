---
id: M00
name: foundation
weight: 20
status: done
---
# M00 foundation
No feature work before this milestone is green. Read-only inventories and drafts may run alongside it.

## Goal
Local `main` carries the accepted `origin/main` line, and the local gates (lint, full suite, contract smoke, release check with archive and wheel, rule-pack drift, taint scan, gitleaks, dependency audit over every declared extra, wheel and sdist release smoke, reproducible build) run green on it. There is no hosted CI by G's decision; the gates are local commands. Every unmerged `wt/*` branch has a reviewed disposition.

## Definition of Done
- [x] Local `main` contains the accepted `origin/main` commit 82d7ca5: `git merge-base --is-ancestor 82d7ca5 main` (evidence: `git merge-base --is-ancestor 82d7ca5 main` passed with main at cd6b134, .plan/work/PLAN-v2/evidence.md)
- [x] Lint passes: `make lint` (evidence: M00-T01 run 4 on 19c7ea7, .plan/work/M00-T01/result.md: make release-check passed end to end, 23711 passed, 0 failed)
- [x] Test harness runs locally and is green: `make test` (evidence: M00-T01 run 4 on 19c7ea7, .plan/work/M00-T01/result.md: make release-check passed end to end, 23711 passed, 0 failed)
- [x] Contract smoke is green: `make contract-smoke` (evidence: M00-T01 run 4 on 19c7ea7, .plan/work/M00-T01/result.md: make release-check passed end to end, 23711 passed, 0 failed)
- [x] Secrets scan passes: `gitleaks dir . --no-banner --redact` (evidence: M00-T01 run 4 on 19c7ea7: gitleaks dir passed, no leaks)
- [x] Release check passes end to end, including archive and wheel check, rule-pack drift and taint scan: `make release-check` (evidence: M00-T01 run 4 on 19c7ea7, .plan/work/M00-T01/result.md: make release-check passed end to end, 23711 passed, 0 failed)
- [x] The release archive and dist steps work with `TMPDIR` unset and set: `env -u TMPDIR make release-archive dist && make release-archive dist` (evidence: merge.sh verify for M00-T02 passed incl. wheel and sdist check, squash bb50c0a; REV-M00-T02 approve at 836261c)
- [x] Dependency audit over the base install and every declared extra (`mcp`, `test`, `google`, `model_train` and any development extra) exits 0, and every ignored advisory has a G-approved `.plan/DECISIONS.md` entry: `make audit-deps` (evidence: merge.sh verify for M00-T03 ran make audit-deps and passed, no known vulnerabilities, no ignored advisories; REV-M00-T03 Codex approve at 0722e93)
- [x] Wheel and sdist each pass the base, Google and MCP release smoke, and two clean builds of the same commit give a byte-identical wheel and a member-identical sdist: `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py` (evidence: merge.sh verify for M00-T05 ran this command and passed, squash f0ae2a7; REV-M00-T05 sol approve at 00afb73)
- [x] Review: sol confirms the ARCHITECTURE.md ownership map matches the repository (every tracked non-test path in exactly one module) `git ls-tree -r --name-only HEAD` (evidence: .plan/work/PLAN-v2/evidence.md, ownership map re-run at 3122ac5 after the revision: 0 unmatched, 0 in two modules)
- [x] Review: terra has spot-checked the M00-T04 branch triage, and every `needed-for-1.3.0` row carries a disposition (a landed task id, or a deferral with its DECISIONS.md id): `grep -q '^spot-check: pass' .plan/work/M00-T04/result.md && ! grep -n -E '\| needed-for-1\.3\.0 \| open \|' .plan/work/M00-T04/result.md` (evidence: M00-T04-check spot-check pass; wt/docs-rules-and-scan-limits disposition M02-T02; command passed 8 Nov 2026)

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M00-T01 | Re-run the gate suite on main after the foundation merges | luna | S | - | done |
| M00-T02 | Make the release archive and dist build TMPDIR-safe make targets | codex | S | mechanical | done |
| M00-T03 | Add a dependency audit over the base install and every extra | codex | M | - | done |
| M00-T04 | Triage unmerged wt branches for 1.3.0 content | luna | M | - | done |
| M00-T05 | Extend the release smoke to the sdist and add a reproducible-build check | codex | M | - | done |
| M00-T06 | Fix the failing installed-wheel resources test | sol | S | debug | done |
| M00-T07 | Make the release smoke independent of a bare python on PATH | terra | S | - | done |

## Acceptance criteria
### M00-T01 Re-run the gate suite on main after the foundation merges
- Precondition: M00-T02, M00-T03 and M00-T05 are merged into `main`, so the run covers the finished foundation.
- In a detached worktree at the `main` head, under `run-job`, behind the load rule: `make release-check`, `make audit-deps`, then `make dist`, `scripts/release-smoke.sh` and `scripts/check-reproducible-build.py` each exit 0.
- `result.md` records the commit, the exit status of each step and the pytest pass, skip and fail counts; on any failure it names the failing step or test ids and stops (no fixes in this task).
- verify: `make release-check && make audit-deps && make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py`
- files: `.plan/work/M00-T01/result.md` (read-only run; no repository file changes)

### M00-T02 Make the release archive and dist build TMPDIR-safe make targets
- The archive-and-wheel block of `release-check` moves into a `release-archive` target that `release-check` calls; behaviour is unchanged when `TMPDIR` is set.
- With `TMPDIR` unset, `release-archive` uses a safe default temporary directory instead of aborting or writing to `/`.
- A new `dist` target builds the wheel and sdist into `dist/` from a clean tree; `dist/` is git-ignored and listed in `.clean-development.json` `buildDirs`.
- `make release-check` still runs every step in the documented order and stops at the first failure.
- verify: `env -u TMPDIR make release-archive dist && make release-archive dist && git check-ignore -q dist/x`
- files: `Makefile`, `.gitignore`, `.clean-development.json`, `pyproject.toml` (only if a build backend extra is needed)

### M00-T03 Add a dependency audit over the base install and every extra
- Runs after M00-T02 (both own `Makefile` and `pyproject.toml`).
- `make audit-deps` resolves the base dependencies and each declared extra (`mcp`, `test`, `google`, `model_train` and the development extra that carries `pip-audit`) to a pinned list with metadata-only resolution (no install into `.venv`, no package download over 5 GB), resolves `model_train` for the host and for Linux aarch64 (its target), and audits every list with `pip-audit --no-deps --disable-pip`; it exits non-zero on any known vulnerability not on the ignore list.
- `pip-audit` sits in a development extra, never a runtime dependency; generated lists go to a git-ignored build directory listed in `.clean-development.json`.
- A finding is fixed by a bounded version change in `pyproject.toml`; for `model_train` that is a pin change only (no model development, no removal). A finding that cannot be fixed goes into an ignore file the target reads, with advisory id, package, reason and the DECISIONS.md id that records G's acceptance; `result.md` names every finding and its outcome.
- verify: `make audit-deps`
- files: `Makefile`, `pyproject.toml`, `.gitignore`, `.clean-development.json`, `scripts/audit-deps-ignore.json` (only if an advisory is accepted; kept out of `configs/` so shipped content is unchanged)

### M00-T04 Triage unmerged wt branches for 1.3.0 content
- Lists every local `wt/*` branch not merged into `origin/main` with its tip, ahead count and the paths it changes, in a table with the columns branch, tip, ahead, class, disposition, evidence.
- Classifies each as merged-equivalent, superseded, post-1.3.0 (D5, live tenant, kit, model) or needed-for-1.3.0, with one line of evidence each; a `needed-for-1.3.0` row starts with disposition `open`.
- terra spot-checks at least 10 percent of the rows and every `needed-for-1.3.0` row, and appends `spot-check: pass` or the rows it disputes.
- The orchestrator then sets each `needed-for-1.3.0` disposition to the task id that lands it (a change-control edit to a milestone) or to a deferral recorded in DECISIONS.md; M00 does not close while any row is `open`.
- Changes nothing in the repository: no checkout, merge, branch or worktree deletion.
- verify: `test "$(git branch --list 'wt/*' --no-merged origin/main | wc -l)" -eq "$(grep -c '^| wt/' .plan/work/M00-T04/result.md)"`
- files: `.plan/work/M00-T04/result.md` (read-only)

### M00-T05 Extend the release smoke to the sdist and add a reproducible-build check
- Runs after M00-T02 (needs `make dist`); its files are disjoint from M00-T03, so the two may run in parallel.
- `scripts/release-smoke.sh` installs the wheel and, in separate fresh environments, the sdist, each for the base, `google` and `mcp` installs, and runs the existing checks against every install; its default smoke root is under `$TMPDIR`, never a fixed `/tmp` path.
- `scripts/check-reproducible-build.py` exports the current commit twice with `git archive` into fresh directories under `$TMPDIR`, builds each with `SOURCE_DATE_EPOCH` set to the commit time, and passes only when the two wheels are byte-identical (same sha256) and the two sdists hold the same sorted member list with the same sha256 per member; it prints the artefact names and hashes.
- verify: `make dist && bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python scripts/check-reproducible-build.py`
- files: `scripts/release-smoke.sh`, `scripts/check-reproducible-build.py`, `tests/test_check_reproducible_build.py`

### M00-T06 Fix the failing installed-wheel resources test
- `tests/test_explainer_integration.py::test_installed_wheel_resources_offline` failed in the M00-T01 gate run on 0a73759 (23,183 passed, 1 failed; log `.plan/work/M00-T01/gate-1-release-check/log.txt` near line 409): one resource adapter did not resolve as "installed".
- Diagnose whether the cause is a packaging defect (a resource missing from the wheel, or the loader preferring the source tree) or the gate environment (worktree, linked .venv, PYTHONPATH). Fix a packaging defect at its source; for an environment cause, make the test robust to it without weakening what it proves, and record the cause in notes.
- The whole test file passes and no other test changes behaviour.
- verify: `.venv/bin/python -m pytest tests/test_explainer_integration.py`
- files: `tests/test_explainer_integration.py`, `pyproject.toml`, `src/auditex/shipped_content.py`, and the resource loader module the diagnosis names (listed under changes)

### M00-T07 Make the release smoke independent of a bare python on PATH
- `scripts/release-smoke.sh` selects its interpreter from `PYTHON` when set, else the repository's `.venv/bin/python`, else `python3`; it never calls a bare `python`.
- The smoke passes for wheel and sdist across base, google and mcp with a PATH that has no `python` on it.
- `tests/test_architecture_modules.py` keeps passing (update only the release-smoke assertions if the script's text changes).
- verify: `make dist && env PATH="/usr/bin:/bin" bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke" && .venv/bin/python -m pytest tests/test_architecture_modules.py`
- files: `scripts/release-smoke.sh`, `tests/test_architecture_modules.py` (release-smoke assertions only)
