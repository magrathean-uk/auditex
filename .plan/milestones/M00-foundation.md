---
id: M00
name: foundation
weight: 10
status: active
---
# M00 foundation
No feature work before this milestone is green. Read-only inventories and design tasks (M02-T01, M03-T01, M05-T01) may run alongside it.

## Goal
Plan v3 starts from a green, lint-enforced `main`: the 1.3.0 gate chain still passes, `make lint` runs the pinned Ruff check over the whole repository with no findings, the small pytest and taint-scan hygiene defects are fixed, and the ownership map matches the tree. There is no hosted CI by G's decision; the gates are local commands.

## Definition of Done
- [x] Lint runs the pinned Ruff check over the whole repository and passes: `make lint` (evidence: merge.sh verify for M00-T01 ran make lint && make test on the integrated tree and passed, squash f4ca1c2)
- [ ] Test harness runs locally and is green: `make test` (M00-T03 at e6531a3: 1 failed, 23679 passed; the M02-T02 script builds a parser outside the factory, fix M02-T02b)
- [x] Contract smoke is green: `make contract-smoke` (evidence: M00-T03 gate run at e6531a3, exit 0)
- [ ] Release check passes end to end, including archive and wheel check, rule-pack drift, taint scan and gitleaks: `make release-check`
- [x] Secrets scan passes: `gitleaks dir . --no-banner --redact` (evidence: .plan/work/PLAN-v3/plan-evidence.md)
- [x] Taint scan passes on the tracked tree: `bash scripts/oss-taint-scan.sh` (evidence: .plan/work/PLAN-v3/plan-evidence.md)
- [x] Dependency audit over the base install and every declared extra exits 0: `make audit-deps` (evidence: .plan/work/PLAN-v3/plan-evidence.md)
- [x] pytest keeps its default exclusions and the taint scan prunes no absent path and no git-ignored build output: `! grep -q '!Review' pytest.ini && ! grep -q 'docs/taint' scripts/oss-taint-scan.sh && make audit-deps && bash scripts/oss-taint-scan.sh` (evidence: merge.sh verify for M00-T02 ran this command and passed, squash 52c0de3; REV-M00-T02 terra approve)
- [x] Review: sol confirms the ARCHITECTURE.md ownership map matches the repository (every tracked non-test path outside `.plan/` in exactly one module) `git ls-tree -r --name-only HEAD` (evidence: .plan/work/PLAN-v3/plan-evidence.md)

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M00-T01 | Run the pinned Ruff check in make lint and clear its findings | codex | M | cross-cutting | done |
| M00-T02 | Fix the pytest norecursedirs and taint-scan prune hygiene | codex | S | mechanical | done |
| M00-T03 | Re-run the gate chain on main after the M00 merges | luna | S | - | doing |

## Acceptance criteria
### M00-T01 Run the pinned Ruff check in make lint and clear its findings
- `make lint` runs the existing compile step and then `ruff check .` with exactly the rule set and target version the pre-commit Ruff hook already uses (`[tool.ruff.lint] select` in `pyproject.toml`: E4, E7, E9, F; target version inferred from `requires-python`); neither is widened or changed (orchestrator ruling, DEC-001). It exits non-zero on any finding.
- The Ruff version is pinned once for `make lint` (development extra or a pinned runner) and equals the `.pre-commit-config.yaml` hook version (0.17.0 unless both move together); `make lint` fails with a clear message when Ruff is absent.
- Each finding `ruff check .` reports at the task's base commit (INV3-lint counted 230 in 54 files) is fixed, or suppressed by a line-level `noqa` with the rule code and a reason; no new file-level or directory-level ignore beyond the existing `tenant-bootstrap/scripts/seed-workload-az.py` entry.
- No behaviour change: `make test` passes with the same pass count as before the change (both counts in `result.md`).
- `.github/CONTRIBUTING.md` and `docs/development/runbook.md` describe `make lint` as compile plus Ruff.
- verify: `make lint && make test`
- files: `Makefile` (lint target only), `pyproject.toml` (`[tool.ruff]` and the development extra only), `.pre-commit-config.yaml`, `.github/CONTRIBUTING.md`, `docs/development/runbook.md` (lint lines only), the 54 Python files Ruff flags at the task's base commit

### M00-T02 Fix the pytest norecursedirs and taint-scan prune hygiene
- `pytest.ini` drops `norecursedirs = !Review` (or replaces it with an explicit list that keeps pytest's defaults); collection from the repository root still gathers the same test ids as before, apart from any id under a directory pytest excludes by default (before and after counts in `result.md`).
- `scripts/oss-taint-scan.sh` no longer prunes `docs/taint` or any other path absent from the tree; each removed prune is named in `result.md`.
- The taint scan no longer reads git-ignored build output: after `make audit-deps` has filled `build/audit-deps/`, the scan still exits 0 (today it fails on a vendored Pygments file there); it prunes the `buildDirs` in `.clean-development.json` or scans only tracked files, stated in `result.md`.
- verify: `! grep -q '!Review' pytest.ini && ! grep -q 'docs/taint' scripts/oss-taint-scan.sh && make audit-deps && bash scripts/oss-taint-scan.sh && .venv/bin/python -m pytest --collect-only -q`
- files: `pytest.ini`, `scripts/oss-taint-scan.sh`

### M00-T03 Re-run the gate chain on main after the M00 merges
- Precondition: M00-T01 and M00-T02 are merged into `main`.
- In a detached worktree at the `main` head, under `run-job`, behind the load rule: `make lint`, `make release-check`, `make contract-smoke` and `make audit-deps` each exit 0.
- `result.md` records the commit, the exit status of each step and the pytest pass, skip and fail counts; on any failure it names the failing step or test ids and stops (no fixes in this task).
- verify: `make lint && make release-check && make contract-smoke && make audit-deps`
- files: `.plan/work/M00-T03/result.md` (read-only run; no repository file changes; work and review directories follow the ARCHITECTURE.md plan v3 evidence convention)
