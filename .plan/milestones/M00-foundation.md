---
id: M00
name: foundation
weight: 8
status: active
---
# M00 foundation
No Track A feature work before this milestone is green. Track B (M01-M03) works outside the repository and may start beside it once G approves the plan v4 scope; read-only design work (M04-T01) may also run alongside.

## Goal
Plan v4 starts from a green `main`: the 1.4.0 gate chain still holds on an unchanged tree, the contract-smoke digest comparison passes again (it fails today on a date-derived field), `make lint` enforces the wider Ruff rule set (W, I, B, UP on top of E4, E7, E9, F) with no findings, the value-rule contract test that always skipped runs, the stale gate lines in `AGENTS.md` and the runbook are corrected, and the ownership map matches the tree. There is no hosted CI by G's decision; the gates are local commands.

## Definition of Done
- [x] Release check is green on main (hook-set lint, test, contract smoke, rule-pack drift, taint scan, gitleaks): `make release-check` (evidence: .plan/archive/plan-v3/work/M06-T02/result.md, 22620 passed 0 failed on 5843f0b = v1.4.0, with the tree unchanged since: `git diff --quiet v1.4.0 HEAD -- . ':!.plan'`)
- [x] Both acceptance suites, the full v3.9.1 replay included, pass on main: `make acceptance` (evidence: .plan/archive/plan-v3/work/M06-T02/result.md, 26901 vectors, no skips, tree unchanged since: `git diff --quiet v1.4.0 HEAD -- . ':!.plan'`)
- [x] Two plain builds give byte-identical wheel and sdist: `make dist && .venv/bin/python scripts/check-reproducible-build.py` (evidence: .plan/archive/plan-v3/work/M06-T02/result.md, tree unchanged since: `git diff --quiet v1.4.0 HEAD -- . ':!.plan'`)
- [x] Secrets scan passes: `gitleaks dir . --no-banner --redact` (evidence: gitleaks dir . --no-banner --redact)
- [x] Taint scan passes on the tracked tree: `bash scripts/oss-taint-scan.sh` (evidence: bash scripts/oss-taint-scan.sh)
- [ ] Dependency audit over the base install and every declared extra exits 0: `make audit-deps`
- [x] The contract-smoke outputs match the recorded digests, with date-derived values normalised: `make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- [ ] `make lint` runs the pinned Ruff check with E4, E7, E9, F, W, I, B and UP over the whole repository and passes: `grep -q '"W", "I", "B", "UP"' pyproject.toml && make lint`
- [ ] The value-rule contract test reads the kit variable `make acceptance` uses and runs instead of skipping: `! grep -q 'getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")' tests/test_value_rules_contract.py && test -f "$AUDITEX_TEST_VALUE_RULE_VECTORS_V391" && out=$(.venv/bin/python -m pytest tests/test_value_rules_contract.py -k all_external_final_vectors -rs -q) && ! printf '%s\n' "$out" | grep -q SKIPPED`
- [ ] `AGENTS.md` describes `make lint` as compile plus Ruff and lists `make acceptance` and `make dist`; the runbook's publication section is not tied to 1.3.0: `! grep -q 'compileall only' AGENTS.md && grep -q 'make acceptance' AGENTS.md && ! grep -q 'Publication for 1.3.0' docs/development/runbook.md`
- [ ] The gate chain, the digest comparison included, passes on `main` after the M00 merges: `make release-check && make audit-deps && make acceptance && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- [x] Review: sol confirms the ARCHITECTURE.md ownership map matches the repository (every tracked non-test path outside `.plan/` in exactly one module) `git ls-tree -r --name-only HEAD` (evidence: .plan/ARCHITECTURE.md:26)

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M00-T05 | Make the output digest comparison pass on the unchanged tree | codex | S | debug | done |
| M00-T01 | Widen the Ruff rule set to W, I, B and UP and clear its findings | codex | M | cross-cutting | todo |
| M00-T02 | Make the value-rule contract test read the replay kit variable | codex | S | mechanical | todo |
| M00-T03 | Correct the stale gate lines in AGENTS.md and the runbook | terra | S | mechanical | todo |
| M00-T04 | Re-run the gate chain on main after the M00 merges | luna | S | - | todo |

## Acceptance criteria
### M00-T05 Make the output digest comparison pass on the unchanged tree
- First Track A writer. On the tree equal to `v1.4.0`, `make contract-smoke` passes but the digest comparison reports `ci-projection-demo` `findings/findings.json`, `reports/action-plan.json`, `reports/report-pack.json` and `summary.json` as different; the demo credentials' `expiry_state` now reads `expired`.
- Names the cause in `result.md`. A value derived from the run date (such as `expiry_state`) is normalised in `scripts/compare-run-outputs.py` the way `expiry_days_remaining` is, with a unit test that two runs on dates either side of an expiry give equal digests; the fixture is refreshed only for an output change the task names and justifies, with the changed run and artefact list.
- The comparator's docstring no longer points at the archived `.plan/work/M02-T01/design.md`; no other change.
- verify: `.venv/bin/python -m pytest tests/test_compare_run_outputs.py && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- files: `scripts/compare-run-outputs.py`, `tests/test_compare_run_outputs.py`, `tests/fixtures/contract-smoke-digests.json` (only if justified)

### M00-T01 Widen the Ruff rule set to W, I, B and UP and clear its findings
- Precondition: M00-T05 merged. Runs alone: no other Track A writer is dispatched until it merges (it touches files in every module).
- `[tool.ruff.lint] select` in `pyproject.toml` is E4, E7, E9, F, W, I, B, UP; `[tool.ruff.lint.isort] known-first-party` names `auditex` and `azure_tenant_audit` so import sorting does not depend on what is installed; the pinned Ruff version (0.17.0) and the pre-commit hook stay equal; the target version stays inferred from `requires-python`.
- Every finding at the task's base commit (INV4-hygiene measured 899) is fixed, or suppressed by a line-level `noqa` with the rule code and a reason; no new file-level or directory-level ignore beyond the existing `tenant-bootstrap/scripts/seed-workload-az.py` entry. B905 fixes use `strict=False` unless the lengths are proved equal; every unsafe fix (70 at measurement) is listed in `result.md` with one line on why behaviour is unchanged.
- No behaviour change: `make test` passes with the same pass count as before the change, and the contract-smoke outputs still match the recorded digests (both counts in `result.md`).
- verify: `make lint && make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- files: `pyproject.toml` (`[tool.ruff]` only), `.pre-commit-config.yaml`, the Python files Ruff flags at the task's base commit

### M00-T02 Make the value-rule contract test read the replay kit variable
- Precondition: M00-T01 merged.
- `tests/test_value_rules_contract.py` reads `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` (the name `Makefile`, `tests/test_value_rules_replay.py` and `tests/test_value_rules_s8.py` use); the catalogue comes from the shipped `configs/scuba-value-rules.json` when the kit has none, so the test no longer needs `AUDITEX_TEST_VALUE_RULE_CATALOGUE` (stated in `result.md` after checking the kit).
- With the kit variable set the test runs and passes; without it, it skips with a message naming `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`. `make acceptance` runs it (added to the target only if it does not already collect it; the `Makefile` change is then listed).
- verify: `.venv/bin/python -m pytest tests/test_value_rules_contract.py -rs -q && make acceptance`
- files: `tests/test_value_rules_contract.py`, `Makefile` (acceptance target only, if needed)

### M00-T03 Correct the stale gate lines in AGENTS.md and the runbook
- Precondition: M00-T01 merged.
- `AGENTS.md` says `make lint` is compile plus the pinned Ruff check and lists `make acceptance` and `make dist` with one line each; the publication section of `docs/development/runbook.md` describes the release form (signed tag plus GitHub release with wheel and sdist, no PyPI, G's yes naming the version) without naming 1.3.0.
- No other change to either file.
- verify: `! grep -q 'compileall only' AGENTS.md && grep -q 'make acceptance' AGENTS.md && grep -q 'make dist' AGENTS.md && ! grep -q 'Publication for 1.3.0' docs/development/runbook.md`
- files: `AGENTS.md`, `docs/development/runbook.md`

### M00-T04 Re-run the gate chain on main after the M00 merges
- Precondition: M00-T05, M00-T01, M00-T02 and M00-T03 merged into `main`.
- In a detached worktree at the `main` head, under `run-job`, behind the load rule: `make lint`, `make release-check`, `make contract-smoke`, the digest comparison, `make audit-deps` and `make acceptance` each exit 0.
- `result.md` records the commit, each step's exit status and the pytest pass, skip and fail counts; on any failure it names the step or test ids and stops (no fixes in this task).
- verify: `make lint && make release-check && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && make audit-deps && make acceptance`
- files: `.plan/work/M00-T04/result.md` (read-only run)
