---
id: M00
name: foundation
weight: 8
status: active
---
# M00 foundation
No Track A feature work before this milestone is green. Track B (M01-M03) works outside the repository and may start beside it once G approves the plan v4 scope; read-only design work (M04-T01) may also run alongside.

## Goal
Plan v4 starts from a green `main`: the 1.4.0 gate chain still holds on an unchanged tree, the contract-smoke digest comparison passes again (it fails today on a date-derived field) and, with an `--as-of` date on every offline smoke run, no longer depends on the day it runs (DEC-005), `make lint` enforces the wider Ruff rule set (W, I, B, UP on top of E4, E7, E9, F) with no findings, the value-rule contract test that always skipped runs, the stale gate lines in `AGENTS.md` and the runbook are corrected, and the ownership map matches the tree. There is no hosted CI by G's decision; the gates are local commands.

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
- [ ] Every offline invocation in the `make contract-smoke` recipe (at least eight) carries `--as-of` with one shared literal `YYYY-MM-DD` date (no shell, make or computed value), and the outputs match the recorded digests with the wall clock on either side of a lifecycle date (DEC-005): `awk '/^contract-smoke:/{f=1;next} f&&/^[A-Za-z.]/{f=0} f&&/--offline/{n++; if(/#/ || gsub(/--as-of/,"&")!=1 || !match($0,/--as-of [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ ;]|$)/)) bad++; else d[substr($0,RSTART+8,10)]++} END{for(x in d)c++; exit !(n>=8 && !bad && c==1)}' Makefile && .venv/bin/python -m pytest tests/test_offline_as_of.py && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- [ ] The gate chain, the digest comparison included, passes on `main` after the M00 merges: `make release-check && make audit-deps && make acceptance && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- [x] Review: sol confirms the ARCHITECTURE.md ownership map matches the repository (every tracked non-test path outside `.plan/` in exactly one module) `git ls-tree -r --name-only HEAD` (evidence: .plan/ARCHITECTURE.md:26)

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M00-T05 | Make the output digest comparison pass on the unchanged tree | codex | S | debug | done |
| M00-T01 | Widen the Ruff rule set to W, I, B and UP and clear its findings | codex | M | cross-cutting | todo |
| M00-T02 | Make the value-rule contract test read the replay kit variable | codex | S | mechanical | todo |
| M00-T03 | Correct the stale gate lines in AGENTS.md and the runbook | terra | S | mechanical | todo |
| M00-T06 | Add an as-of date to offline runs and pass it in the contract smoke | codex | M | - | todo |
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

### M00-T06 Add an as-of date to offline runs and pass it in the contract smoke
- Precondition: M00-T01 and M00-T02 merged (M00-T02 may change `Makefile`). May run beside M00-T03 (disjoint files); M00-T04 waits for it. Facts: `.plan/work/EXP-clock/result.md` (main checkout) and DEC-005.
- The Microsoft 365 offline run (`azure_tenant_audit --offline`, and `auditex run --offline`, which forwards to it) and the Google offline run (`auditex google run --offline`; `ci-google` is in the digest fixture) take a visible `--as-of YYYY-MM-DD`; an invalid date is a usage error (exit 2); a live run refuses it; without it the wall clock is used as before.
- Every wall-clock read that reaches a smoke output (end-of-support and lifecycle tables, credential expiry, stale sync, stale account and login windows, password age; at least `findings.py:525`, `:599`, `:1155`, `:2369`, `:2926`, `normalize.py:1613` and the Google `normalize.py:244` and `findings.py:803`, `:1036` at the task's base commit) takes the as-of date when given; `result.md` lists each read and how it is fed, and names any read left on the wall clock with why it reaches no smoke output (for example waivers, which `--offline` does not apply).
- CLI rules: each parser keeps `allow_abbrev=False`; tests show an abbreviation of `--as-of` is refused on both offline commands; `--as-of` carries no secret and is in no argv redaction set (a test checks it stays out).
- Every offline call of `make contract-smoke` (the eight runs) passes one fixed date, written as the literal `--as-of YYYY-MM-DD` on each invocation line of the recipe (the same date on all eight, once per line; no make variable, `$(shell ...)`, command substitution or other computed value, so the date cannot follow the run date): the day the current digest fixture was recorded (the M00-T05 merge), so every date-dependent finding in the recorded digests stands, every smoke assertion still holds and no verdict changes; `result.md` names the date. No bundle artefact gains a new field.
- New `tests/test_offline_as_of.py`: for the endpoint-posture sample (an operating-system end of support), the demo tenant sample (a credential expiry) and the Google sample (a ChromeOS auto-update expiry), two offline runs with the same `--as-of` and the wall clock patched to dates either side of that lifecycle date give equal digests under `scripts/compare-run-outputs.py`; without `--as-of` the endpoint-posture pair differs (proving the test moves the clock; the comparator already normalises the expiry fields).
- `docs/guides/product-manual.md` (offline run sections) and `docs/reference/output-contract.md` (offline replay paragraph) describe `--as-of`; no other document lists offline options.
- `tests/fixtures/contract-smoke-digests.json` is refreshed at most once, with `--write`; `result.md` lists every changed run and artefact with the reason (or states that none changed), and the digest comparison passes on the result.
- verify: `awk '/^contract-smoke:/{f=1;next} f&&/^[A-Za-z.]/{f=0} f&&/--offline/{n++; if(/#/ || gsub(/--as-of/,"&")!=1 || !match($0,/--as-of [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]([ ;]|$)/)) bad++; else d[substr($0,RSTART+8,10)]++} END{for(x in d)c++; exit !(n>=8 && !bad && c==1)}' Makefile && .venv/bin/python -m pytest tests/test_offline_as_of.py tests/test_cli_abbreviations.py tests/test_cli.py tests/test_google_workspace.py && make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`
- files: `src/azure_tenant_audit/cli.py`, `src/azure_tenant_audit/findings.py`, `src/azure_tenant_audit/normalize.py`, `src/auditex/cli.py` (the `--as-of` parser entries of `auditex run` and `auditex google run`, and the dispatch, validation and forwarding that carry the date to the offline run handlers, including the `run_google_offline` call; no other change), `src/auditex/google_workspace/{run,normalize,findings}.py`, `Makefile` (contract-smoke target only), `tests/test_offline_as_of.py`, `tests/test_cli_abbreviations.py`, `tests/fixtures/contract-smoke-digests.json`, `docs/guides/product-manual.md` (offline run sections only), `docs/reference/output-contract.md` (offline replay paragraph only)

### M00-T04 Re-run the gate chain on main after the M00 merges
- Precondition: M00-T05, M00-T01, M00-T02, M00-T03 and M00-T06 merged into `main`.
- In a detached worktree at the `main` head, under `run-job`, behind the load rule: `make lint`, `make release-check`, `make contract-smoke`, the digest comparison, `make audit-deps` and `make acceptance` each exit 0.
- `result.md` records the commit, each step's exit status and the pytest pass, skip and fail counts; on any failure it names the step or test ids and stops (no fixes in this task).
- verify: `make lint && make release-check && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && make audit-deps && make acceptance`
- files: `.plan/work/M00-T04/result.md` (read-only run)
