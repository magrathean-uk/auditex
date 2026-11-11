## RESULT REV-M00-T02
status: done
summary:
verdict: changes-required
reviewed: aaab72b49f985ce52274a463ddcf72ddeff82224
The test now reads the kit variable and `make acceptance` runs it, but the kit has `cell-catalogue.json`. The test always uses the shipped catalogue, so the comparison against an independent reference is gone and the check at :276 is always true. Neither result file says the kit was checked. Evidence: `.plan/work/REV-M00-T02/evidence.md`.
changes: none (git-ignored `.venv` link added in the review worktree; evidence.md written under `.plan/work/REV-M00-T02/`)
verification: `.venv/bin/python -m pytest tests/test_value_rules_contract.py -rs -q` passed: variable unset, exit 0 with one skip naming the variable; variable set to the v391 kit, exit 0, 192 tests, no skips. `make acceptance` not runnable here: load 52.9 then 122.2 on 12 cores is above the core count, so the load rule forbids starting it; `merge.sh --verify` is the gate.
risks: (1) With `ref = shipped`, the test no longer compares the shipped catalogue with an independent one, so if the shipped catalogue and the vectors drift together, the test cannot see it. (2) I did not run `make acceptance` on this head.
questions_for_g: none
### Findings
Criteria checklist:
- Reads `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`: met, tests/test_value_rules_contract.py:271.
- Catalogue from the shipped file only when the kit has none, stated in result.md after checking the kit: not met. The kit folder holds `cell-catalogue.json` (102 policies, same keys, no differences in recommendations or limitations today). Line :274-275 always uses the shipped catalogue, and neither result-1.md nor result.md mentions checking the kit.
- No longer needs `AUDITEX_TEST_VALUE_RULE_CATALOGUE`: met, tests/test_value_rules_contract.py:270-275.
- Runs and passes with the variable set; skips naming the variable when unset: met, :272-273 (evidence.md).
- `make acceptance` runs it and the Makefile change is listed: met, Makefile:16, listed in result.md.
- DoD item "contract test reads the kit variable and runs instead of skipping": met by leg 1 with the kit set. It stays unticked until merge.
- Scope: both changed paths are on the files line, and the Makefile change is in the acceptance target only. No scope creep.
- Security: no secrets, no new dependencies, no injection surface. The kit path comes from the environment and is only read.
Required changes:
1. tests/test_value_rules_contract.py:274-276. Problem: `ref = shipped` means the test always uses the shipped catalogue, which makes the assertion at :276 always true and drops the reference check, even though the kit carries `cell-catalogue.json`. Fix: load `Path(vectors).with_name("cell-catalogue.json")` as `ref` when it exists. Fall back to `loader.catalogue()["policies"]` only when it does not. Keep `assert set(ref) == set(shipped)`.
2. .plan/work/M00-T02/result.md. Problem: the criterion requires a statement that the kit was checked for a catalogue, and there is none. Fix: name the kit file found (`cell-catalogue.json`) and say which branch the test takes.
Suggestions (non-blocking):
- Once ref and shipped are different objects again, the `shipped[...]["sections"]` lookup at :288 keeps its meaning. Otherwise use `entry`/`ref` throughout, so the test has a single catalogue variable.
