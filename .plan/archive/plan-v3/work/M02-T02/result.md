## RESULT M02-T02
status: done
summary: Added `scripts/compare-run-outputs.py`, which digests the report, action-plan, summary, findings, `model_assessment.json`, projection and `policy_explanations` artefacts of the 8 contract-smoke runs. It normalises the volatile fields named in design.md section 8 and has `--write` and `--digests FILE RUNDIR` modes.
summary: The baseline fixture holds 43 digests recorded at 223fbaa, the pre-retirement `main` head. A second `make contract-smoke` run compared equal. The tests cover the volatile-only, changed-verdict, changed-explainer, missing-artefact and bad-digest-file cases.
changes: scripts/compare-run-outputs.py, tests/fixtures/contract-smoke-digests.json, tests/test_compare_run_outputs.py (commit 874cd0a)
verification: `make contract-smoke` pass; `.venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` pass (43 digests match); `.venv/bin/python -m pytest tests/test_compare_run_outputs.py` pass (15 tests). The worktree is clean.
risks: M02-T03 and T04 must keep writing `model_assessment.json` at the same path with the same content for `ci-projection-demo`, or the comparison fails by design. `.venv` is a git-ignored link to the main checkout's venv. The machine was under load (about 17) during the smoke runs, so the second smoke run was slow but passed.
questions_for_g: none
