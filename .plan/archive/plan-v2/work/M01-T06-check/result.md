## RESULT M01-T06-check
status: done
summary: Check passes. The no-held-out claim holds for everything in the repo, and the generator --check now runs clean. The frozen holdout id list is not committed, so a direct comparison against it was not possible.
changes: none (a .venv symlink in my worktree only)
verification: .venv/bin/python scripts/build-model-examples.py --check (pass, 48 cases, 12 families, 32/8/8 split, synthetic true, review_status unreviewed, model_execution_performed false); id overlap scan of the 48 ids against every tracked file in configs, examples, tests, scripts and docs (pass, 0 hits); git ls-files search for split-report, test_ids or holdout id files (none tracked)
risks: The frozen holdout id list (`test_ids_sha256` in split-report.json) is outside the repo, so the id comparison is against the repo only. The earlier "--check fail" in M01-T06 result.md was a missing-venv artefact and can be dropped.
questions_for_g: none
### Findings
Pass: no row in examples/model_development/ is held-out, sealed, real or derived from a held-out set.
- Every case id has the form `synthetic-<family>-NN`, built in scripts/build-model-examples.py:47. All 48 have source auditex-synthetic-generator-v3 and synthetic true (:61).
- The ids are unique, and none appears in any tracked file in configs/, examples/, tests/, scripts/ or docs/ outside the three example files.
- The only tracked held-out-named files are tests/fixtures/value-rules/held-rows-s4.json, held-rows-s5.json, held-rows-README.md and tests/test_value_rules_held.py. They hold SCuBA policy rows (`MS.SECURITYSUITE.*`) that are now shipped in configs. They are not model-evaluation holdout ids and share no ids with the examples.
- The word "holdout" in docs/guides/model-development.md:655-679 describes the frozen test split. Its id list is not in the repo.
- Unknown: whether the 8 `test` split ids here collide with that frozen split. Inferred no, because the ids come from this generator. `test_ids_sha256` in split-report.json (the workspace path is in docs/guides/model-development.md:655) would settle it.
- Notes: .plan/work/M01-T06-check/ was not written, because the findings fit in this block.
