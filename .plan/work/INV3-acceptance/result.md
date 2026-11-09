## RESULT INV3-acceptance
status: done
summary: The v3.9.1 replay kit exists on the 4TB, outside the repo; its vectors, A2 vectors and A2 overrides match the hashes pinned in `tests/test_value_rules_replay.py`. The repo holds a 2,233-row sample that is pinned by manifest and matches. The explainer acceptance jobs are in `tests/explainer_checks/` and `tests/test_explainer_integration.py`. No Makefile target or runbook section runs either acceptance job. Full notes: `.plan/work/INV3-acceptance/notes.md`.
changes: none in repo; notes written to `.plan/work/INV3-acceptance/notes.md`
verification: `shasum -a 256` on kit `vectors.jsonl`, `a2-vectors.jsonl`, `a2-label-overrides.jsonl` and repo sample and overrides: all pass against pins. `wc -l` on kit files: 26,898 / 3 / 190, pass. `rg` on the Makefile, pytest.ini and selectors: read-only, pass. No tests run.
risks: The full replay and explainer acceptance have not been run, so they may fail. The kit's `build_vectors.py` regeneration path is unverified.
questions_for_g: none
### Findings

**1. exists**
- Replay test: `tests/test_value_rules_replay.py` (242 lines). Full replay is `test_full_v391_replay_acceptance` at line 219, gated by `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` (line 53).
- Repo fixtures: `tests/fixtures/value-rules/vectors-v391-sample.jsonl.xz`, `label-overrides-a2-v391-sample.jsonl`, `manifest-v391-sample.json`, `vectors-a2-constructed.jsonl`.
- Sample builder: `scripts/build-value-rule-sample-v391.py` (100 lines; `build()` at line 35).
- Explainer acceptance: `tests/explainer_checks/` (about 6,100 lines; `README.md` lines 21-29 give the run recipe), `tests/test_explainer_integration.py:402,413`, `tests/explainer_checks/test_mutation.py:72`.
- Markers: `pytest.ini:2` excludes both markers by default; `pytest.ini:7-8` describes them.
- Full kit (4TB, outside repo): `vectors.jsonl` (26,898 lines), `a2-vectors.jsonl` (3), `a2-label-overrides.jsonl` (190), `ADDENDUM-A2.md`, `build_vectors.py`, `cell-tables.md`.

**2. works**
- Kit `vectors.jsonl` sha256 `3515b6fa…92cf4e` equals the pin at `tests/test_value_rules_replay.py:163,227`. Command: `shasum -a 256`.
- Kit `a2-vectors.jsonl` sha256 `0351259…622ac0b` equals `:164`. Same command.
- Kit `a2-label-overrides.jsonl` sha256 `74639d1…8e1fa1` equals `:165`. Same command.
- Kit line counts 26,898 / 3 / 190 match the asserts at `:238,229`. Command: `wc -l`.
- Repo sample sha256 `c7af2f21…767a49` and overrides sha256 `d760c1ae…3663` equal the values in `manifest-v391-sample.json`. Command: `shasum` and grep.
- `Makefile:6-7`: `make test` is bare `pytest`, so the acceptance markers are excluded by default. No Makefile target runs the acceptance jobs.

**3. broken**
- none confirmed by read; nothing executed.

**4. dead candidates**
- none confirmed in-slice.
- Kit logs `acceptance-finish.log`, `assembly-finish.log` and `cat391.log` are external run artefacts with no repo references (`rg`).

**5. contradictions**
- `docs/guides/model-development.md:148` names `AUDITEX_TEST_VALUE_RULE_VECTORS`; the test reads `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` (`tests/test_value_rules_replay.py:53`).
- `docs/development/runbook.md` has no acceptance section; the commands live only in `tests/test_value_rules_replay.py:9-10` and `tests/explainer_checks/README.md:21-29`.
- `pytest.ini:4` `norecursedirs = !Review` uses an unusual `!` form (inferred: likely a no-op; not verified).

**6. open questions**
- Does the full replay pass on main? Settle with `AUDITEX_TEST_VALUE_RULE_VECTORS_V391=<kit>/vectors.jsonl .venv/bin/python -B -I -m pytest tests/test_value_rules_replay.py -m value_rule_acceptance -o addopts= -q`, if a suite run is allowed.
- Do the explainer acceptance chunks pass, with only the four known misses? Settle with the README recipe.
- Do the `.gz` fixtures named at `tests/test_explainer_fixtures.py:43` exist? They are not at the top level of `tests/fixtures/explainer/`. Settle with `find tests/fixtures/explainer -name '*.gz'`.
- Can the full kit be regenerated offline? Not checked. Settle by reading `build_vectors.py` and running it into a temp dir.
- Neighbour area: `configs/explainer-what-to-collect.json:27654` pins the same `vectors.jsonl` hash, which is consistent with the kit.
