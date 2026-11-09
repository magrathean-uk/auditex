## RESULT ASSESS-v3
status: done
summary: Merged all 8 INV3 slice results (all done, none malformed) into `assessment-v3.md`. 15 of about 60 claims were spot-checked with rg and targeted reads; 2 corrections applied in the body. No slice ran a build or test suite, so every "works" is static (read or hash-checked).
changes: `.plan/work/assessment-v3.md` (new)
verification: read the 8 `INV3-*/result.md` files (pass); rg and sed spot-checks on 15 claims (pass); `wc -l assessment-v3.md` gives 109, within the 150 cap (pass).
risks: INV3-hygiene gave only a summary, so its claims are single-source. The ownership-map globs overlap by prefix and are resolved by an "except" rule, not mechanically checked. Dead verdicts cover this repo only.
questions_for_g: Is the standalone `tenant-bootstrap/` kit still shipped? Should D5 mask free-text names of all users or only privileged users? Should `model_prompt.py`, the `--endpoint`/`--model` flags and the `model_train` extra go with the parked model layer? Which ruff rule set and target-version should the repo adopt? Should the release gate compare sdist bytes?

### Findings
Five facts a plan must respect:
1. `catalog.py` and `scripts/build-value-rule-fixture.py` are not dead; earlier plans listed them as dead. `catalog.py` is imported by `tests/test_architecture_modules.py` and `tests/test_directory_relationships.py`. `build-value-rule-fixture.py` is loaded by the `-s4` to `-s9` builders.
2. `make dist` is not byte-reproducible and the check script compares sdist members only (`scripts/check-reproducible-build.py:66`, `Makefile:104-118`). The sdist-hash evidence comes from `.plan/work/M03-T05/notes.md`, not a run here.
3. The model layer cannot simply be deleted. Reporting, projection, contracts and value rules import `model_assessment`, `model_evidence` and two `model_eval` helpers, and `Makefile:140` imports `model_serving`. Re-home those first. `model_prompt.py` has no consumer outside `model_serving.py` and tests.
4. D5 exists only on unmerged branch `wt/redact-person-names` (3e495d6). D3 name discovery is privileged-only, and no numbered D6 decision is recorded in `.plan/DECISIONS.md`.
5. There is no CI workflow and `make lint` is compileall only. Ruff 0.17.0 reports 230 findings (tests 196, src 34) that the pre-commit hook would reject on touched files. Neither acceptance job (value replay, explainer) has any Makefile or runbook entry.

Corrections: 2 (forwarder line numbers are `:9-10` and `:12`; `NOTICE` also names `requirements.txt`).

Open questions: the five above, plus the `clean-development doctor` question from the bootstrap slice (the brief forbids running it). Whether the full replay and explainer acceptance pass on main is also unrun.

Notes: none written to `.plan/work/ASSESS-v3/`.
