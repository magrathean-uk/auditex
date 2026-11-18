## RESULT M11-T01F
status: done
summary: The cause was `tenant_isolation_unconfirmed` missing from the projection section reason enum in the current assessment schema; I added it. No `src/` change was needed because the enum is not mirrored in code. Two end-to-end tests run `assess_run` on the `never-configured` case and on the one-operation sample. Side check: the pinned ScubaGear Rego uses 181 days for AAD 5.6 (`PASSWORD_MAX_DAYS`) and 366 for AAD 5.7 (`CERTIFICATE_MAX_DAYS`), so our rules match it and I changed no rule. Detail is in `.plan/work/M11-T01F/notes.md`.
changes: schemas/model_assessment.schema.json, tests/test_scuba_adapters_powerplat.py, CHANGELOG.md (commits b58a6e7 and 90ee9f1)
verification:
- `PYTHONPATH=src .venv/bin/python -m pytest tests -k "powerplat or tenant_isolation or schema"`: pass (1006 passed, 192 skipped)
- `make contract-smoke` through `hostload.sh --wait 3600`: pass. The first attempt with `--strict --wait 120` was deferred because the slots were busy.
- `make lint`: pass
- Negative case: with the schema change reverted, both new tests fail with `ValueError: Invalid model assessment value` raised from `assess_run`.
- `git status --porcelain`: empty
risks:
- `docs/reference/output-contract.md` (~line 623) does not list the new reason. Docs are outside my files, so this is left for a follow-up.
- The enum change went into the current schema in place, as a loosening, with `CONTRACT_VERSION` unchanged. Older dated schemas are untouched.
questions_for_g: none
