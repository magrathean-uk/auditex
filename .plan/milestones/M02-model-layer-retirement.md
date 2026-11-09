---
id: M02
name: model-layer-retirement
weight: 20
status: planned
---
# M02 model-layer-retirement
Implements v2 DEC-004 (G: retire the parked local-model layer after 1.3.0). Removal goes through the deletion gate: G approves the exact path list before any `git rm`, and the approved paths become `.plan/CLEANUP.md` rows. The deterministic template explainer stays. Writers run after M01-T03 merges (shared `Makefile`, runbook and model guide).

## Goal
The parked model layer is gone from code, CLI, packaging, configs, tests and docs. The helpers the shipped report, projection, export and value-rule paths still use live under non-model names first. No verdict, explainer output or bundle field changes: a normalised digest comparison of the contract-smoke runs, recorded before the retirement, proves it. A change that cannot be avoided stops the milestone for an explicit G re-baseline.

## Definition of Done
- [x] Review: G approved the exact removal path list at the deletion gate (DECISIONS.md entry titled "M02 deletion gate", approver G) and every approved path is a `.plan/CLEANUP.md` row with that DEC id: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M02 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && grep -A8 "^## $d M02 deletion gate" .plan/DECISIONS.md | grep -q '^- approver: G'`
- [ ] Every approved path is gone from the tree: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M02 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && o=$(printf '%s\n' "$P" | xargs git ls-files --) && test -z "$o"`
- [ ] The cleanup ledger records each M02 removal with reason, evidence, approval and commit: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M02 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && ! awk -F'|' -v d="$d" '{gsub(/ /,"",$5)} $5==d && ($3 !~ /[a-z]/ || $4 !~ /[a-z]/ || $6 !~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/)' .plan/CLEANUP.md | grep -q .`
- [ ] No source, Makefile or packaging file references the model client, the model CLI or the `model_train` extra: `test -d src && ! git grep -q -E 'ModelClient|_build_model_parser|model_serving|model_train' -- src Makefile pyproject.toml`
- [ ] The HTTP allow-list and transport tests pass with no model-endpoint site left: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_transport_hygiene.py && ! git grep -q -i 'chat/completions' -- src`
- [ ] Shipped report, projection and explainer output are unchanged by the retirement, by normalised digest against the pre-retirement baseline: `make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && .venv/bin/python -m pytest tests/test_compare_run_outputs.py tests/test_reporting.py tests/test_scuba_projection.py tests/test_explainer_integration.py tests/test_value_rules_contract.py`
- [ ] Full suite, shipped-content parity and dependency audit pass: `make test && make audit-deps`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass at milestone close: `make acceptance`
- [ ] No public doc describes the model layer as present: `test -f README.md && ! git grep -q -E 'auditex model|model_train' -- README.md AGENTS.md docs agent skills`
- [ ] Review: other-vendor reviews approve the plan v3 merges of M02-T03 and M02-T04 (Tier A: network and schemas) at the exact merged heads (ARCHITECTURE.md review binding): `ok=1; for T in M02-T03 M02-T04; do ( c=$(git log v1.3.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -q "^reviewed: $s" ".plan/work/REV-$T/result.md" && grep -q '^verdict: approve' ".plan/work/REV-$T/result.md" ) || ok=0; done; test $ok = 1` Orchestrator check at close (ARCHITECTURE.md provider binding): the dispatch record names a launcher of the other vendor from the author's.

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M02-T01 | Design the retirement and write the exact removal list | sol | M | - | done |
| M02-T02 | Record the pre-retirement output digest baseline | codex | M | - | done |
| M02-T03 | Re-home the shared helpers out of the model modules | codex | M | cross-cutting | todo |
| M02-T04 | Remove the model layer per the approved list | codex | L | cross-cutting | todo |
| M02-T05 | Rewrite the docs for the retired model layer | terra | M | - | todo |
| M02-T06 | Record the M02 removals in the cleanup ledger | orchestrator | S | mechanical | todo |

## Acceptance criteria
### M02-T01 Design the retirement and write the exact removal list
- Starts from the INV3-model notes (main checkout `.plan/work/INV3-model/notes.md`) and re-checks the import graph on current `main` (`rg` over `src`, `scripts`, `tests`, `Makefile`, `pyproject.toml`).
- `design.md` names each shared helper (explainer derivation and validation with its schema table, `NOT_COLLECTED`, the two `model_eval.py` helpers), its new module and every importer to update; lists the CLI wiring, extra, data-files, `shipped_content.py`, `audit-deps` and test edits.
- The design keeps every verdict, explainer output, bundle field, schema the bundle references and `CONTRACT_VERSION` unchanged. If that is impossible, `design.md` names the change and the task stops with `status: blocked` for a G re-baseline; it never plans a contract change on its own authority.
- `design.md` names the volatile fields (timestamps, run ids, durations, absolute paths) that `scripts/compare-run-outputs.py` normalises and the report, projection and explainer artefacts it digests.
- `removal-list.txt` is a plain list of tracked paths, one per line, each with a one-line reason and reference evidence in `design.md`; it covers the model modules (including `model_prompt.py` and `model_serving.py`), model and oracle scripts, `examples/model_development/`, `configs/model-sources.json` and the model-only tests; it excludes anything the shipped path still imports after M02-T03. A path that also appears in a G-owned legal file is flagged with the proposed legal text for G.
- verify: `test -s .plan/work/M02-T01/design.md && L=.plan/work/M02-T01/removal-list.txt; grep -q '[^[:space:]]' "$L" && xargs git ls-files --error-unmatch -- < "$L" >/dev/null`
- files: `.plan/work/M02-T01/design.md`, `.plan/work/M02-T01/removal-list.txt` (no repository file changes)

### M02-T02 Record the pre-retirement output digest baseline
- Precondition: M02-T01 delivered `design.md`; runs on `main` before M02-T03 merges (disjoint files, may run alongside M01).
- New `scripts/compare-run-outputs.py`: digests the report, projection and explainer artefacts of each contract-smoke run after normalising the volatile fields `design.md` names; `--write FILE` records the digests with the commit; `--digests FILE RUNDIR` exits non-zero and names every artefact that differs or is missing, and on an empty or unreadable digest file.
- `tests/fixtures/contract-smoke-digests.json` holds the digests of `make contract-smoke` on the pre-retirement `main` head, with that commit.
- `tests/test_compare_run_outputs.py` proves two contract-smoke-shaped runs differing only in volatile fields compare equal, a changed verdict or explainer line compares different, and a missing artefact or digest file fails.
- verify: `make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && .venv/bin/python -m pytest tests/test_compare_run_outputs.py`
- files: `scripts/compare-run-outputs.py`, `tests/fixtures/contract-smoke-digests.json`, `tests/test_compare_run_outputs.py`

### M02-T03 Re-home the shared helpers out of the model modules
- Precondition: M02-T01 design delivered, M02-T02 and M01-T03 merged.
- The helpers move to the homes `design.md` names; every importer (`src/auditex/reporting.py`, `scuba_projection.py`, `scubagear_export.py`, `src/azure_tenant_audit/scuba_precheck.py`, `contracts.py`, `value_rules/record.py` and the tests) uses the new names; no shipped module imports a `model_*` module afterwards.
- `make contract-smoke` no longer imports `auditex.model_serving` and still asserts the rules-only path.
- The digest comparison against `tests/fixtures/contract-smoke-digests.json` passes unchanged; the fixture is not edited.
- verify: `make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && .venv/bin/python -m pytest tests/test_reporting.py tests/test_scuba_projection.py tests/test_value_rules_contract.py tests/test_explainer_integration.py && test -f src/auditex/reporting.py && ! git grep -q -E 'from (auditex|azure_tenant_audit)\.model_|import model_' -- src/auditex/reporting.py src/auditex/scuba_projection.py src/auditex/scubagear_export.py src/azure_tenant_audit/scuba_precheck.py src/azure_tenant_audit/value_rules/record.py`
- files: the new helper modules named in `design.md`, `src/azure_tenant_audit/{model_assessment,model_evidence}.py`, `src/auditex/{reporting,scuba_projection,scubagear_export}.py`, `src/azure_tenant_audit/{scuba_precheck,contracts}.py`, `src/azure_tenant_audit/value_rules/record.py`, `Makefile` (contract-smoke recipe only), the tests that import the moved names

### M02-T04 Remove the model layer per the approved list
- Precondition: M02-T03 merged and the M02 deletion-gate rows are in `.plan/CLEANUP.md`.
- `git rm` removes exactly the CLEANUP.md rows carrying the M02 gate's DEC id, nothing more; the `model` subcommand, the endpoint and model flags and their dispatch leave `src/auditex/cli.py`; the `model_train` extra, its data-files and `shipped_content.py` entries and its `make audit-deps` lists go; the frozen HTTP allow-list drops the model-endpoint row; secret-flag redaction sets drop only flags that no parser still has.
- `tests/test_parser_error_privacy.py`, `tests/test_architecture_modules.py` and the abbreviation and redaction tests are updated for the removed parsers and scripts; no test is skipped to make the suite pass; the digest comparison still passes with the fixture unedited.
- verify: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M02 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && o=$(printf '%s\n' "$P" | xargs git ls-files --) && test -z "$o" && make test && make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract && make audit-deps`
- files: the approved M02 paths in `.plan/CLEANUP.md`, `src/auditex/cli.py`, `src/auditex/output_writers.py`, `src/azure_tenant_audit/bundle_integrity.py`, `src/azure_tenant_audit/shipped_content.py`, `pyproject.toml`, `Makefile` (audit-deps block only), `tests/test_http_verb_allowlist.py`, `tests/test_parser_error_privacy.py`, `tests/test_architecture_modules.py`, the further tests `design.md` names

### M02-T05 Rewrite the docs for the retired model layer
- Runs after M02-T04 merges.
- `README.md`, `AGENTS.md` (the model-fallback sentence), `docs/guides/ai-assessment.md`, `docs/reference/output-contract.md`, `docs/reference/security-privacy.md` (transport class 6), `docs/development/runbook.md` and `docs/provenance/` describe the product without a model layer; `docs/guides/model-development.md` is removed if on the approved list, otherwise reduced to a short retirement note; `CHANGELOG.md` `[Unreleased]` records the removal of the `model` command, its flags and the `model_train` extra.
- Legal files are not edited; any needed legal change is drafted for G in `result.md`.
- verify: `test -f README.md && ! git grep -q -E 'auditex model|model_train' -- README.md AGENTS.md docs agent skills && grep -q 'model_train' CHANGELOG.md && .venv/bin/python -m pytest tests/test_docs_paths.py tests/test_architecture_modules.py`
- files: `README.md`, `AGENTS.md`, `CHANGELOG.md`, `docs/guides/ai-assessment.md`, `docs/guides/model-development.md`, `docs/reference/output-contract.md`, `docs/reference/security-privacy.md`, `docs/development/runbook.md`, `docs/provenance/provenance.md`, `docs/provenance/provenance.csv`

### M02-T06 Record the M02 removals in the cleanup ledger
- At the deletion gate: one `.plan/CLEANUP.md` row per approved path with its reason and reference evidence from `design.md` and the gate's DEC id; after M02-T04 merges: the squash commit sha in each row's commit column.
- verify: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M02 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && ! awk -F'|' -v d="$d" '{gsub(/ /,"",$5)} $5==d && ($3 !~ /[a-z]/ || $4 !~ /[a-z]/ || $6 !~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/)' .plan/CLEANUP.md | grep -q .`
- files: `.plan/CLEANUP.md`, `.plan/DECISIONS.md` (the M02 deletion gate entry)
