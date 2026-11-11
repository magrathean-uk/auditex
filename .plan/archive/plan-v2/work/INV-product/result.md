## RESULT INV-product
status: done
summary:
- Parsers: every `add_parser`/`ArgumentParser` in `src/auditex` sets `allow_abbrev=False`, including the multi-line one at `cli.py:554-555`.
- Redaction: `command_runner.py:13-21` covers the Azure path; `google_workspace/run.py:66` is a separate, non-identical list.
- No TODO/FIXME/XXX/HACK markers in `src/auditex`. Dead-code candidate: `scubagear_prune_proof.py` (575 lines).
- Tests and lint were not run (brief forbids it). `clean-development doctor` passes except five report-only dot-folder warnings in `~`. Whether this worktree is registered with clean-development is unknown; `doctor` does not say.
changes: `.plan/work/INV-product/notes.md` (new)
verification:
- `wc -l src/auditex/*.py` - pass
- `git log --oneline -12` - pass
- `clean-development doctor` - pass with 5 WARN dot-folders (report only)
- `rg 'add_parser\(|ArgumentParser\(' src/auditex | rg -v allow_abbrev` - pass (one hit, cli.py:554, multi-line, flag on 555)
- `rg 'TODO|FIXME|XXX|HACK' src/auditex` - pass (no matches)
- Glob/Grep for imports and redaction references - pass
risks:
- `scubagear_prune_proof.py` appears unreferenced in `src/` and `tests/`; Makefile and docs unchecked.
- Google redaction list diverges from `command_runner.SENSITIVE_ARGS`; neighbouring area, not assessed.
- Model layer is labelled parked but still ships (about 2,500 lines in `model_*.py`).
questions_for_g:
- Keep the parked `model_*` modules in the product, or remove them?
- Should the Google and Azure redaction lists be unified?

### Findings

**1. exists**
- CLI: `src/auditex/cli.py` (1454 lines); subcommands registered at `cli.py:49-68`, probe/auth/google/response/rules/compare/report/export/model/gate/notify parsers after that.
- Guided flows: `src/auditex/guided.py` (582), `operator_flow.py` (79), `demo.py` (448), `explorer.py` (1209) with `explorer_assets/explorer.js` and `explorer.css`.
- Reporting and output: `src/auditex/reporting.py` (3835), `run_bundle.py` (469), `output_writers.py` (223), `scuba_projection.py` (2214), `scubagear_export.py` (839), `scope_postcheck.py` (75).
- Exporters: `src/auditex/exporters.py` (96; `BUILTIN_EXPORTERS` at :12, `list_exporters` at :37, `run_exporter` at :70).
- Compare, drift and gate: `compare.py` (660), `gate.py` (799), `assessment_review.py` (347), `external_assessments.py` (317).
- Explainer and setup: `setup_guide.py` (642), `notify.py` (691), `command_runner.py` (129), `features.py` (16).
- Model layer (parked per `cli.py:682` help text): `model_training.py` (695), `model_serving.py` (584), `model_corpus.py` (393), `model_eval.py` (412), `model_sources.py` (213), `model_precheck.py` (132), `model_prompt.py` (4).
- Tests: about 223 files in `tests/` match the auditex-related patterns; the product-specific ones include `tests/test_auditex_product.py`, `tests/test_cli.py`, `tests/test_cli_abbreviations.py`, `tests/test_customer_pack_d3.py`, `tests/test_demo_and_explorer.py`, `tests/test_gate_cli.py`.

**2. works**
- `clean-development doctor`: all checks ok except five WARN report-only dot-folders in `~` (`.agent-reach`, `.asc`, `.asc-web-session-locks`, `.claude-science`, `.grokbot`).
- `rg 'add_parser\(|ArgumentParser\(' src/auditex | rg -v allow_abbrev`: only `cli.py:554` (multi-line; flag at `cli.py:555`). The brief's allow_abbrev rule holds.
- `rg -n 'allow_abbrev' src/auditex`: every parser listed in `cli.py:42-970` and `guided.py:304`, `demo.py:91`, `model_training.py:606`, `mcp_server.py:767`.
- `command_runner.py:13-32`: `SENSITIVE_ARGS`, `OPERATOR_ARGS` and `OPERATOR_INPUTS` are defined as read.
- `demo.py` is live: `cli.py:53` subcommand, `tests/test_demo_and_explorer.py:11` imports `run_demo`.
- `exporters.py` is read, not executed.

**3. broken**
- none found by the commands run. Builds, tests and lint were not run (brief forbids it), so no failing commands are reported.

**4. dead candidates**
- `src/auditex/scubagear_prune_proof.py` (575 lines): `rg` for its module name finds no importer in `src/` or `tests/` (inferred unreferenced; Makefile and docs not checked).
- `src/auditex/evidence_db.py` (5 lines) and `src/auditex/model_prompt.py` (4 lines): stub-sized; importers not checked.
- `src/auditex/features.py` (16) and `assessment_sources.py` (16): importers not checked.
- Abandoned TODOs: none (`rg 'TODO|FIXME|XXX|HACK' src/auditex` returns no matches).

**5. contradictions**
- `cli.py:682` says the model layer is parked, but `cli.py` has 21 `model_` references and `tests/test_model_*.py` plus several `test_*` files still exercise it. This is a status note against shipped code, not a defect.
- `src/auditex/google_workspace/run.py:66` `_SENSITIVE_COMMAND_FLAGS` differs from `command_runner.py:13-21` `SENSITIVE_ARGS`: the Google list adds `--service-account-key`, `--oauth-client`, `--token-cache` and omits `--access-token`, `--client-secret`, `--token`. Neighbouring area; the two lists are not in sync.

**6. open questions**
- Is `scubagear_prune_proof.py` reachable from any CLI or Makefile path? Settle with `rg -n 'scubagear_prune_proof' src tests Makefile docs`.
- Should the Google and Azure redaction lists be unified, and is the Google list covered by a test? Settle by reading the Google redaction tests (`tests/test_google_workspace.py` and related).
- Are the parked `model_*` modules (about 2,500 lines) kept or removed? This is a G product decision; check `.plan/DECISIONS.md`.
- Is this worktree registered with clean-development? The SessionStart hook reported a lifecycle registration failure, and `doctor` does not name the worktree. Settle with `clean-development status` (not run).
- Neighbouring area (one line): `google_workspace/findings.py` (2280 lines) and `reporting.py` (3835 lines) are the largest files; not assessed.
