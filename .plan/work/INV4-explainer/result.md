## RESULT INV4-explainer
status: done
summary: The template explainer covers all 102 SCuBA policies (1,084 cells) and is wired into report output only, never into MCP. Value rules answer all 102 policies. Baselines hold 109 entries, so 7 are unexplained. Google Workspace has no value-rule or not_assessed path in its directory.
changes: none (notes written to .plan/work/INV4-explainer/notes.md)
verification: 3 shell commands, all passed (wc/ls/git log; two python -I read-only counts). Other checks were Read/Grep/Glob. No builds, tests or tenant contact.
risks: Customer-pack use of policy_explanations is untraced. The 7 unexplained baseline entries are inferred, not checked. not_assessed reason counts are not taken.
questions_for_g: none
### Findings
1. exists
- Explainer package `src/azure_tenant_audit/explainer/` (8 files, 1,588 lines): `__init__.py:30` `explain()`, `generate.py`, `render.py`, `view.py`, `adapter.py`, `collection.py`, `baselines.py`, `textkit.py`.
- Configs: `configs/explainer-template.json` (1,084 cells, 102 policies), `configs/explainer-what-to-collect.json` (1,084 cells, 102 policy_sections), `configs/explainer-baselines.json` (109 policy entries), `configs/scuba-value-rules.json` (102 policies), `configs/report-sections.json`.
- Schema `schemas/explainer.schema.json`; value rules `src/azure_tenant_audit/value_rules/` (21 entries).
- Output per policy: `explanation` (max 80 words, 3 sentences), `remediation_steps` (max 6), `evidence_refs` (`generate.py:12-13`, `render.py:116-132`).
- Glue: `src/azure_tenant_audit/scuba_assessment.py:212` `derive_explainer`; `src/auditex/rule_assessment.py:321` `assess_run` writes `model_assessment.json`.
- Report consumers: `src/auditex/reporting.py:575-602` (`_load_policy_explanations`), markdown `:2823-2830`, HTML `:3336-3340`.
- Tests: `tests/test_explainer_*.py` (9), `tests/explainer_checks/` (12), `tests/fixtures/explainer/`.
2. works
- `explain()` (`explainer/__init__.py:30-51`) and `render.py:38-46` read: schema/limit/key checks as stated. Read.
- Template counts (python -I over `configs/explainer-template.json`): 1,084 cells, 102 policies, 102 `required_evidence_section_not_collected` cells. Ran.
- What-to-collect (python -I): 1,084 cells, 102 policy_sections. Ran.
- Baselines (python -I): 109 policy entries. Ran.
- Value rules (python -I over `configs/scuba-value-rules.json`): 102 policies, 2 shared_reasons. Ran.
- Reporting re-derives the explainer and keeps stored text only if it matches (`reporting.py:569-602`). Read.
- `docs/guides/ai-assessment.md:151-155` (explainer ships, wired into reports, never changes a verdict) matches the code. Read.
3. broken
- none found in the commands run or the read paths.
4. dead candidates
- 7 baseline entries (109 vs 102) appear unreferenced by the template (inferred from counts; no rg run).
- `src/auditex/reporting.py:484` says "used in this preview"; no preview flag checked.
- No dead explainer module found; all 8 are imported.
5. contradictions
- none confirmed in the parts read. The baseline count (109 vs 102) is not explained in the parts read of `docs/provenance/explainer-baselines.md` (not opened).
6. open questions
- Which 7 baseline keys are not template policies: key diff of `configs/explainer-baselines.json` against the template.
- Does the customer-pack builder emit `policy_explanations`? Builder not traced; `reporting.py:100` lists the section.
- not_assessed counts and reasons (`scuba_assessment.py:183,377,480,532`): settle with a read-only count over `configs/scuba-value-rules.json`.
- Google Workspace (`src/auditex/google_workspace/`, 32 defs in `findings.py`): no not_assessed or value-rule reference by rg. Settle with `rg -n "scuba|value_rule|not_assessed" src/auditex/google_workspace`.
- MCP: `src/auditex/mcp_registry.py` has no explain or narrative tool; `mcp_server.py:624-639` and `1056-1064` expose only external-assessment tools.
- Neighbour: `configs/finding-templates.json` holds remediation-style text for non-SCuBA findings; not inventoried.
