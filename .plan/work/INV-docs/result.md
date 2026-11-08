## RESULT INV-docs
status: done
summary: Slice is mostly clean. No forbidden paths, retired domains or TODOs. Three broken doc links, one stale "planned" heading for the shipped explainer, and an unresolved held-out-data rule conflict. Full detail in .plan/work/INV-docs/notes.md.
changes: none in the repo; wrote .plan/work/INV-docs/notes.md (allowed).
verification: 11 shell commands. Forbidden-pattern rg over slice: pass (no hits beyond security-privacy.md:148 `XXXX` text). Backticked path existence check, 88 refs: 3 missing. Relative .md link loop over 83 links: no failures reported, no known-bad control run. CLI verb vs add_parser comparison: pass except `validate`. Makefile target check: pass. Version vs CHANGELOG: pass.
risks: (1) examples/model_development/*.jsonl row content not inspected; may conflict with AGENTS.md held-out rule. (2) Relative-link loop unvalidated against a bad link. (2) Schema version currency not settled.
questions_for_g: Does the public repo carry held-out or sealed evaluation rows? AGENTS.md says no; your recorded 5 Nov answer says the public repo may carry anything. Which governs examples/model_development/?

### Findings

1. exists
- README.md (191); AGENTS.md; CLAUDE.md (`@AGENTS.md`).
- docs/guides/ (8 files, 1226 lines max in model-development.md); docs/reference/output-contract.md (1500); docs/reference/framework-mappings.md (619); docs/reference/security-privacy.md (458); docs/reference/api-call-catalog.md (263); docs/development/runbook.md (167); docs/development/scubagear-export-adapter.md (272); docs/provenance/provenance.md (208), provenance.csv (47); docs/legal/ (2 files).
- agent/agent-prompt.md (40), agent/tenant-audit-skill.json (432).
- skills/ (app-readonly-escalation, auditex-operator, delegated-auth, evidence-pack; each SKILL.md).
- profiles/ (5 .md, 11 lines each).
- examples/ (demo_tenant, google_workspace_sample.json, model_development JSONL, sample_audit_bundle 8 JSON); assets/ (2 PNG).
- Shipped-content declarations: pyproject.toml:67-95; src/azure_tenant_audit/shipped_content.py:19-75. AGENTS.md names this file without its path.
- Neighbouring: src/azure_tenant_audit/explainer/ (7 modules); schemas/explainer.schema.json; configs/explainer-*.json.

2. works
- Forbidden-pattern scan (`rg` for /apps/, contact@, workstation paths, retired domains, TODO|FIXME|XXX): clean. Only hit docs/reference/security-privacy.md:148 (`\uXXXX` text).
- Support address and product URL correct: docs/reference/output-contract.md:420, :1475; README.md:10, :12.
- Makefile targets cited in docs exist: test, login, lint, install, release-check, contract-smoke (Makefile:6, 10, 19, 31, 49, 71).
- Every `auditex <verb>` in README and docs/** matches an add_parser in src/auditex/cli.py, except `validate` (see 5).
- All four skills declared in pyproject.toml:79-82 and shipped_content.py.
- Version pyproject.toml:7 `1.3.0.dev0`, consistent with CHANGELOG.md:577 `[1.2.4] - 2026-11-06`.

3. broken
- docs/guides/admin-permission-guide.md:362 cites docs/prerequisites/noninteractive.md; directory absent.
- docs/legal/third-party-notices.md cites skills/mcp-builder/scripts/requirements.txt; skills/mcp-builder/ absent.
- docs/guides/model-development.md cites tests/providers/m365; absent.

4. dead candidates
- docs/development/scubagear-export-adapter.md: no inbound link (`rg -n -F 'scubagear-export-adapter' .` returns only its own line 3). Orphan doc, not dead code: the adapter is live (scripts/assess-scubagear-export.py, src/auditex/scubagear_prune_proof.py, tests/test_scubagear_export.py, tests/test_scubagear_differential.py).
- None other found.

5. contradictions
- docs/reference/output-contract.md:1451 "## Explainer (planned output)"; explainer is implemented under src/azure_tenant_audit/explainer/.
- AGENTS.md (boundaries) forbids committed held-out or sealed rows; examples/model_development/ is shipped (pyproject.toml data-files). Row content not inspected.
- `auditex validate` appears in docs/development/scubagear-export-adapter.md:3 and as note text in src/auditex/scubagear_export.py:837; no `validate` parser in src/auditex/cli.py.
- Spec v3.9.1 stated at AGENTS.md:34, docs/guides/model-development.md:131, docs/provenance/provenance.md:80; configs/scuba-value-rules.json carries no explicit version key (inferred from rg).

6. open questions
- Do examples/model_development/*.jsonl contain held-out or sealed rows? Settle: read the split/family field. Governing rule needs G.
- Restore or retarget docs/prerequisites link? Settle: `git log --all --oneline -- docs/prerequisites`.
- Was skills/mcp-builder ever shipped? Settle: `git log --all -- skills/mcp-builder`.
- Is output-contract.md:1451 stale? Settle: read 1451-1500 against src/azure_tenant_audit/explainer/generate.py.
- Current model_assessment schema version: four dated variants in schemas/, only model_assessment.schema.json cited (output-contract.md). Settle: read output-contract.md:161-172.
- Which test enforces shipped-content parity? Settle: `rg -n 'data-files|shipped_content' tests/test_architecture_modules.py`.
- Confirm the relative-link loop catches a known-bad link before trusting it.
- Confirm contosoexample.onmicrosoft.com (examples/sample_audit_bundle/endpoint_posture_result.json:324, :356) is fictional (inferred).
- Neighbouring, not inspected: tests/, scripts/, tenant-bootstrap/, benchmarks/, configs/ (existence only).
