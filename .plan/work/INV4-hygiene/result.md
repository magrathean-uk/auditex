## RESULT INV4-hygiene
status: done
summary: Re-checked the BACKLOG Next items on the frozen main. Ruff W,I,B,UP gives 899 findings (796 fixable, 70 unsafe), with 521 I001 and 0 W. The explainer "absent fixtures" premise is wrong: line 43 is a negative assertion, and 14 .gz files exist in subdirectories. The value-rules contract test skips because it reads a stale env name. Notes: .plan/work/INV4-hygiene/notes.md.
changes: none in the repo; notes written to .plan/work/INV4-hygiene/notes.md
verification: ruff check . --select W,I,B,UP --statistics --no-cache (main checkout .venv ruff 0.17.0) pass as a read-only run; ruff --output-format concise per top-level dir pass; find tests/fixtures/explainer -name '*.gz' (14); rg/Grep and Read checks pass. No tests, builds or git writes run. `clean-development doctor` not run (brief forbids it without explicit authorisation).
risks: BACKLOG's "about 31,800 findings" does not reproduce (899 today, probe config unknown). Ruff's 796 fixable does not reconcile exactly with per-rule markers (750 [*] + 47 [-]). The clean-development SessionStart hook reported a registration failure and asked for doctor; G should decide whether to authorise it.
questions_for_g: Should the BACKLOG premises for the explainer fixtures and the microsoft-skills removal be corrected before the next plan gate? Should `clean-development doctor` be authorised for diagnosis?

### Findings

1. exists
- pyproject.toml:39-42 pins ruff==0.17.0; :50-51 lint select E4,E7,E9,F.
- tests/fixtures/explainer/: 9 dirs, README.md, SHA256SUMS, corpus-manifest.json; 14 .gz files (renderer/, collection/, checks/, baselines/, baselines/raw/).
- tests/test_explainer_fixtures.py: rule test and SHA256 test; FIX.rglob at :20.
- tests/test_value_rules_contract.py:267-271 (skipped test).
- tenant-bootstrap/vendor/microsoft-skills/ (MANIFEST.md, LICENSE, ALL-SKILLS-CATALOG.md).
- src/azure_tenant_audit/bundle_integrity.py:80; scripts/compare-run-outputs.py (main :254); tests/test_compare_run_outputs.py; scripts/check-reproducible-build.py; tests/test_check_reproducible_build.py.
- src/azure_tenant_audit/output_redaction.py:1652 (Redactor.text).

2. works
- Ruff wider set, `ruff check . --select W,I,B,UP --statistics --no-cache`: 899 findings; 0 from W; I001 521, UP045 101, UP017 81, B905 57, UP035 47, UP037 24, B023 16, UP006 11, UP031 9, B904 9, UP034 8, B007 6, B033 3, UP028 3, B017 2, UP012 1. Fixable summary 796, 70 unsafe.
- Per top-level dir (ruff concise output): src 408 (azure_tenant_audit 314, auditex 94); tests 444; tenant-bootstrap 29; scripts 18.
- Fixability per directory not computed.
- Explainer: 14 .gz files under tests/fixtures/explainer (find). tests/test_explainer_fixtures.py:40-44 is a list of names that must not be stored; :43 is not a fixture reference.
- Contract test env: tests/test_value_rules_contract.py:268-269 reads AUDITEX_TEST_VALUE_RULE_VECTORS and _CATALOGUE; Makefile:13-14, tests/test_value_rules_replay.py:54 and tests/test_value_rules_s8.py:187 use AUDITEX_TEST_VALUE_RULE_VECTORS_V391.
- Redactor.text `names` parameter (output_redaction.py:1652): not read in body 1653-1677 (read); callers at :1732, :1785, :1789 (rg).
- Reproducibility test varies mtime 1 vs 2 and asserts byte difference (tests/test_check_reproducible_build.py:40-43); the script normalises mtime (scripts/check-reproducible-build.py:29,36) (read).

3. broken
- none (no failing command was run; no missing referenced file found for the slice).

4. dead candidates
- Redactor.text `names` parameter, output_redaction.py:1652: unused in the body; rg for `names` in 1652-1677 shows only the signature and docstring (inferred from read).
- Vendored microsoft-skills entries ALL-SKILLS-CATALOG, microsoft-foundry, entra-agent-id: no code reference; rg in src, tests, scripts finds only scripts/oss-taint-scan.sh:35 (prunes the whole vendor dir). Textual refs: tenant-bootstrap/vendor/microsoft-skills/MANIFEST.md:16,29,43,69 and ALL-SKILLS-CATALOG.md:18-19.
- Legal notices do not name these three entries: rg for them in docs/legal/third-party-notices.md shows no hit; NOTICE:7-9 and provenance.csv:23 name the directory (wildcard).

5. contradictions
- BACKLOG.md:11 and .plan/work/INV3-acceptance/result.md:41 and .plan/work/assessment-v3.md:62 say the .gz fixtures are "absent"; the test at tests/test_explainer_fixtures.py:40-44 asserts their names must not be stored, and 14 .gz files exist in subdirectories.
- BACKLOG.md:10 says about 31,800 findings; today's measurement for the same rule families is 899.
- BACKLOG.md:13 says the contract test needs a catalogue the v3.9.1 kit lacks; the repo's kit name is _V391 (Makefile:13-14), and the catalogue variable is read only at tests/test_value_rules_contract.py:269.
- src/azure_tenant_audit/bundle_integrity.py:80 treats model_assessment_prompts.jsonl as a post-finalisation output, but CHANGELOG.md:37 says it is no longer written and docs/reference/output-contract.md:821 says no current command writes it.
- "model view" still appears in docs/reference/output-contract.md:81; docs/reference/security-privacy.md:31,42; docs/guides/admin-permission-guide.md:66 and code comments at src/auditex/scuba_projection.py:326,1170,1172,1305,1346; the model layer was removed in commit c97539d.
- scripts/compare-run-outputs.py: no "inventory" or "validate" match in the file (rg); RELATIVE_DAY_KEYS at :53-54 lists only expiry_days_remaining, so the expiry_state claim is not visible here.

6. open questions
- Whether ruff's 796 fixable reconciles with per-rule markers (750 [*] plus 47 [-]): run ruff check . --select W,I,B,UP --statistics --no-cache --output-format json and count fix.applicability per rule.
- Whether scripts/compare-run-outputs.py compares expiry_state through another path: read its compare logic from line 254.
- Whether the mtime-varying reproducibility test is the REV-M01-T01 defect: read tests/test_check_reproducible_build.py:36-70 against the milestone review.
- Whether the v3.9.1 kit contains a catalogue: check the kit outside the repo (not in this slice).
- Neighbouring area: tenant-bootstrap/vendor/microsoft-skills/MANIFEST.md:60-62 contains rm -rf /tmp/... (not in slice).
