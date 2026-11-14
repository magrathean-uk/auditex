## RESULT M08-T08
status: done
summary: Review item 1 (result-2) fixed. In `src/azure_tenant_audit/baselines.py`, the skipped or cut site-permission read now withholds all four checks that depend on it: `sharepoint.site_orphaned`, `site_weak_ownership`, `broad_link` and `external_principal`. Each one becomes `not_assessed` with reason `site_permissions_not_read`. `external_principal` still needs the tenant's own domains (`tenant_domains_unknown`), and `broad_link` keeps its earlier bounded-sample fallback.
The end-to-end test (collector, normalisation, baseline) now includes known tenant domains and a completed `domains_hybrid` collection. It shows all four checks `not_assessed` after an app-only skip and all four `pass` with a delegated read.
Earlier rounds, unchanged and met: D1 (inline method configurations, null `policyMigrationState`, AAD 3.3 and 3.5 decide), D3 (fan-out attribution, truncation tests, AAD 5.2), D7 (app-only mode makes no permission read and records a named skip; delegated reads are unchanged). Changelog line is in `.plan/work/M08-T08/changelog.md`.
changes: src/azure_tenant_audit/baselines.py, tests/test_first_collection_graph_fixes.py (commit 4fb66bd; earlier rounds 0524fa6, 7e1c00d, 7713d8a, 8319adb)
verification: The verify command (`.venv/bin/python -m pytest tests/test_first_collection_graph_fixes.py tests/test_auth_methods_collector.py tests/test_scuba_adapters_aad.py tests/test_scuba_projection.py tests/test_external_sharing.py tests/test_collection_gaps.py && make contract-smoke`) passed under hostload. Contract smoke reported "5 projected sections ... 102 value-rule rows ... bundle seal verified".
I re-ran the same tests plus `tests/test_baseline_evaluation.py` and `tests/test_framework_baselines.py` at head: 1670 passed, 2 skipped.
`make lint`: All checks passed. gitleaks on the staged commit: no leaks found.
Negative case: the new test run against the previous `baselines.py` fails with `AssertionError: assert {'not_assessed', 'pass'} == {'not_assessed'}`, which is the false pass the review described.
`rule_inputs_gap` spot checks: `external_principal` with no domains gives `tenant_domains_unknown`, with no snapshot gives `inputs_not_available`, and `broad_link` with a permission gap gives `site_permissions_not_read`.
risks: For `external_principal`, a permission gap is now reported ahead of unknown tenant domains, so a run missing both shows `site_permissions_not_read`.
Not run: the full `make test` (the integrator runs it per batch).
questions_for_g: none
