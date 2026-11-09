## RESULT REV-M05-T03
status: done
summary:
verdict: changes-required
reviewed: cce05774d816d369e8648a5beb71f82933ee1b98
Comma matching is repaired, but silent leakage and per-person coverage defects remain. No local-profile change found.
changes: none
verification: Both diffs checked; git diff --check passed; worktree clean. Direct in-memory checks: 22 existing cases passed, four regression probes failed, local identity check passed. clean-development doctor completed with configuration/folder warnings; no repairs.
verification: not runnable: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_notify_redaction.py tests/test_redaction_export_schemas.py && make contract-smoke && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked` - `.venv/bin/python` absent; read-only sandbox prevents linking it.
risks: Full acceptance and HTML peak remain independently unverified.
questions_for_g: none

### Findings
1. `src/azure_tenant_audit/output_redaction.py:1250` - The eight-key slice silently discards accepted variants while retaining `named=True`. Supported name fields can consume eight keys before the comma swap, leaving `Priya Kovalenko` readable with zero unmatched people. Fix: account for truncated variants, retaining required forms within the budget or reporting an unmatched reason; add a saturation regression.
2. `src/azure_tenant_audit/output_redaction.py:1020` - Privileged people enter through both real person records and synthetic name-only records. One privileged `Bo` counts as two unmatched people; adding usable given/family names still leaves one phantom unmatched person. Fix: remove duplicate synthetic people from run discovery and test actual `context_for_run` construction.
3. `src/azure_tenant_audit/output_redaction.py:1309` - Filtering matched entries before resolving aliases loses identity bridges. A matched object-id reference, an unmatched object-id-plus-UPN reference and an unmatched UPN-only reference leave one unmatched person. This also reproduces across three merged indexes. Fix: resolve complete identity groups before suppressing covered people and preserve alias links across merges.
4. `src/azure_tenant_audit/output_redaction.py:404` - Object id and UPN are equal union keys, so two distinct object IDs sharing a reused UPN collapse into one person. Fix: make object id authoritative, use UPN as fallback, and test distinct IDs sharing a UPN.
