## RESULT INV3-d5
status: done
summary: D3 redaction lives in src/azure_tenant_audit/output_redaction.py. Name discovery is privileged-only, so free-text names for ordinary users are not masked. The branch wt/redact-person-names (3e495d6) is unmerged and holds the earlier D5 attempt. The D6 decision text is referenced but not recorded in DECISIONS.md. The 0.5 and 1.5 GiB HTML peak figures have no harness in the repo.
changes: none (notes written to .plan/work/INV3-d5/notes.md)
verification: git log --oneline --all -- .; git show --stat --oneline 3e495d6; git branch -a --list '*redact*'; git merge-base main wt/redact-person-names; git diff --stat eecad1d wt/redact-person-names; wc -l on 11 files; rg sweeps for TODO, peak/maxrss and symbol counts; Read output_redaction.py L1120-1165, L391-422, L314-324. No tests or builds run.
risks: D6 decision text not located outside excluded `.plan/work` and `.plan/archive`. Peak-memory claims in docs are not reproducible from this repo. Free-text name matching depends on the privileged-user rule in `_is_privileged_user`.
questions_for_g: Should D5 mask display names of all users in free text, or only privileged users as D3 does?

### Findings
1. exists
- src/azure_tenant_audit/output_redaction.py (1406 lines): D3 redactor, profiles local/shareable/customer_pack/explainer (L24-27, L81); RedactionContext protected_names/ids (L235-262); pseudonym/run_salt (L264-272).
- Privileged-only name discovery: _collect adds displayName only for privileged records (L391-422); _is_privileged_user (L314-324).
- Free-text matching: names length >= 4, not vocabulary (L1126-1148); narrative ids length >= 4 (L1149-1164); structured ids pseudonymised at any length.
- src/azure_tenant_audit/output_writers.py (208 lines): WRITER_INVENTORY and redact_output routing (L1-16, L23-26).
- Other redaction call sites (rg count): src/auditex/reporting.py 18 (3970 lines), mcp_server.py 21, notify.py 16, cli.py 10, azure_tenant_audit/bundle_integrity.py (matched, not read).
- src/auditex/scuba_projection.py:1534-1554: second pseudonym helper for DisplayName and OnPremisesImmutableId.
- Docs: docs/reference/security-privacy.md:430-482 (boundary; names not discovered "can remain in prose", L481); docs/reference/output-contract.md:616-624 (run-salted-sha256-v1 counts).
- CHANGELOG.md:10, :20 (D6 limit), :69. Plan: .plan/BACKLOG.md:12 (D5-v2 spec), .plan/master-plan.md:36,55, .plan/DECISIONS.md:8-9, .plan/milestones/M03-release-1-3-0.md:11,16,39.
- Main tests: tests/test_redaction_profiles_d3.py (439 lines, 24 tests), tests/test_redaction_scan_budget.py (301 lines, 11 tests), tests/test_redaction_export_schemas.py, tests/test_notify_redaction.py, tests/test_targeted_pseudo_*.py. No person-named test on main.
- Branch wt/redact-person-names (tip 3e495d6, merge-base eecad1d, 12 files +3129/-115), branch-only: src/azure_tenant_audit/redaction_key.py (80 lines, operator-inputs/redaction.key, run_person_key), tests/test_redact_person_names.py (1427 lines), tests/test_person_single_locals.py (311), tests/fixtures/person-single-locals.json. Its output_redaction.py adds _PERSON_TOKEN_RE (L230), _PROCESS_PERSON_KEY (L259, process-local fallback).
2. works
- Branch tip, merge-base and diffstat: confirmed by git log, git show --stat, git merge-base, git diff --stat.
- Main file sizes: confirmed by wc -l. redaction_key.py and test_redact_person_names.py absent on main (wc error).
- Redactor logic at L1120-1165, L391-422, L314-324: confirmed by Read.
- Tests not run, so D3 pass status is unverified.
3. broken
- none found by reading. No missing referenced file in the slice. No TODO, FIXME, XXX or HACK in redaction files or tests (rg).
4. dead candidates
- src/azure_tenant_audit/output_redaction.py:455 REASON_OUTSIDE: rg -w -c over src, tests, scripts gives 1 (definition only). Inferred unused.
- Branch wt/redact-person-names: unmerged, still held by another worktree (git branch marks it +).
5. contradictions
- .plan/DECISIONS.md:9 cites "D6 keeps D5 out", but DECISIONS.md has no numbered D6 entry (D6 cited in master-plan.md:28,55, BACKLOG.md:12, CHANGELOG.md:20).
- docs/reference/security-privacy.md:466-469 gives HTML peaks of 0.5 and 1.5 GiB "on the test machine". rg for maxrss, tracemalloc, peak and resident finds no harness; only tests/test_chunk_normalization.py:167-174 (different path). Inferred not reproducible from repo.
- Two pseudonym implementations (output_redaction.py:264, scuba_projection.py:1534); docs describe only the first.
6. open questions
- Where is the D6 decision text? rg -n 'D6' .plan/archive .plan/work (excluded by brief).
- How were the 0.5 and 1.5 GiB peaks measured? Check M03 evidence or ask the author.
- Does scuba_projection.py:1534-1554 match output_redaction.py:264-268? Read both and compare.
- Which redact_output callers in reporting.py, notify.py, mcp_server.py and bundle_integrity.py need D5 changes? Not read; rg -n -C3 'redact_output|RedactionContext' in each.
- Neighbour (one line): scuba_projection.py projection pseudonyms, not inspected.
