## RESULT M04-T03
status: blocked
summary: Review items 1-3 fixed. Reports in every format, all nine customer-pack files and the CLI analyze, api-calls, permissions, proof-table and handoff outputs (stdout and file) now carry the temporary-key notice; tests read the written files.
Blocked: make test has 11 failures that the test-update rule does not cover. All 11 also fail on the reviewed commit c2a6510. 9 are the DEC-019 legacy-relabel class; 2 are one projection golden hash. This needs a design note.
Not run: contract-smoke and the digest check, deferred twice by hostload (exit 75, both slots busy). Detail is in .plan/work/M04-T03/notes.md.
Review 1 fixed: md and html as before; csv gets a closing `pseudonym_notice` row; json a top-level key; sarif a run property; oscal metadata remarks. SARIF and OSCAL pass schema validation for keyed and keyless runs.
Review 2 fixed, with a scope note: the only cli.py change outside prepare-key is `_redacted_report_payload`. Review 3 answered: the listings are below and in notes.md.
changes: src/auditex/reporting.py, src/auditex/cli.py, docs/reference/output-contract.md, tests/test_redaction_keyed_pseudonyms.py, tests/test_redaction_scan_budget.py (branch rebased onto main; commits 1429888, 9987edf, ac93aa3)
verification: make lint pass (one run plus a rerun after fixing 4 errors in the new tests).
Verify gates pass (seed strategy, forbidden paths, schemas, historical literals).
The focused 19-file pytest list passes inside the full run.
make test fail: 11 failed, 22901 passed (suite-r3.log).
contract-smoke and compare-run-outputs: deferred, not run.
Negative case: the new tests against the pre-fix reporting.py and cli.py give 10 failures, for example "FAILED ...::test_amendment_6_every_written_report_format_carries_the_notice[json]" with "assert ('Pseudonyms: this run has no private pseudonym key yet, ...' in '{\n  \"sections\": ...') is True".
Listings for item 3: current-version assertions at tests/test_contract.py:38, tests/test_auditex_product.py:187 and :284, tests/test_assessment_review.py:202, tests/test_integrity_gate_followups.py:531.
Test-update rule (ii): tests/test_partner_domains.py:543 and tests/test_sensitive_users.py:474.
Test-update rule (iii), new this round: tests/test_redaction_scan_budget.py:40, because the keyless JSON preview gains `pseudonym_notice`.
risks: The cli.py change goes beyond the files line's "prepare-key only"; DEC-004 amendment 6 and the review required it, so the orchestrator should record it as a widening.
Contract-smoke has not run since the earlier round. Keyed runs' output is unchanged, so no digest should move.
A CSV of a keyless run gains one non-finding row whose id is `pseudonym_notice`.
questions_for_g: none

### Findings
Design note needed (orchestrator):
1. Same class as DEC-019: a fresh assessment, relabelled to the unchanged 2026-10-29 schema, is refused with "Invalid model assessment value at assessment.projection.redaction.strategy". Affected: tests/test_model_rules_only.py:241 (2 params), tests/test_optional_collection_reason.py:228 (2), tests/test_scope_postcheck.py:565 (4) and tests/test_value_rules_contract.py:258 (1). Should DEC-019's fix (set the relabelled document's strategy to run-salted-sha256-v1) extend to these 4 files?
2. tests/test_scuba_projection_area_hook.py:35, golden hash. With the label set back in memory, [False] matches the old pin exactly. [True] also differs in its pseudonyms (rule (i)), and its keyless fixture needs `seed_key` before the pin can be refreshed. Should this file join the files line, with both pins refreshed?
