## RESULT REV-M04-T03
status: done
summary:
verdict: changes-required
reviewed: c2a6510b2bb27ca2c43ab0c6bd83ddd66b882e88
Temporary-key notices are missing from several emitted reports; required assertion listings are absent from the author’s result.
changes: none
verification: verify blocked by sandbox: M04-T03 criteria command, launched through hostload.sh run --strict --wait 120 --label REV-M04-T03 -- /bin/bash -c; first blocking line: "cannot create temp file for here document: Operation not permitted". No tests ran. git diff --check main...HEAD passed; AST parsing passed for all 27 changed Python files; design SHA and baseline ancestry checks passed.
risks: Full suite, contract smoke, digest reproduction and runtime privacy checks remain unverified here. Progress-file writing was unavailable in the read-only sandbox.
questions_for_g: none

### Findings

- Met: preconditions. DEC-004 approves revision 3 and its SHA matches; M04-T02 commit 18275e0 is an ancestor of HEAD (.plan/DECISIONS.md:32; benchmarks/html-peak-baseline.json:1).
- Not met: exact design implementation, because amendment 6 is incomplete (src/auditex/reporting.py:3904; src/auditex/cli.py:627).
- Met by inspection: exported interface, HMAC construction, context key and removal of run_salt (src/azure_tenant_audit/output_redaction.py:53, :276, :310).
- Met by inspection: private-input registration, atomic publication, collection-time creation and integrity exclusions (src/azure_tenant_audit/guarded_io.py:494, :628, :655; src/azure_tenant_audit/finalize.py:352; src/azure_tenant_audit/bundle_integrity.py:55).
- Met by inspection: prepare-key parsing, created/present output and guarded refusal handling; MCP registry and server unchanged (src/auditex/cli.py:585, :1089).
- Met by inspection; runtime untestable: path-independent pseudonyms, private key handling, keyless sessions, damaged-key refusal, first-run comparison key and legacy validation (tests/test_redaction_keyed_pseudonyms.py:189, :572, :682, :837, :897).
- Met by inspection; runtime untestable: amendments 1-5, including lock errors, paused-creator privacy, operation key pinning, directory flushing and documented limits (tests/test_redaction_keyed_pseudonyms.py:368, :440, :1030, :1047, :1074; docs/reference/output-contract.md:261).
- Not met: amendment 6. Rendered files and CLI report outputs can omit the temporary-key notice (src/auditex/reporting.py:3904; src/auditex/cli.py:627).
- Met by inspection: contract version, schema enums, compatibility label and contract documentation (src/azure_tenant_audit/contracts.py:25; schemas/model_assessment.schema.json:370; schemas/bundle_hashes.schema.json:33; docs/reference/output-contract.md:231).
- Met by inspection; digest reproduction untestable: eight smoke seeds and only two changed digest entries (Makefile:149, :155; tests/fixtures/contract-smoke-digests.json:49).
- Not met: required current-version assertion listings in result.md; they exist only in evidence.md (.plan/work/M04-T03/result.md:5).
- Met by inspection; execution untestable: tests 1-19 and amendment tests exist, but notice tests inspect preview envelopes rather than every emitted report (tests/test_redaction_keyed_pseudonyms.py:165, :1093).
- Met: changed-path scope. All 32 paths match the files line; the two additional canary-scan edits fit test-update rule (ii) (tests/test_partner_domains.py:555; tests/test_sensitive_users.py:485). Unexplained paths: none.
- DoD: design approval confirmed; keyed-test, smoke and digest gates are untestable here. Full-suite and both-provider privacy approval remain outstanding (.plan/work/M04-T03/result.md:16; .plan/milestones/M04-d5-keyed-pseudonyms.md, Definition of Done).
- Security and maintainability: no additional defect found by inspection in key secrecy, injection, permissions, deserialisation or dependency changes. No dependencies were added.

Required changes:

1. src/auditex/reporting.py:3904 and :4009: temporary-key notices reach only Markdown/HTML content; JSON, CSV, SARIF and OSCAL files discard the preview-envelope notice. Embed a format-appropriate notice in each emitted report, preserving format validity, and test the actual written files for keyed and keyless runs.
2. src/auditex/cli.py:627: analyze, api-calls, permissions, proof-table and handoff use redact_output without adding the notice. Record the required design/scope note because CLI ownership currently permits prepare-key only, then carry the notice into their JSON and Markdown outputs and test stdout/file output.
3. .plan/work/M04-T03/result.md:5: the claimed copied listings are absent. Add the final path:line list of changed current-version assertions required by the acceptance criteria, using the verified entries already recorded in evidence.md.

### Defect classes

Temporary-key notices omitted from emitted report content.
Regression tests inspect enclosing metadata instead of the delivered artefact.
Mandatory acceptance evidence missing from result.md.
