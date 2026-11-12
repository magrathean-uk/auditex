## RESULT REV-M04-T03
status: done
summary:
verdict: changes-required
reviewed: 1f0348d2be71a87bf9c22b45f0130a93315343ae
Two blocking gaps remain in A1 and A3.
changes: none
verification: PASS git diff --check, Python AST/parity checks, read-only mocked race/cache probes, frozen HEAD and clean-worktree checks. Focused pytest blocked before collection: no writable temporary directory.
risks: Full suite and contract-smoke left to the executing check. Progress/evidence files unwritable in the sandbox.
questions_for_g: none

### Findings

1. closed by inspection: B1 notices reach source JSON, README, manifest and printed result (src/auditex/reporting.py:1869, src/auditex/reporting.py:2179, src/auditex/reporting.py:2193). The test walks every pack file (tests/test_redaction_keyed_pseudonyms.py:1158); the two exceptions contain no generated pseudonyms and are documented accurately (docs/reference/output-contract.md:274).
2. open: A1 repairs the four changed entry points, but misses the subdirectory-root path through open_run_file (src/azure_tenant_audit/run_files.py:78).
3. open: A3 uses triples everywhere, but absent, non-string and empty run IDs share an empty discriminator (src/azure_tenant_audit/guarded_io.py:402; src/azure_tenant_audit/output_redaction.py:348).
4. open, advisory: rename is behaviour-neutral; seven repair paths are authorised and plan changes are inherited. Keyed-output logic and smoke inputs remain unchanged. One keyed-JSON absence assertion was weakened (src/auditex/scuba_projection.py:1566; tests/test_redaction_keyed_pseudonyms.py:1170).
5. closed: no additional privacy, security or contract consequence found beyond items 2-4 (src/auditex/reporting.py:2193; docs/reference/output-contract.md:265).

- blocking A1: read_run_file(run/"operator-inputs", "pseudonym.key") admitted the synthetic key when publication occurred after discovery and before directory opening. Re-discover the selected path after opening, before admission, and add this root variant to the race regression; amend file ownership as needed (src/azure_tenant_audit/run_files.py:80).
- blocking A3: replacement manifests with absent/null/empty IDs reused both the temporary key and pseudonym; distinct IDs did not. Avoid the shared empty discriminator through safe refusal or a non-reusable run identity, with regressions for each missing-ID case (src/azure_tenant_audit/guarded_io.py:402).
- advisory: the stated _write_private discovery/open overwrite did not reproduce. Parent creation precedes discovery and existing-key admission resynchronises identities. Add a regression documenting this protection (src/azure_tenant_audit/private_io.py:75; src/azure_tenant_audit/private_io.py:104).
- advisory: restore the whole-file temporary-notice absence assertion for keyed JSON pack files, retaining the expanded file walk (tests/test_redaction_keyed_pseudonyms.py:1170).
