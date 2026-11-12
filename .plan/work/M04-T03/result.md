## RESULT M04-T03
status: partial
summary: verify deferred: heavy slot busy (hostload exit 75; the slots were held by another project's job and M03-T13). Round 5 addresses REV-M04-T03-privacy result-1. B1, A1, A3 and A4 are fixed, each with a test, and A2 is answered below. The branch is rebased onto main; head is 1f0348d.
B1 fixed: in a keyless run's customer pack, the notice is now in pack-manifest.json, README.md, every redacted JSON copy under source-artifacts/ and the printed customer-pack result. The pack test walks every pack file.
A1 fixed: open_guarded_file, open_private_output, remove_guarded_output and remove_guarded_tree run discovery again after the open. A3 fixed: temporary keys are indexed by device, inode and run_id. A4 fixed: the loop variable is renamed. A2 answered: not changed, because the CSV notice row is the open DEC-021 item for G.
changes: src/auditex/reporting.py, src/auditex/output_writers.py, docs/reference/output-contract.md, src/azure_tenant_audit/guarded_io.py, src/azure_tenant_audit/output_redaction.py, src/auditex/scuba_projection.py, tests/test_redaction_keyed_pseudonyms.py
verification: make lint pass ("All checks passed!"). Focused run of tests/test_redaction_keyed_pseudonyms.py, test_key_guard_copy.py, test_mcp_guard_repair.py, test_pack_integrity_and_permissions.py, test_writer_sinks_d3.py and test_scuba_projection.py: pass, exit 0. It ran before the rebase, which brought in only .plan/ commits. The verify command's shell pre-checks and closing grep pass on 1f0348d. The full verify (.plan/work/M04-T03/verify-r5.sh: pytest list, make test, make contract-smoke, digest compare) was deferred by hostload and not run. Negative cases (each fix reverted, then its test run), all fail as expected:
A1: 4 failed, "Failed: DID NOT RAISE UnsafeRunFileError" for read, overwrite, remove and remove-folder.
B1: "assert (None == 'Pseudonyms: this run has no private pseudonym key yet, ...') is True" on the printed pack result.
A3: "assert (b'O7\x93...' != b'O7\x93...')": the same key was reused.
A4: "assert [23, 26] == []": the key parameter was rebound.
Details: .plan/work/M04-T03/evidence-r5.md.
risks: private_io._write_private is outside the files line and has the same discovery-then-open window for a replace. An output aimed at operator-inputs/pseudonym.key while prepare-key runs could overwrite the key, but never read it. Follow-up: the same re-discovery there. Two pack files carry no notice, by design, and the contract now says so: source-artifacts/bundle-hashes.json, because verify-pack checks it by digest and it holds no pseudonym, and checksums.sha256.
questions_for_g: none
