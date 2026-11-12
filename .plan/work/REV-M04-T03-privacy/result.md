## RESULT REV-M04-T03-privacy
status: done
summary:
verdict: approve
reviewed: 1f0348d2be71a87bf9c22b45f0130a93315343ae
9f38936 was rebased; its twin d9c1357 has the same code outside .plan, so the judged diff is d9c1357..1f0348d (7 files). B1, A1 and A4 are closed. A3 is closed for runs with different run ids; the rest of A3 and the A1 paths the repair missed are advisory. Detail: .plan/work/REV-M04-T03-privacy/notes.md (round 2).
changes: none on the branch; notes.md and progress.md in .plan/work/REV-M04-T03-privacy/
verification: pytest tests/test_redaction_keyed_pseudonyms.py pass (79 passed); ruff check on the six changed Python files pass
risks: full suite and contract-smoke not run (left to the executing check); the second discovery adds refusals that only the full suite exercises
questions_for_g: none
### Findings
- 1 B1 closed: src/auditex/reporting.py:1869-1870, :1885-1886, :2178-2180, :2193-2194 and :2196-2201. The test at tests/test_redaction_keyed_pseudonyms.py:1138 walks every pack file and checks the printed result. The bundle-hashes copy is written only when redaction leaves it unchanged, and checksums.sha256 holds only digests and pack paths, so neither holds a pseudonym. docs/reference/output-contract.md:268-276 says this accurately.
- 2 A1 closed for src/azure_tenant_audit/guarded_io.py:1005, :1152, :1191 and :1223 (test :1289). The second discovery can only add refusals, and no open_private_output caller creates run-manifest.json.
- 3 A3 partly closed: the session key is indexed by device, inode and run id (src/azure_tenant_audit/output_redaction.py:337, :348; guarded_io.py:401-402), with no fallback to the old index. Open: a missing or non-string run_id becomes "" at guarded_io.py:402, so two such runs at a reused inode still share a key.
- 4 Closed: the rename at src/auditex/scuba_projection.py:1566-1570 changes no behaviour, because the emails closure reads neither key nor name. All seven files are on the files line. The only test edit is stricter. Every new branch depends on temporary_key, so keyed outputs and the smoke digests (seeded keyed runs, no pack files) cannot move.
- 5 No new blocking consequence. The schemas allow extra properties, so the new top-level key still validates. Keyless pack-manifest digests change, as documented.
- advisory A3 residual: a run re-collected under the same run name into the same folder keeps its run_id (src/azure_tenant_audit/output.py:182-191), and the docstring at output_redaction.py:342-344 says such a run never shares a key, which overclaims. This is narrower than the round-1 advisory, and the schema has always required run_id. Fix: also index by the SHA-256 of the pinned manifest bytes that bind_run already reads.
- advisory A1 leftover: src/azure_tenant_audit/private_io.py:84-107 has the same window for a replace. It can overwrite the key but never read it, and the damaged key is then refused. Fix: discover again before the open of the existing file.
- advisory A1 missed: src/azure_tenant_audit/run_files.py:57-80 binds only run_dir. A key that appears after discovery in a run nested below run_dir is not registered, so the read is not refused. The file is barred by the M04-T03 verify command. Follow-up: discover again after the open.
- advisory (existing before this repair): remove_guarded_tree discovers only upwards (guarded_io.py:1226), so it never binds a run nested inside the tree it removes. Its only caller clears a stale pack's source-artifacts.
- advisory B1 edge: src/auditex/reporting.py:1885 adds the notice only to a JSON object, so a JSON list would be copied without it. No product writer produces one. Fix: under a temporary key, skip a non-object copy with a skipped_reason.
