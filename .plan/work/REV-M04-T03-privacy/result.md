## RESULT REV-M04-T03-privacy
status: done
summary:
verdict: changes-required
reviewed: 9f38936ce973ccb5ff34210cb4bf7649a1480431
Blocking: in a keyless run's customer pack, pack-manifest.json, README.md and the JSON copies under source-artifacts/ carry temporary-key pseudonyms but no notice. The key reached no output, log, repr or hash-manifest row in any test or probe. Pseudonyms are HMAC-SHA256 under a per-run key, and legacy bundles validate.
changes: none on the branch; notes.md, evidence.md and probes/ are in .plan/work/REV-M04-T03-privacy/
verification: pytest tests/test_redaction_keyed_pseudonyms.py pass (73 passed). Sample-data probes all ran as planned: key leak scan over every preview format, pack, notify and the run tree; keyless notice per file; keyless assess in two processes; label acceptance per schema version; a race between discovery and open that returned the key bytes.
risks: full suite not run (out of brief scope); the race probe forces the timing by wrapping `_parent`; MCP tools were called through their handlers, not FastMCP
questions_for_g: none

### Findings
- 1 Key secrecy: met apart from A1. Temporary registered before write (src/azure_tenant_audit/guarded_io.py:625); lock taken before anything is written (:674); 0600/0700 modes; only `excluded` in bundle-hashes; no-lock storage seals the run keyless (src/azure_tenant_audit/finalize.py:357).
- 2 Pseudonym strength: met. HMAC-SHA256 cut to 16 hex (src/azure_tenant_audit/output_redaction.py:313); no run-path salt left in src; the smoke seed is Makefile-only; compare uses the first-listed run's key (:1186).
- 3 Keyless runs: not met (B1). Every preview format, notify, MCP results (output_redaction.py:2008) and the five CLI commands carry the notice; damaged and widened keys refuse.
- 4 Legacy and contract: met. The old label validates under 2026-11-05, the keyed label is refused under 2026-10-29, unknown labels are refused (schemas/model_assessment.schema.json:369). The DEC-019/021 edits only relabel fixtures.
- 5 Tests: test_08, test_09, test_06 paused creator, test_02, test_10 (secrecy); test_15, test_01, test_04, test_12, test_14 (strength); test_18, test_11, amendment_6 tests, test_07 (keyless); test_11, test_16, tests/test_scuba_projection.py:454 (legacy). No test covers B1 (_PACK_FILES, tests/test_redaction_keyed_pseudonyms.py:1135), A1, or the keyed label being refused under 2026-10-29.
- 6 Other: no injection, deserialisation or error-text leak found; fixed messages hold no path or bytes. See A1 to A4.
- B1 blocking: src/auditex/reporting.py:2171, :2183, :2186 and :1810 against docs/reference/output-contract.md:268. In the demo, report-pack.json holds 1300 tokens and pack-manifest.json 7, neither with a notice. Fix: add `pseudonym_notice` to the manifest and the returned result, append the Markdown notice to README.md, add the notice to each JSON derivative in `_copy_source_artifact`, and extend _PACK_FILES to every file that can hold a pseudonym.
- A1 advisory: src/azure_tenant_audit/guarded_io.py:992-995 (and :1122, :1174, :1204). If another process publishes the key between discovery and open, and `operator-inputs/` did not exist at discovery, an ordinary read returns the key bytes. Fix: call `discover_run` again after the open, before `_check_file`, and add a test for it.
- A2 advisory: src/auditex/reporting.py:3932. CSV consumers count the notice row as a finding (DEC-021 item already open for G).
- A3 advisory: src/azure_tenant_audit/output_redaction.py:337-349. Session keys are keyed by device and inode only, so an MCP server can reuse a deleted run's inode for another keyless run and link people across the two. Fix: add the bound manifest's run_id to the key.
- A4 advisory: src/auditex/scuba_projection.py:1566. `for key in projection` shadows the key parameter; rename the loop variable.
