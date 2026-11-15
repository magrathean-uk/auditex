## RESULT M08-T14
status: done
summary: Repair round 1 is done. Every review and check item is fixed, and the branch is rebased onto main (head bcb1312).
  REV item 1, fixed: the instance read is now section-scoped. When it fails, only privileged_roles is withheld and the failure is named as a section gap, while the collector stays complete and MS.AAD privileged-MFA keeps its evidence. A licence refusal of the read is recorded as a skipped section with reason license_required, so the PIM licence exemption still holds. baselines.py did not need to change.
  REV item 2, fixed: the generator now removes the disabled admin's instance as well, the remediated demo was regenerated (only rasi-005 is dropped), and a coherence test pins it.
  CHK fixed: the fixture answers the new read, the demo index count is now 1081, and roleassignmentscheduleinstances is added to _D5_FIELD_NAMES. All criteria are met.
changes: src/azure_tenant_audit/collectors/identity_governance.py, tests/test_privileged_roles.py, docs/reference/output-contract.md, scripts/make-remediated-demo.py, examples/demo_tenant/demo_tenant_remediated.json, src/azure_tenant_audit/output_redaction.py, tests/test_enterprise_depth_collectors.py, tests/test_mcp_temp_layouts.py, CHANGELOG.md (commits ac2b4d4, 5ffb259, bcb1312, on top of the round 0 commits rebased onto main)
verification: verify line (pytest on the 7 files && make lint && make contract-smoke) under hostload on bcb1312: pass, exit 0. Lint said "All checks passed!" and the smoke ended "privileged_roles artefact written, withheld by the frozen shape gate; bundle seal verified".
  Full suite (make test) under hostload --wait 5400 on bcb1312: pass, 23905 passed, 273 skipped, 34 xfailed. The first attempt was stopped at 48% by my shell's 10-minute limit, with no failures up to then; I re-ran it with a longer limit.
  Negative case for item 1 (fix reverted in a scratch copy): "AssertionError: only privileged_roles reads the instances / assert 'partial' == 'ok'" and "KeyError: 'reason'".
  Negative case for the coherence test (old remediated fixture): "AssertionError: an instance without its schedule".
  Focused passes: test_privileged_roles, test_redaction_person_names, test_enterprise_depth_collectors, test_mcp_temp_layouts, test_demo_and_explorer, test_scuba_projection. Evidence is in .plan/work/M08-T14/evidence.md, with logs verify-r1.log and full-suite-r1.log.
risks: A licence refusal of the instance read now shows as status "skipped" (reason license_required) rather than "failed". It is still named in collection_gaps and the manifest, but the re-review should confirm that wording is acceptable. The other way to keep the exemption was a one-line _LICENCE_GATED_SECTIONS entry in baselines.py, which this task does not own.
  The section-gap summary prints the raw reason "license_required", because SECTION_GAP_REASON_TEXT in collection_gaps.py (not owned) has no text for it.
questions_for_g: none
