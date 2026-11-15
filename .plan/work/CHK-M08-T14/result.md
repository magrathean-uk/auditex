## RESULT CHK-M08-T14
status: done
summary: check: fail
checked: 1310ec1858466e527cdbd4ffb0f0ef4bc2c686b2
The verify line passes, but the full suite fails with 14 failures in 3 test files, all caused by the new `roleAssignmentScheduleInstances` read. Those files pass on main. Details are in `.plan/work/CHK-M08-T14/evidence.md`.
changes: none
verification: verify line (pytest on 7 files, `make lint`, `make contract-smoke`) pass; full suite fail (14 failed); new regression tests fail on main and pass on branch; the three failing files pass on main
risks: the branch cannot merge until the three files are updated; the redaction failure may also mean the new key is not exempt from whole-key masking in output
questions_for_g: none
### Findings
- FAIL tests/test_enterprise_depth_collectors.py::test_identity_governance_collector_collects_reviews_packages_and_role_schedules: `'partial' == 'ok'`; its fixture has no answer for the new read.
- FAIL tests/test_mcp_temp_layouts.py::test_demo_index_in_common_tmp_layouts (12 params): `item_count` is 1081, expected 1080; the demo bundle gains one operation, so the hard-coded count needs updating.
- FAIL tests/test_redaction_person_names.py::test_every_product_field_name_is_exempt_from_whole_key_masking: "regenerate `_D5_FIELD_NAMES` in src/azure_tenant_audit/output_redaction.py; missing: roleassignmentscheduleinstances". None of these three files, nor `output_redaction.py`, is in the brief's file list, so it needs a widened scope.
- OK regression tests (checked with the changed source files, plus `configs/collector-definitions.json`, taken from main in a scratch copy): the api_inventory read, read_boundaries scan, assignments-from-instances, direct assignment (MS.AAD.7.5 not met), instance-dates (4 params) and failed-schedule-does-not-withhold tests fail on main. All pass on the branch in the verify run.
- OK `test_pim_assignments_with_an_instance_start_keep_aad_7_5_met` also passes on main, as expected for a keep-met guard.
- OK diff read: one added `GET /roleManagement/directory/roleAssignmentScheduleInstances` (v1.0, no params, no content), same scope, no writes, no file-content reads. The kept fields (`PrincipalId`, `StartDateTime`, `EndDateTime`) were already in the artefact, so nothing is widened.
- NOTE src/azure_tenant_audit/adapters/read_guard.py is unchanged and needs no edit, since it only guards PowerShell commands.
