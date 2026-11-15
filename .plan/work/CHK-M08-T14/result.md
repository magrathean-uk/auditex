## RESULT CHK-M08-T14
status: done
summary: check: pass
checked: 0d6c4866972b240d67a495a0924c7cfcd838a434
Ran in the heavy slot (acquired after 0s). Verify line passed (1729 passed, 2 skipped; `make lint` clean; `make contract-smoke` valid), and the full suite exited 0. Evidence is in `.plan/work/CHK-M08-T14/evidence.md`.
changes: none
verification: verify line (focused pytest, make lint, make contract-smoke) pass; full suite `pytest tests` pass (exit 0; no summary line printed because the pytest config is quiet); scratch copy with `main` versions of the 7 changed src and config files: new tests fail, as intended
risks: none
questions_for_g: none
### Findings
- Regression tests on `main`: 22 new or changed tests fail against `main` source and pass on the branch.
- The two the brief names: `test_a_direct_assignment_without_an_instance_start_answers_aad_7_5_not_met` and `test_assignments_come_from_the_instances_not_the_schedules` both fail on `main`.
- `test_pim_assignments_with_an_instance_start_keep_aad_7_5_met` passes on both, as expected for a keep-met guard.
- The other new tests that fail on `main`: the failed-instance section-gap test, the licence-refusal test, the API-inventory test, the read-boundary scan test and four projection tests.
- Tenant writes: none. The only new call is `GET /roleManagement/directory/roleAssignmentScheduleInstances` (v1.0, no params), using the same read permission as the schedules. The API-inventory and read-boundary tests assert `content_reads` and `write_actions` false.
- File or message content: none read. The read returns role assignment metadata only.
- Widened retention: none. `Assignments` keep only `PrincipalId`, `StartDateTime` and `EndDateTime`, and the `directoryScopeId` field is dropped. The redaction word list gains only the operation name.
- Collector behaviour: a failed instance read is a section-scoped gap and does not make the collector partial. A licence refusal becomes "skipped", so the PIM licence exemption in `baselines.py` still holds. No credentials or workstation paths appear in the diff.
