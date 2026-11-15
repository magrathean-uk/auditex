## RESULT CHK-M08-T13
status: done
summary: check: pass
checked: 5da16b3ffd83d1816ecd15bcd9aee044eaa8df34
Verify line, `make lint`, `make contract-smoke` and the full suite exited 0 in the heavy slot. All three new regression tests fail on main source and pass on the branch. The diff shows no tenant write, no file-content read and no widening of kept data.
changes: none (notes in .plan/work/CHK-M08-T13/notes.md)
verification: hostload verify line, then full `pytest tests`: pass (exit 0, no F or E in the output). `make lint`: pass. `make contract-smoke`: pass. Scratch copy with the three changed src files taken from main: 3 new tests fail, as expected.
risks: none
questions_for_g: none
### Findings
- Regression tests fail on main, pass on branch: `tests/test_teams_admin_rest.py::test_accepted_shapes[parsed2]` (bare array, KeyError on main).
- `tests/test_scuba_projection.py::test_manifest_section_gap_of_another_operation_does_not_withhold_a_single_read` fails on main with `SPO_tenant` withheld.
- `tests/test_ipps_session.py::test_unrolled_dlp_locations_become_lists` fails on main with `'All'` instead of `['All']`.
- The new `[]` case in `test_empty_configuration_or_global_policy_is_withheld` passes on both main and branch. It guards behaviour that is kept, so it is not a regression test.
- `src/azure_tenant_audit/adapters/teams_admin_rest.py`: the bare-array path still runs the per-row dict check, the required-field type check and the empty-answer withhold. The changed source is read-only.
- `src/azure_tenant_audit/collectors/exchange_policy.py`: the string and null DLP locations are normalised to lists before minimising. Any non-"All" value is still replaced by the literal `"location"`, so nothing new is kept.
- `src/auditex/scuba_projection.py`: the extra `if not health: return` only applies to single-read sections and mirrors the existing coverage-row rule. Health sections still raise, and the test confirms a gap naming the section the payload does carry still withholds.
