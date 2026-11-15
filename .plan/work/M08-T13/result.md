## RESULT M08-T13
status: done
summary: Three live shape gaps fixed (lead-authored): Teams admin bare arrays, a manifest section gap of another operation no longer withholds a single read, DLP locations kept as lists. Each has a regression test that fails before the change; the live m08e run projects SPO_tenant with the fix.
changes: src/azure_tenant_audit/adapters/teams_admin_rest.py, tests/test_teams_admin_rest.py, src/auditex/scuba_projection.py, tests/test_scuba_projection.py, src/azure_tenant_audit/collectors/exchange_policy.py, tests/test_ipps_session.py, CHANGELOG.md (commit 5da16b3 on task/M08-T13-live-shapes)
verification: focused tests pass; make lint pass; make contract-smoke pass; full suite left to CHK-M08-T13
risks: the live Teams and DLP shapes are proven on one trial tenant only
questions_for_g: none
