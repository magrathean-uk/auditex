## RESULT REV-M08-T14
status: partial
summary: Correctness review complete; verify deferred: heavy slot busy.
  verdict: changes-required
  reviewed: 1310ec1858466e527cdbd4ffb0f0ef4bc2c686b2
changes: .venv link; .plan/work/REV-M08-T14/{progress,notes,evidence}.md; no source edits or commits
verification: Offline reproduction probes passed; required verify deferred by hostload (exit 75); pytest, lint and contract-smoke did not start.
risks: Required verification remains outstanding.
questions_for_g: none
### Findings

- [P2] `src/azure_tenant_audit/collectors/identity_governance.py:89`: An instance-only failure makes the collector partial, changing privileged-MFA baseline `pass` to `not_assessed` despite unchanged admin evidence. Instance licence refusals also break the existing licence exemption. Preserve baseline failure isolation and extend licence handling.
- [P2] `examples/demo_tenant/demo_tenant_remediated.json:412`: `rasi-005` retains the disabled administrator removed from schedules and role assignments. Normalisation still emits that administrator under Global Administrator. Update the remediation generator and regenerate the fixture.
- Reproduction details: `.plan/work/REV-M08-T14/notes.md`.
