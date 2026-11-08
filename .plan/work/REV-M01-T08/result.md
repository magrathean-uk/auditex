## RESULT REV-M01-T08
status: done
summary:
verdict: approve
reviewed: 40260b019bbef58de53b5bd6205de3818e60d2ce
No required changes found. Runtime verification remains for merge.sh --verify.
changes: none
verification: PASS: git diff --check main...HEAD; dependency ancestry check; unchanged rule code, rule configs and Exchange vectors. Specified verification attempted, not runnable (exit 127): zsh:1: no such file or directory: .venv/bin/python
risks: Verification command at .plan/milestones/M01-boundary-proof.md:101 blocked by sandbox: required .venv link refused with "Operation not permitted"; pytest, generation and contract smoke did not run. Rule/vector, drift and shipped-content checks remain unexecuted. Mandatory session storage diagnostic exited 1 for GUI environment, DerivedData routing and lifecycle-lock issues; no repairs made.
questions_for_g: none

### Findings

- MET: M01-T04 dependency merged and is an ancestor of reviewed HEAD (0e4d69d); dependency specified at .plan/milestones/M01-boundary-proof.md:96.
- MET: Disclaimer removed from both commands; PrependSubject retained: src/azure_tenant_audit/collectors/exchange_policy.py:126, configs/collector-definitions.json:709.
- MET: Normalisation, adapter field set and catalogue updated: src/azure_tenant_audit/normalize.py:2107, src/auditex/scuba_adapters_exchange.py:38, docs/reference/api-call-catalog.md:172.
- UNTESTABLE: Runtime proof of unchanged SCuBA verdicts and generated-pack drift, required at .plan/milestones/M01-boundary-proof.md:98. Rule code, configs and vectors are unchanged; projection still selects the same four verdict inputs at src/auditex/scuba_adapters_exchange.py:35.
- MET: Fixtures updated: tests/test_scuba_adapters_exchange.py:225, tests/test_enterprise_depth_collectors.py:758, tests/test_exchange_policy_scuba_inputs.py:20, examples/demo_tenant/demo_tenant.json:530, examples/demo_tenant/demo_tenant_remediated.json:540.
- MET by inspection: Regression assertion rejects the field in both shipped command sources: tests/test_read_boundaries.py:1697. Execution blocked.
- MET: Both G6 rows use removed_at_request; G7 remains accepted: tests/test_read_boundaries.py:186.
- DoD: This task addresses the G6 portion of the content-read item at .plan/milestones/M01-boundary-proof.md:16, as scoped by .plan/DECISIONS.md:79. It does not claim to close the whole milestone.
- Security: No new secrets, injection paths, permissions, file-mode changes, deserialisation or dependencies found in the diff.
- Maintainability: Existing command parity and projection behaviour checks remain at tests/test_exchange_policy_scuba_inputs.py:208 and tests/test_scuba_adapters_exchange.py:135; no dead code found.
- Scope: All 11 changed paths match .plan/milestones/M01-boundary-proof.md:102. Unauthorised paths: none.

Required changes:
1. None.

Non-blocking suggestions: none.
