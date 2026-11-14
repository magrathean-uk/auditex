## RESULT M08-T07
status: done
summary: Rebased onto main (e1ecc75). REV-M08-T07 item 1 fixed: in a guided delegated run with Exchange, an explicit --collectors list now drops the m365 CLI exchange collector and adds exchange_policy when it is missing (new _delegated_exchange_selection in src/auditex/guided.py). So `--collectors identity --include-exchange` and `--collectors identity,exchange --include-exchange` both run identity,exchange_policy over the one sign-in, with no second CLI sign-in.
Tests: tests/test_single_sign_in.py now runs the guided one-sign-in check for the default selection, `identity` and `identity,exchange`. The assertion in tests/test_cli_extensions.py that kept the bypass now expects exchange_policy.
Criteria: run-path sign-in counts, static checks, DEC-068 (4) `exchange-one-sign-in: met` and the docs were met before. The review's not-met item is now met.
changes: src/auditex/guided.py, tests/test_single_sign_in.py, tests/test_cli_extensions.py, .plan/work/M08-T07/result.md (plus the five earlier branch commits, rebased unchanged)
verification: criteria verify (grep result.md && pytest over the six focused files && make lint && make contract-smoke) passed (exit 0) on head 64b3172 after the rebase. make lint (Ruff): "All checks passed!". git diff --check main...HEAD clean; git status --porcelain empty. Negative case: with the explicit-list routing disabled, the guided guard fails with "AssertionError: assert ('exchange_policy' in ['identity'])" and "AssertionError: assert ('exchange_policy' in ['identity', 'exchange'])". Full suite not run; the merge batch runs make test.
risks: (1) It is still not confirmed live that the sign-in app is a public client with delegated Exchange.Manage and admin consent; CHK-M08-T07 or a live delegated run should confirm. (2) An explicit list in a delegated Exchange run silently swaps exchange for exchange_policy; the run does not print a notice about it.
questions_for_g: none

### Findings
exchange-one-sign-in: met
(line restored by the lead from round 1 and this round's summary; format fix in place, rule 7)
