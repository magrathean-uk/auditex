## RESULT M09-T03
status: done
summary: Repair round 1 (review-1.md) addressed; all three items fixed.
1 fixed: `scripts/tenant-audit-full` and `scripts/bootstrap-local-tools.sh` no longer echo a rejected argument. Unknown, abbreviated or malformed arguments are named only by their position. Tests cover inline, abbreviated and malformed sensitive forms on stdout and stderr.
2 fixed: the `purview`, `ediscovery` and `exchange` metadata no longer asks for `m365`, a CLI session or CLI commands. It now states what the certificate reads and names the gap `m365_cli_not_used`, and the setup guide shows this as a step. Tests cover app-readonly-full and explicit Purview/eDiscovery/Exchange guides.
3 fixed: the read-guard tests skip the retired Exchange collector, which has no commands. The m365 adapter still applies the read guard first and logs refusals. The full suite then showed two more failures, both fixed: a CHANGELOG line naming a missing path, and five product field names missing from the redaction list.
changes: scripts/tenant-audit-full, scripts/bootstrap-local-tools.sh, configs/collector-permissions.json, src/auditex/setup_guide.py, src/azure_tenant_audit/adapters/m365_cli.py, src/azure_tenant_audit/output_redaction.py (generated _D5_FIELD_NAMES only; outside the files line, done under review item 3 "fix anything else it shows"), CHANGELOG.md, tests/test_local_auth_scripts.py, tests/test_setup_guide.py, tests/test_read_guard.py, tests/test_adapters.py, .plan/work/M09-T03/result.md (commits ac0d857, 8ac23db, 3b48ea0, fb06f59, f9721bc, 0cdc74c, 3bfb174)
verification: make test, full suite, run directly after hostload exit 75 three times (lead-authorised): on fb06f59 2 failed, 23,487 passed; on 0cdc74c 23,489 passed, 271 skipped, 34 xfailed, 0 failed (.plan/work/M09-T03/make-test-r2.log): pass.
Verify line on 3bfb174 with PYTHONPATH=src (make lint, the eight pytest files, make contract-smoke, result grep): pass, 230 tests. make lint: "All checks passed!". gitleaks over cbfedfb..HEAD: no leaks found.
Negative cases:
- Old script: `--client-secret=constructed-canary` printed "Unknown argument: --client-secret=constructed-canary".
- New script: that input gives "--client-secret was removed: ...".
- `--certificate-password-file=...` gives "--certificate-password-file=VALUE is not accepted; pass --certificate-password-file VALUE (value not shown)."
- `--access-tok constructed-canary` gives "Unknown argument 3 (not shown)."
- Guide check on the old metadata finds 'm365 ', 'CLI session', 'CLI-driven', 'authenticated M365' and the tool m365; on the new metadata it finds none.
risks: The teams_policy, exchange_policy and Power Platform permission notes still mention secret, delegated or access-token runs, which no longer exist. This is wording only; follow-up for M09-T04.
Round-0 follow-ups still open: remove the deprecated ProbeConfig/ResponseConfig fields and auth_context helpers; update .plan/ARCHITECTURE.md rows; add .plan/CLEANUP.md rows for the 8 deleted paths (see notes.md).
questions_for_g: none
### Findings
product-certificate-only: yes
