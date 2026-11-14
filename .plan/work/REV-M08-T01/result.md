## RESULT REV-M08-T01
status: done
summary:
verdict: approve
reviewed: 2f9c131ae3764ff5bf94967a61b7e2f385ac12f2
Prior fixes remain intact after rebase; no new blocking findings.
changes: none
verification: verify blocked by sandbox: .venv/bin/python -m pytest tests/test_certificate_auth.py tests/test_teams_policy_collector.py tests/test_teams_admin_rest.py tests/test_cli.py tests/test_cli_abbreviations.py tests/test_vendored_cli_abbreviations.py tests/test_secret_cli_matrix.py tests/test_command_output_privacy.py tests/test_presets.py tests/test_architecture_modules.py && make lint && make contract-smoke
risks: Executing check required on this head; live Teams behaviour remains unverified.
questions_for_g: none
### Findings
- Certificate authentication: met by inspection at src/azure_tenant_audit/certificate_auth.py:218 and src/azure_tenant_audit/graph.py:442. MSAL mints resource tokens; mixed credentials are refused at src/azure_tenant_audit/config.py:38.
- Teams collection: met by inspection at src/azure_tenant_audit/collectors/teams_policy.py:105 and tests/test_teams_policy_collector.py:256. Five REST operations and two named skips match DEC-070; secret-only and delegated skips are covered at tests/test_teams_policy_collector.py:306.
- Porting: file-only implementation and tests present at src/azure_tenant_audit/certificate_auth.py:218 and tests/test_certificate_auth.py:135. Source-branch retention is untestable: the named ref is absent from both checkouts.
- CLI/privacy: met by inspection at tests/test_cli_abbreviations.py:261, tests/test_vendored_cli_abbreviations.py:93 and tests/test_secret_cli_matrix.py:210. Coverage includes abbreviations, pass-through, ledger/bundle redaction and isolated credentials at tests/conftest.py:73.
- Selection: met by inspection at src/azure_tenant_audit/profiles.py:82, configs/collector-presets.json:42 and tests/test_presets.py:287.
- Documentation: met by inspection at docs/guides/admin-permission-guide.md:425, docs/guides/setup-guide.md:171, docs/reference/api-call-catalog.md:207, configs/collector-permissions.json:301 and CHANGELOG.md:16. Shipped-content parity is untestable here; its test is tests/test_architecture_modules.py:235.
- Eleven-row closure and executing gates: untestable here. Collection assertions are at tests/test_teams_policy_collector.py:275; .plan/work/CHK-M08-T01/result.md:4 binds its passing check to the previous SHA.
- Relevant DoD: certificate/default-selection implementation is present; execution remains untestable. Setup/audit sign-in counts are met at src/auditex/setup_guide.py:395 and docs/guides/setup-guide.md:179. Other milestone-wide items remain outside this task.
- Verification stopped before pytest: `zsh:1: no such file or directory: .venv/bin/python` (exit 127). The read-only sandbox prevents linking dependencies; pytest, lint and smoke did not run.
- Security/maintainability: no new credential disclosure, injection, unsafe deserialisation, dependency or file-mode defect found. Private-file restrictions remain at src/azure_tenant_audit/certificate_auth.py:98.
- Scope: tests/test_setup_guide.py:298 is the sole task-owned path outside the files line, explained by prior required change 3. Another 58 out-of-scope paths in the re-check delta are identical to rebased main, inherited rather than task additions.
- `git diff --check 785f613fdf82fd1406ece8aef73809b870ebda01..HEAD`: pass. Worktree clean. Progress notes skipped because filesystem writes are blocked.

Required changes: none.

Prior required changes:
1. fixed - src/azure_tenant_audit/cli.py:692 refuses credential/output overlap before writes; tests/test_cli.py:1493 asserts source preservation.
2. fixed against DEC-070 - tests/test_teams_policy_collector.py:282 requires five successful REST operations and two named skips.
3. fixed - src/auditex/setup_guide.py:395 and tests/test_setup_guide.py:298 distinguish setup sign-ins from zero interactive audit sign-ins.

Prior defect classes:
- Credential source/output overlap lacks refusal and regression coverage: fixed at src/azure_tenant_audit/certificate_auth.py:249 and tests/test_cli.py:1444.
- Incomplete collection accepted instead of enforcing the criterion: fixed against DEC-070 at tests/test_teams_policy_collector.py:282.
- Setup documentation omits required sign-in counts: fixed at docs/guides/setup-guide.md:179 and src/auditex/setup_guide.py:395.
