## RESULT REV-M08-T01
status: done
summary:
verdict: changes-required
reviewed: eb810c2b90027d296037a99469929c6da9180d75
Three required changes: credential/output overlap, two uncollected Teams operations, and missing sign-in counts.
Verification could not start because .venv/bin/python is absent; the sandbox prevents linking it.
changes: none
verification: verify not runnable: .venv/bin/python -m pytest tests/test_certificate_auth.py tests/test_teams_policy_collector.py tests/test_teams_admin_rest.py tests/test_cli.py tests/test_cli_abbreviations.py tests/test_vendored_cli_abbreviations.py tests/test_secret_cli_matrix.py tests/test_command_output_privacy.py tests/test_presets.py tests/test_architecture_modules.py && make lint && make contract-smoke
risks: Credential files can remain in the bundle; executing check and contract smoke remain outstanding on this head.
questions_for_g: none
### Findings
- Certificate authentication: not met overall. PEM/PFX loading, MSAL minting, mixed-credential refusal and secret-only skips are implemented at src/azure_tenant_audit/certificate_auth.py:221, src/azure_tenant_audit/graph.py:442 and src/azure_tenant_audit/cli.py:1243; two required operations remain skipped at src/azure_tenant_audit/collectors/teams_policy.py:121.
- Porting: met by inspection. File-based credentials and tests are present at src/azure_tenant_audit/certificate_auth.py:221 and tests/test_certificate_auth.py:139; wt/collect-certauth-1 remains separate and retained.
- CLI and privacy: not met overall because credential/output overlap is unchecked at src/azure_tenant_audit/cli.py:686. Flag refusal, redaction and isolated fixtures are covered at tests/test_cli_abbreviations.py:261, tests/test_secret_cli_matrix.py:214 and tests/conftest.py:73.
- Selection: met by inspection at src/azure_tenant_audit/profiles.py:82, configs/collector-presets.json:42, src/azure_tenant_audit/selection.py:29 and tests/test_presets.py:285.
- Documentation: met for the requested certificate guidance at docs/guides/admin-permission-guide.md:165, docs/guides/setup-guide.md:171, docs/reference/api-call-catalog.md:40, configs/collector-permissions.json:301 and CHANGELOG.md:8. Shipped-content parity is untestable here; its check is tests/test_architecture_modules.py:235.
- Eleven-row closure and executing gates: untestable here. Required sections are mapped at configs/scuba-policy-sections.json:1001; the author records incomplete verification at .plan/work/M08-T01/result.md:3.
- Relevant DoD: certificate/default-selection implementation is present, but its test predicate was not executed. The sign-in-count documentation requirement is not met at src/auditex/setup_guide.py:385. Other milestone-wide DoD items are not claimed closed by this task.
- Scope: all 30 changed paths match the authoritative files line; no unexplained scope creep.
- Security and maintainability: fixed authentication errors, restricted file reads, in-memory credentials and behavioural tests are present. No dependency changes, unsafe deserialisation, tenant mutations or committed credentials were found. git diff --check main...HEAD passed.
- Progress file was not written because the sandbox is read-only.

1. src/azure_tenant_audit/cli.py:686 - Credential sources are loaded without checking their relationship to the effective run directory. A valid key or password file already inside that directory remains there and is included by src/azure_tenant_audit/bundle_integrity.py:270; a source named summary.json can also be overwritten. Reject credential sources within the effective output/resume directory and output aliases before constructing AuditWriter. Add regression coverage for retention and overwrite.
2. src/azure_tenant_audit/collectors/teams_policy.py:121 - Certificate runs still skip messagingPolicies and appSetupPolicies, contrary to the seven-operation criterion. Implement authenticated, guarded reads for both and require successful collection in tests/test_teams_policy_collector.py:256, which currently asserts those skips despite its name.
3. src/auditex/setup_guide.py:385 - The new certificate setup steps and docs/guides/setup-guide.md:171 omit the explicit sign-in counts required by the DoD. State the setup sign-ins separately from the zero interactive sign-ins required during an app-only certificate audit, and cover the generated guidance.

### Defect classes
Credential source/output overlap lacks refusal and regression coverage.
Incomplete collection is accepted by tests instead of enforcing the stated criterion.
Setup documentation omits required sign-in counts.
