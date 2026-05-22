# Codex / AI Caller Prompt Pack

Use this as a starting prompt when handing over a tenant for audit:

```
Use the Auditex product surface in this folder.
First run offline validation:
`auditex run --offline --tenant-name <label> --sample examples/sample_audit_bundle/sample_result.json`.

Preferred guided operator flows:
`auditex guided-run`
`auditex guided-run --flow gr-audit --include-exchange`
`auditex guided-run --flow ga-setup-app`
`auditex guided-run --flow app-audit`

Before asking for tenant access:
`auditex setup-guide m365 --collector-preset full --format json`
`auditex setup-guide google --collector-preset everything --format json`

Codex-led flow:
1. Generate setup-guide JSON for the provider.
2. Authenticate the current session.
3. Run probe.
4. Capture the signed-in identity and directory roles.
5. Run live collection only after probe.
6. Return the audit bundle and blocked items.

Then run live collection with provided credentials:
`auditex run --tenant-name <tenant-name> --tenant-id <tenant-id> --client-id <app-id> --client-secret <secret> --top 400`.

If you prefer browser login with Global Reader/Admin:
`auditex run --tenant-name <tenant-name> --interactive --client-id <app-id> --browser-command firefox`.

If no app is available, use the Azure CLI flow:
`az login --tenant <tenant-id>` then
`auditex run --tenant-name <label> --tenant-id <tenant> --use-azure-cli-token --auditor-profile global-reader`.

Collectors to run by default: identity, security, intune, teams, exchange.
After run, open `<output>/<tenant-name>-<run-id>/summary.md` then inspect any raw/<collector>.json files with anomalies.

Bootstrap workflow (no app required, Azure CLI token mode):
`cd tenant-bootstrap && ./run-bootstrap-azurecli.sh --tenant-name <tenant-name> --dry-run`.

For a live build:
`cd tenant-bootstrap && ./run-bootstrap-azurecli.sh --tenant-name <tenant-name>`.

If you want end-to-end bootstrap + collection in one step:
`cd tenant-bootstrap && ./run-enterprise-audit.sh --tenant-name <tenant-name> --inspect`.

Also hand over logs on request:
- `audit-log.jsonl` for all command and Graph events
- `run-manifest.json` for an evidence summary and artifact map
- `bootstrap-shell.log` and `bootstrap-debug.log` for wrapper command-level logs (Azure CLI flow)
- `identity-seed-az-log.jsonl` and `workload-seed-az-log.jsonl` for seed command streams
```

Preferred output handling:

- Do not print secrets.
- Summarize any blocked collectors (`status=partial`/`failed`) and the exact error.
- Keep evidence paths in responses.
