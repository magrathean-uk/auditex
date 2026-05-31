# Auditex Product Manual

Auditex is an audit-only evidence collection and reporting toolkit for Microsoft 365 and Google Workspace. It gathers read-only posture evidence, records exactly what was attempted, normalizes the evidence into a stable bundle, and produces a customer-review pack with proof for every claim.

## What Auditex Does

- Runs Microsoft 365 delegated, app-readonly, and offline sample audits.
- Runs Google Workspace domain-wide delegation, OAuth, and offline sample audits.
- Flags Google collaboration posture from metadata-only evidence, including public group visibility, public membership visibility, shared-drive external-member allowance, calendar ACL exposure, and Drive sharing exposure.
- Produces a local evidence bundle with manifest, summary, raw evidence, normalized records, findings, report pack, API inventory, proof table, evidence index, AI-safe context, and validation.
- Explains coverage gaps as structured blockers instead of pretending the audit is complete.
- Produces customer handoff packs with checksums and a verifier command.
- Provides CLI and MCP surfaces for the same bundle evidence.

## What Auditex Does Not Do

- It does not fix production tenants.
- It does not run production write actions in audit mode.
- It does not read Gmail bodies, Drive file content, Exchange mailbox bodies, SharePoint file content, or OneDrive file content.
- It does not place tenant credentials, service-account keys, OAuth caches, or bearer material into repo defaults or customer packs.
- It does not hide missing permissions, missing licenses, or blocked APIs.

## Install

Use Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Install optional Google dependencies only when Google Workspace audits are needed.

```bash
python -m pip install -e '.[google]'
```

Install MCP dependencies only when serving Auditex through MCP.

```bash
python -m pip install -e '.[mcp]'
```

## First Local Check

```bash
auditex doctor --json
auditex --help
auditex guided-run --help
auditex setup-guide m365 --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

If `doctor` reports missing optional tools, install only the adapters needed for the audit scope.

## Microsoft 365 Audit Flow

Start with delegated read access when you only have tenant login access.

Generate the access plan before asking an admin to grant roles or app permissions.

```bash
auditex setup-guide m365 \
  --mode delegated \
  --auditor-profile global-reader \
  --collector-preset full \
  --tenant-id <tenant-id-or-domain>
```

```bash
az login --allow-no-subscriptions --tenant <tenant-id-or-domain>
auditex probe live \
  --tenant-name CLIENT \
  --tenant-id <tenant-id-or-domain> \
  --mode delegated \
  --use-azure-cli-token \
  --run-name probe
```

If the probe is usable or partial with acceptable blockers, run the audit.

```bash
auditex run \
  --tenant-name CLIENT \
  --tenant-id <tenant-id-or-domain> \
  --auditor-profile global-reader \
  --plane full \
  --use-azure-cli-token \
  --out outputs/live
```

For app-readonly tenants, use the app profile and locally supplied app credentials.

```bash
auditex run \
  --tenant-name CLIENT \
  --tenant-id <tenant-id> \
  --auditor-profile app-readonly-full \
  --plane full \
  --client-id <app-id> \
  --client-secret <app-secret> \
  --out outputs/live
```

## Google Workspace Audit Flow

Domain-wide delegation is the preferred full-domain path.

Generate the scope list and setup steps first.

```bash
auditex setup-guide google \
  --auth domain-delegation \
  --collector-preset everything \
  --domain example.com \
  --customer-id my_customer \
  --subject admin@example.com
```

```bash
auditex google doctor --json \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123
```

Probe with small limits after every scope or admin change.

```bash
auditex google probe \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123 \
  --collector-preset everything \
  --top 1 \
  --page-size 1
```

Run full collection after probe confirms the useful surfaces.

```bash
auditex google run \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123 \
  --collector-preset everything \
  --tenant-name CLIENT-GOOGLE \
  --out outputs/google
```

OAuth is available when domain-wide delegation is not possible. Treat OAuth output as potentially partial because some domain-wide surfaces require service-account delegation.

```bash
auditex google run \
  --auth oauth \
  --oauth-client /path/to/oauth-client.json \
  --token-cache .secrets/google-token.json \
  --domain example.com \
  --tenant-name CLIENT-GOOGLE \
  --out outputs/google
```

## Offline Smoke

Microsoft 365 sample:

```bash
auditex run --offline \
  --sample examples/sample_audit_bundle/sample_result.json \
  --tenant-name demo \
  --out outputs/offline
```

Google Workspace sample:

```bash
auditex google run --offline \
  --sample examples/google_workspace_sample.json \
  --domain example.com \
  --tenant-name demo-google \
  --out outputs/google
```

## Read A Run

A completed run directory contains the contract artifacts. Start with:

1. `run-manifest.json`
2. `summary.json`
3. `validation.json`
4. `data-handling.json`
5. `audit-plan.json`
6. `live-readiness.json`
7. `api-inventory.json`
8. `reports/report-pack.json`

`validation.json` must be valid for customer handoff. Partial audits can still be useful, but the blocker reasons must be explicit.
Accepted-risk findings with expired waiver dates are stale for handoff and should be treated like a review blocker until re-approved.

## Render Reports

```bash
auditex report render <run-dir> --format md
auditex report render <run-dir> --format html --output reports/client-report.html
auditex report render <run-dir> --format json --output reports/client-report.json
auditex report render <run-dir> --format csv --output reports/findings.csv
auditex report render <run-dir> --format sarif --output reports/findings.sarif.json
auditex report render <run-dir> --format oscal --output reports/oscal.json
```

## Customer Pack

Create and verify the handoff pack before sharing.

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

If `verify-pack` returns `valid: false`, do not send the pack. Recreate it from the run directory or investigate missing or tampered files.
`stale_accepted_risk` means the bundle still marks a finding as accepted even though its waiver expiry date has passed.

For targeted review, render single artifacts:

```bash
auditex report handoff <run-dir> --format md --output customer-pack/handoff.md
auditex report api-calls <run-dir> --format md --output customer-pack/api-calls.md
auditex report permissions <run-dir> --format md --output customer-pack/permissions.md
auditex report proof-table <run-dir> --format md --output customer-pack/proof-table.md
```

## Compare And Drift

Compare completed runs from the same tenant:

```bash
auditex compare --run-dir outputs/baseline/client --run-dir outputs/current/client
```

Use drift gates in CI or scheduled checks:

```bash
auditex gate <run-dir> --fail-on high
auditex gate-drift --baseline-run-dir <old-run> --current-run-dir <new-run> --fail-on medium
```

## MCP

Start the MCP server:

```bash
auditex-mcp
```

Use MCP tools for bundle-backed answers only. Every answer should cite bundle evidence or say evidence is missing. Key read-only review tools:

- `auditex_summarize_run`
- `auditex_setup_guide`
- `auditex_report_preview`
- `auditex_report_analyze`
- `auditex_api_inventory`
- `auditex_permissions_ledger`
- `auditex_proof_table`
- `auditex_enterprise_handoff`
- `auditex_verify_customer_pack`
- `auditex_compare_runs`
- `auditex_rules_inventory`

## Ship Criteria

Auditex is shippable when:

- contract smoke passes,
- full tests pass,
- customer pack verifies,
- no-secret scan is clean,
- docs match current commands,
- Google and Microsoft sample runs still validate,
- public 1.0 surface remains audit-only.
