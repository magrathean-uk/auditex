# Auditex Product Manual

Auditex is an audit-only evidence collection and reporting toolkit for Microsoft 365 and Google Workspace. It gathers read-only posture evidence, records exactly what was attempted, normalizes the evidence into a stable bundle, and produces a customer review pack with finding-to-evidence references and recorded coverage gaps.

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

For app-readonly tenants, use the app profile and an ignored local auth file containing `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`. Keep the file local; do not put secret values in shell commands or reports.

```bash
auditex run \
  --tenant-name CLIENT \
  --tenant-id <tenant-id> \
  --auditor-profile app-readonly-full \
  --plane full \
  --env .secrets/m365-auth.env \
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

### Attack paths

The report pack lists privilege-escalation paths from footholds to tier-0 control. Auditex builds a read-only graph from the run's normalized evidence: users, groups, service principals, applications, directory roles, PIM schedules, app and service principal owners, Microsoft Graph application permissions, delegated grants, MFA registration, and app credentials. It then looks for the shortest routes (at most five privilege hops, ten paths) from ordinary users, guests, users without MFA, third-party or multi-tenant apps, and apps with long-lived or expired secrets to tier-0 roles such as Global Administrator or to Graph permissions such as `RoleManagement.ReadWrite.Directory`.

Each path names every hop, its MITRE ATT&CK technique, and the normalized record that proves it, plus the breakpoints: the single changes that remove the route. High and critical paths also appear as findings. Open the explorer's Attack paths tab or read `attack_paths` and `attack_graph` in `reports/report-pack.json`.

The graph only sees what the run collected. Group membership is read for role-assignable groups and the groups nested in them, and app role assignments are read for Microsoft Graph and the first ten service principals. A missing collector or permission means fewer edges, so treat "no path found" as "no path in the collected evidence".

### Detection coverage and public footprint

`reports/report-pack.json` answers "could this tenant see an attack?" in
`detection_coverage`: a list of signals (unified audit log, mailbox auditing,
audit bypass, alert policies, risk-based Conditional Access, Identity
Protection, sign-in and directory audit logs, Defender alerts API, SIEM export),
each `on`, `off`, or `unknown`, with `evidence_ref` and `why_it_matters`. The
`score` counts only signals with evidence; `unknown` means not collected or
blocked and is never treated as `off`. `off` signals raise `detection.*`
findings. Exchange cmdlets need an Exchange Online PowerShell session, and
`Get-ProtectionAlert` needs Security & Compliance PowerShell. Enable the
`identity_protection` collector (`IdentityRiskyUser.Read.All`, Entra ID P2) to
assess risk detection.

`public_footprint` lists what anyone can learn about each verified domain
without credentials (tenant ID, region, federation). It is informational. A
federated domain raises the low-severity
`exposure.federated_domain_metadata_public` finding. MTA-STS and TLS-RPT gaps
raise `dns_posture.mta_sts_missing`, `dns_posture.mta_sts_testing_mode`,
`dns_posture.mta_sts_policy_invalid`, and `dns_posture.tls_rpt_missing`. See
`docs/reference/security-privacy.md` for the external lookups involved.

`reports/report-pack.json` also carries `baseline_alignment`. It shows the status of each CIS Microsoft 365 v7, CISA SCuBA, Microsoft Secure Score, Zero Trust, and Microsoft cloud security benchmark control that Auditex rules map to, and a Secure Score reconciliation table. To list rules by product area or framework, run `auditex rules packs --kind framework` or `auditex rules inventory`. [Framework Mappings](../reference/framework-mappings.md) describes the sources and limits.

## Render Reports

```bash
auditex report render <run-dir> --format md
auditex report render <run-dir> --format html --output reports/client-report.html
auditex report render <run-dir> --format json --output reports/client-report.json
auditex report render <run-dir> --format csv --output reports/findings.csv
auditex report render <run-dir> --format sarif --output reports/findings.sarif.json
auditex report render <run-dir> --format oscal --output reports/oscal.json
```

## Run Explorer

```bash
auditex report explorer <run-dir>
auditex report explorer <run-dir> --compare <previous-run-dir> --output explorer.html
```

The explorer is one self-contained HTML file (default `<run-dir>/reports/explorer.html`) for auditors, administrators and customer stakeholders. It has seven views:

- **Overview**: risk grade on the engine's grade scale, a one-line verdict, open findings by severity, findings with proof, collector coverage, bundle contract status, the five findings to fix first, findings by area, and run metadata.
- **Findings**: search by title, object, rule or control id; filter by area, framework, status and severity; findings page in groups of 20. Each finding shows what was found, why it matters, how to fix it, affected objects, framework mapping, and the evidence record (source file and record key) that proves it, with a copy button.
- **Attack paths**: each route from a foothold to tier-0 control, every hop with its relationship, ATT&CK technique and evidence record, and the single change that breaks the route.
- **Detection**: the detection signals with their status. Not verified signals are never counted as off; the score is withheld when most signals are not verified.
- **Baselines**: per-framework control status (fail, accepted risk, pass, not assessed) with links to the findings, and the Microsoft Secure Score reconciliation.
- **Access & data handling**: the assertions recorded in `data-handling.json`, and every collector with its status (verified, not verified with the reason, or not selected) and read permissions.
- **Before / after**: with `--compare`, the oldest run against the newest: grade change, resolved, new and changed findings, attack paths and detection score. Runs from different tenants or platforms are refused.

The header switches between embedded runs, toggles light and dark themes, and prints a customer handoff PDF (all views in one flow, critical and high findings expanded). The file makes no network requests and uses no web fonts; a Content-Security-Policy pins its one inline script by hash, and the same runs always produce the same bytes. It contains tenant evidence: share it the way you would share the run folder.

## Customer Pack

Create the pack in a fresh directory, verify its integrity, and review its content before sharing. Generated packs may contain tenant identifiers and other sensitive metadata; verification is not a disclosure approval.

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

If `verify-pack` returns `valid: false`, do not send the pack. Recreate it from the run directory or investigate missing or tampered files.
`stale_accepted_risk` means the bundle still marks a finding as accepted even though its waiver expiry date has passed.

For targeted review, render single artifacts outside the verified pack. Changing pack files invalidates its recorded hashes:

```bash
auditex report handoff <run-dir> --format md --output review-notes/handoff.md
auditex report api-calls <run-dir> --format md --output review-notes/api-calls.md
auditex report permissions <run-dir> --format md --output review-notes/permissions.md
auditex report proof-table <run-dir> --format md --output review-notes/proof-table.md
```

## Compare And Drift

Compare completed runs from the same tenant:

```bash
auditex compare --run-dir outputs/baseline/client --run-dir outputs/current/client
auditex compare --run-dir outputs/baseline/client --run-dir outputs/current/client --format md
```

JSON is the default. `--format md` prints a before/after summary of the first and last run: risk grade change, and new, resolved, and changed findings grouped by severity.

Use drift gates in CI or scheduled checks:

```bash
auditex gate <run-dir> --fail-on high
auditex gate-drift --baseline <old-run> --current <new-run> --fail-on medium
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

## Validation before release

Review the checks in [the runbook](../development/runbook.md#development-and-release-checks). Offline validation and local tests do not establish live provider acceptance. At minimum:

- contract smoke passes,
- full tests pass,
- customer pack verifies,
- no-secret scan is clean,
- docs match current commands,
- Google and Microsoft sample runs still validate,
- public 1.0 surface remains audit-only.
