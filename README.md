# Auditex

Auditex is a Python-first CLI and MCP toolkit for Microsoft 365 tenant audits. It keeps raw evidence local, emits normalized report packs, and supports three main operator modes:

Built by [Magrathean UK](https://magrathean.uk).

- delegated read-only audits,
- one-time Exchange app bootstrap,
- saved app-based reruns.

## Repo shape

- `src/azure_tenant_audit/` - core collectors, auth, diffing, findings, and report generation.
- `src/auditex/` - product wrapper CLI plus MCP entrypoint.
- `configs/` - shipped collector definitions, permission maps, report sections, and rule packs.
- `profiles/` - shipped operator profile notes for delegated and app-based runs.
- `schemas/` - shipped output contracts.
- `agent/` and `skills/` - shipped operator/runtime content.
- `scripts/` - login helpers and guided-run wrappers.
- `tenant-bootstrap/` - portable tenant seeding kit for audit rehearsal and lab work.
- `tests/` - pytest coverage.

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
auditex setup
```

Optional adapters:

```bash
auditex setup --mcp
auditex setup --exchange
auditex setup --pwsh
```

Fast checks:

```bash
make test
make lint
auditex doctor
```

## Main flows

Guided operator flow:

```bash
auditex guided-run
auditex guided-run --flow gr-audit --include-exchange
auditex guided-run --flow ga-setup-app
auditex guided-run --flow app-audit
```

Direct CLI surface:

```bash
auditex run --offline --tenant-name demo --out outputs/offline
auditex compare --run-dir run-a --run-dir run-b
auditex report render <run-dir> --format md
auditex export list
auditex export run <exporter-name> <run-dir>
auditex notify send <run-dir> --sink teams
auditex-mcp
```

Use `auditex run ...` for explicit raw audit runs. Legacy raw flags without the `run` subcommand still work, but the docs prefer the explicit form.

The login helper stays local and uses `az login --allow-no-subscriptions` for tenant-level reader accounts:

```bash
make login TENANT=<tenant-id-or-domain>
```

## Canon docs

- [AGENTS.md](AGENTS.md) - repo rules and edit guardrails.
- [RUNBOOK.md](RUNBOOK.md) - setup, live audit flows, and tenant bootstrap commands.
- [docs/provenance/provenance.md](docs/provenance/provenance.md) - provenance sheet.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) - third-party notice file.

## Data handling

- Keep `.venv/`, `.secrets/`, and tenant exports local.
- Treat `configs/`, `profiles/`, `schemas/`, `agent/`, and `skills/` as shipped operator/runtime content.
- Treat generated audit outputs as artifacts, not hand-edited source.

Saved auth contexts from `auditex auth import-token` can be reused for `auditex probe live --auth-context <name>` and `auditex response run --auth-context <name>`.

Optional Exchange coverage:

```bash
auditex run \
  --tenant-name CONTOSO \
  --tenant-id contoso.onmicrosoft.com \
  --use-azure-cli-token \
  --auditor-profile global-reader \
  --include-exchange \
  --out outputs/live
```

Safer live runs can use:

```bash
auditex run --probe-first --throttle-mode safe
```

## Profiles

Built-in profiles:

- `auto`
- `global-reader`
- `security-reader`
- `reports-reader`
- `exchange-reader`
- `intune-reader`
- `app-readonly-full`

These profiles do not force permissions into existence. They shape:

- expected role context
- default collector intent
- escalation guidance in diagnostics
- report wording about blocked coverage

Quick support matrix:

| Path | CLI profile | Sign-in | Exchange-assisted | Response |
| --- | --- | --- | --- | --- |
| Global Reader | `global-reader` | Delegated | Optional with `--include-exchange` | No |
| Security Reader | `security-reader` | Delegated | No | No |
| App read-only full | `app-readonly-full` | App-only or delegated token | Yes, with `m365` and `powershell_graph` adapters | No |
| Exchange-assisted | `exchange-reader` | Delegated | Yes, built in | Yes |

Use `auditex probe live --mode delegated|app` for probe runs and `auditex response run --auditor-profile <profile>` for guarded response planning. `exchange-reader` is the only built-in response-capable profile.

## Output contract

Current contract version: `2026-04-21`.

Successful `run`, `probe`, and `response` bundles are finalized through one contract path. Required contract artifacts are:

- `run-manifest.json`
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite`
- `ai_context.json`
- `validation.json`

The manifest records `schema_contract_version`, `contract_status`, and `contract_issue_count`. `validation.json` fails loudly on missing required artifacts, broken finding evidence refs, malformed normalized records, invalid evidence DB shape, and unsafe `ai_safe/` drift. Raw evidence stays local; normalized, report, evidence-index, and `ai_safe` artifacts are the intended reasoning surfaces.

Additional run artifacts include `summary.md`, `audit-log.jsonl`, `audit-debug.log`, `raw/`, `index/coverage.jsonl`, `blockers/`, `diagnostics.json`, `normalized/`, `ai_safe/`, `findings/`, `reports/`, `chunks/`, and `checkpoints/checkpoint-state.json`.

Schemas live in `schemas/`; contract notes live in [docs/OUTPUT_CONTRACT.md](docs/OUTPUT_CONTRACT.md).

## MCP

Local MCP entrypoint:

```bash
auditex-mcp
```

Current MCP tools include local contract, auth, run, probe, report, export, notification, diff, and guarded response surfaces:

- `auditex_list_profiles`
- `auditex_list_collectors`
- `auditex_list_adapters`
- `auditex_contract_schema_manifest`
- `auditex_run_offline_validation`
- `auditex_run_delegated_audit`
- `auditex_summarize_run`
- `auditex_diff_runs`
- `auditex_compare_runs`
- `auditex_probe_live`
- `auditex_probe_summarize`
- `auditex_list_blockers`
- `auditex_report_preview`
- `auditex_export_list`
- `auditex_notify_preview`
- `auditex_rules_inventory`
- `auditex_list_response_actions`
- `auditex_run_response_action`
- `auditex_auth_status`
- `auditex_auth_list`
- `auditex_auth_use`
- `auditex_auth_import_token`
- `auditex_auth_inspect_token`
- `auditex_auth_capability`

## Response

Guarded response actions are isolated from the default audit plane:

```bash
auditex response list-actions
auditex response run --tenant-name ACME --action message_trace --target user@contoso.com --intent "triage mail flow" --tenant-id organizations
```

By default the response command writes a dry-run bundle. Execution requires `--execute`, explicit intent, a response-capable profile, and lab-tenant gating.

## Privacy and auditability

- secrets and tokens are scrubbed from command logging
- collector crashes do not abort the run
- permission issues become structured diagnostics
- raw tenant evidence is stored locally
- normalized and `ai_safe` artifacts are the default reasoning surfaces

## GitHub

Target repository: `magrathean-uk/auditex`

## Legal

Copyright © 2026 Magrathean UK Ltd. All rights reserved.

Auditex is proprietary software. See [`LICENSE`](./LICENSE) for the full licence text. Third-party components and their licences are listed in [`license.md`](./license.md) and [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) where present. Public availability of this repository does not grant any right to copy, modify, redistribute, or use the software outside the licence terms.

### Lawful use only — tenant audits

Auditex performs reads and limited operational actions against Microsoft 365 tenants. **You may use Auditex only against tenants that you own, or for which you have explicit written authorisation from the tenant owner.** Unauthorised access to a Microsoft 365 tenant or to any computer system is a criminal offence under the **Computer Misuse Act 1990** in the United Kingdom and equivalent laws elsewhere. You are solely responsible for: (a) obtaining proper authorisation before any audit; (b) compliance with Microsoft's terms of service and the tenant's own data-protection commitments; (c) compliance with the **UK GDPR** and the **Data Protection Act 2018** in respect of any personal data observed; (d) handling, retaining, and protecting evidence packs and reports produced by Auditex; and (e) any regulatory, civil, or criminal liability arising from your use of Auditex.

### Trademarks and disclaimers

Microsoft, Microsoft 365, Entra ID, Intune, Defender, Exchange, SharePoint, Azure, the Microsoft Graph, and PowerShell are trademarks of Microsoft Corporation. The trademarks of any other vendor referenced in this repository remain the property of their respective owners.

Auditex is **not affiliated with, endorsed by, sponsored by, or in any way officially connected to** Microsoft Corporation or any other vendor. References to these names exist solely for descriptive interoperability.

### Reporting

For security issues, see [`SECURITY.md`](./SECURITY.md). For licensing or commercial enquiries, email <contact@magrathean.uk>.

---

Magrathean UK Ltd. is a company registered in England and Wales (Company No. 16955343) with registered office at 16 Caledonian Court West Street, Watford, England, WD17 1RY.
