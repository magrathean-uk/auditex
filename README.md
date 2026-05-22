# Auditex

Auditex is a Python-first CLI and MCP toolkit for Microsoft 365 and Google Workspace tenant audits. It keeps raw evidence local, emits normalized report packs, and supports the main operator modes:

Built by [Magrathean UK](https://magrathean.uk).

- delegated read-only audits,
- Google Workspace domain-delegated or OAuth read-only audits,
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
auditex setup-guide google --collector-preset identity --format json
auditex setup-guide m365 --collector-preset identity-only --format json
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
auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name demo --out outputs/google
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

Before requesting tenant access, generate the setup plan:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --auth domain-delegation --collector-preset everything --format md
```

Use the JSON form for AI/MCP callers:

```bash
auditex setup-guide m365 --collector-preset full --format json
auditex setup-guide google --collector-preset everything --format json
```

## Canon docs

- [AGENTS.md](AGENTS.md) - repo rules and edit guardrails.
- [RUNBOOK.md](RUNBOOK.md) - setup, live audit flows, and tenant bootstrap commands.
- [docs/README.md](docs/README.md) - full product documentation index.
- [docs/provenance/provenance.md](docs/provenance/provenance.md) - provenance sheet.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) - third-party notice file.
- [CHANGELOG.md](CHANGELOG.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md) - v1 release notes.

## Website and releases

Build the GitHub Pages handoff artifact locally:

```bash
python scripts/build-pages-site.py site
```

The public website lives at `auditex.hu` outside this repository. The `pages` workflow only keeps GitHub Pages configured to hand traffic to that domain.

Create the v1 release from a verified checkout:

```bash
make test
make lint
make contract-smoke
python -m build
git tag -a v1 -m "Auditex v1 enterprise release"
git push origin main v1
gh release create v1 dist/* --title "Auditex v1 Enterprise Release" --notes-file RELEASE_NOTES.md --verify-tag
```

## Data handling

- Keep `.venv/`, `.secrets/`, and tenant exports local.
- Treat `configs/`, `profiles/`, `schemas/`, `agent/`, and `skills/` as shipped operator/runtime content.
- Treat generated audit outputs as artifacts, not hand-edited source.

Saved auth contexts from `auditex auth import-token` can be reused for `auditex probe live --auth-context <name>`.

Google Workspace coverage uses a separate read-only path:

```bash
python -m pip install -e '.[google]'
auditex google doctor --json
auditex google probe \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123
auditex google run \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123 \
  --tenant-name EXAMPLE \
  --out outputs/google
```

The Google path reuses the same local bundle contract, report, export, compare, and MCP surfaces as Microsoft 365 runs. Use `--collector-preset everything` for Drive metadata, Google Groups settings, Calendar sharing ACLs, and deeper Gmail protocol/send-as posture; this may require adding `drive.metadata.readonly`, `apps.groups.settings`, `admin.directory.resource.calendar.readonly`, `calendar.calendarlist.readonly`, and `calendar.acls.readonly` scopes to domain-wide delegation.

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

| Path | CLI profile | Sign-in | Exchange-assisted |
| --- | --- | --- | --- |
| Global Reader | `global-reader` | Delegated | Optional with `--include-exchange` |
| Security Reader | `security-reader` | Delegated | No |
| App read-only full | `app-readonly-full` | App-only or delegated token | Yes, with `m365` and `powershell_graph` adapters |
| Exchange-assisted | `exchange-reader` | Delegated | Yes, built in |

Use `auditex probe live --mode delegated|app` for probe runs. Public Auditex 1.0 is audit-only.

## Output contract

Current contract version: `2026-04-21`.

Successful `run` and `probe` bundles are finalized through one contract path. Required contract artifacts are:

- `run-manifest.json`
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite`
- `ai_context.json`
- `validation.json`

The manifest records `schema_contract_version`, `contract_status`, and `contract_issue_count`. `validation.json` fails loudly on missing required artifacts, broken finding evidence refs, malformed normalized records, invalid evidence DB shape, unsafe `ai_safe/` drift, bad new proof-table rows, and audit-plane API inventories that report tenant writes or body/file content reads. Raw evidence stays local; normalized, report, proof-table, evidence-index, API inventory, and `ai_safe` artifacts are the intended reasoning surfaces.

Additional run artifacts include `summary.md`, `data-handling.json`, `audit-plan.json`, `api-inventory.json`, `audit-log.jsonl`, `audit-debug.log`, `raw/`, `index/coverage.jsonl`, `blockers/`, `diagnostics.json`, `normalized/`, `ai_safe/`, `findings/`, `reports/`, `chunks/`, and `checkpoints/checkpoint-state.json`.

Schemas live in `schemas/`; contract notes live in [docs/OUTPUT_CONTRACT.md](docs/OUTPUT_CONTRACT.md). The product documentation index lives in [docs/README.md](docs/README.md), with the operator manual, setup guide, admin permission guide, customer handoff guide, AI operator guide, GitHub operator guide, security/privacy model, troubleshooting guide, and ship-readiness guide. The 1.0 audit-only release plan lives in [docs/improvement/auditex-1.0-ultimate-plan.md](docs/improvement/auditex-1.0-ultimate-plan.md).

For customer call review:

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex report handoff <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
```

Run `verify-pack` before handoff. Add `--output <path>` to write any single customer-review artifact to disk.

## MCP

Local MCP entrypoint:

```bash
auditex-mcp
```

Current MCP tools include local contract, auth, run, probe, report, export, notification, and diff surfaces:

- `auditex_list_profiles`
- `auditex_list_collectors`
- `auditex_list_adapters`
- `auditex_contract_schema_manifest`
- `auditex_run_offline_validation`
- `auditex_run_delegated_audit`
- `auditex_google_doctor`
- `auditex_google_probe`
- `auditex_run_google_workspace_audit`
- `auditex_summarize_run`
- `auditex_diff_runs`
- `auditex_compare_runs`
- `auditex_probe_live`
- `auditex_probe_summarize`
- `auditex_list_blockers`
- `auditex_report_preview`
- `auditex_report_analyze`
- `auditex_api_inventory`
- `auditex_permissions_ledger`
- `auditex_proof_table`
- `auditex_enterprise_handoff`
- `auditex_verify_customer_pack`
- `auditex_export_list`
- `auditex_notify_preview`
- `auditex_rules_inventory`
- `auditex_auth_status`
- `auditex_auth_list`
- `auditex_auth_use`
- `auditex_auth_import_token`
- `auditex_auth_inspect_token`
- `auditex_auth_capability`
- `auditex_setup_guide`

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

Auditex performs reads and limited operational actions against Microsoft 365 tenants, and read-only Google Workspace collection when using the Google path. **You may use Auditex only against tenants that you own, or for which you have explicit written authorisation from the tenant owner.** Unauthorised access to a Microsoft 365 tenant, Google Workspace domain, or any computer system is a criminal offence under the **Computer Misuse Act 1990** in the United Kingdom and equivalent laws elsewhere. You are solely responsible for: (a) obtaining proper authorisation before any audit; (b) compliance with Microsoft and Google terms of service and the tenant's own data-protection commitments; (c) compliance with the **UK GDPR** and the **Data Protection Act 2018** in respect of any personal data observed; (d) handling, retaining, and protecting evidence packs and reports produced by Auditex; and (e) any regulatory, civil, or criminal liability arising from your use of Auditex.

### Trademarks and disclaimers

Microsoft, Microsoft 365, Entra ID, Intune, Defender, Exchange, SharePoint, Azure, the Microsoft Graph, and PowerShell are trademarks of Microsoft Corporation. Google, Google Workspace, Gmail, Google Drive, Google Calendar, ChromeOS, and related marks are trademarks of Google LLC. The trademarks of any other vendor referenced in this repository remain the property of their respective owners.

Auditex is **not affiliated with, endorsed by, sponsored by, or in any way officially connected to** Microsoft Corporation, Google LLC, or any other vendor. References to these names exist solely for descriptive interoperability.

### Reporting

For security issues, see [`SECURITY.md`](./SECURITY.md). For licensing or commercial enquiries, email <contact@magrathean.uk>.

---

Magrathean UK Ltd. is a company registered in England and Wales (Company No. 16955343) with registered office at 16 Caledonian Court West Street, Watford, England, WD17 1RY.
