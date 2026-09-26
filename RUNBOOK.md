# Auditex runbook

Use this runbook for local setup, authorized audits, and development checks. For access planning, start with the [setup guide](docs/SETUP_GUIDE.md). For the full workflow, use the [product manual](docs/PRODUCT_MANUAL.md).

## Install and inspect

Use Python 3.11 or newer from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
auditex doctor --json
auditex --help
```

Google Workspace needs `python -m pip install -e '.[google]'`; MCP needs `python -m pip install -e '.[mcp]'`. `auditex setup` installs local tools. Its `--mcp`, `--exchange`, and `--pwsh` options install optional tooling, so use them only for the intended scope.

## Plan access and probe

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

Review the generated plan with the tenant administrator. Scope names may carry broader rights than the read calls Auditex makes; check scope risk before granting access. Keep app credentials, service-account files, and token caches in an ignored local location such as `.secrets/`.

For delegated Microsoft 365 access:

```bash
az login --allow-no-subscriptions --tenant contoso.onmicrosoft.com
auditex probe live --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --mode delegated --use-azure-cli-token
```

`make login TENANT=contoso.onmicrosoft.com` is an alternative Azure CLI login helper that selects Firefox. Review the probe's `live-readiness.json` and `audit-plan.json` before collection. Missing scopes, roles, licenses, services, local tools, tenant policy, runtime errors, and unverified surfaces are separate blockers.

## Run an audit

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --auditor-profile global-reader --plane full --use-azure-cli-token --out outputs/live
```

`auditex guided-run` provides the interactive route. `--flow gr-audit` uses delegated access and `--flow app-audit` uses saved app credentials. `--flow ga-setup-app` performs app setup and requires explicit authority to create or change the customer-local registration; it is not an audit-only step.

Google Workspace commands and credential choices are in the [product manual](docs/PRODUCT_MANUAL.md#google-workspace-audit-flow). Rerun a probe after changing roles or scopes.

## Offline fixtures

```bash
auditex run --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name demo --run-name sample --out outputs/offline
auditex run --offline --sample examples/sample_audit_bundle/known_bad_result.json --tenant-name demo --run-name known-bad --out outputs/offline-known-bad
auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name demo --out outputs/google
```

These exercise sample processing and do not demonstrate live tenant access or completeness.

## Review and hand off

```bash
auditex report handoff <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

Use a fresh pack directory and review it for confidential information before sharing through the customer's approved channel. Integrity verification does not establish audit completeness or permission to disclose. Follow the [customer handoff guide](docs/CUSTOMER_HANDOFF_GUIDE.md), including expired accepted-risk checks.

```bash
auditex compare --run-dir run-a --run-dir run-b
auditex gate-drift --baseline run-a --current run-b --fail-on high
auditex export list
auditex notify send <run-dir> --sink teams
```

Comparison suppresses selected volatile timestamp changes by default; `--classic` retains them. Notifications are previews unless `--execute` is supplied. Sending is an external action that needs an authorized destination and reviewed content.

## Development and release checks

Install pytest for development: `python -m pip install -e . pytest`.

| Check | What it exercises |
| --- | --- |
| `make lint` | Compiles Python under `src` and `tests`; it does not check style or types. |
| `make test` | Runs pytest with the interpreter selected by `scripts/select-python.sh`. |
| `make contract-smoke` | Deletes and recreates `outputs/ci-contract`, validates an offline bundle and its evidence index. |
| `./scripts/oss-taint-scan.sh` | Checks forbidden research/derived paths and taint markers. |
| `python3 scripts/build-pages-site.py /tmp/auditex-pages` | Recreates the destination as a redirect artifact to the configured site. It deletes an existing destination. |

The existing `.pre-commit-config.yaml` also declares checks including a manual Ruff hook. This runbook does not change or install hooks. Use focused tests for changed behavior. Contract changes need contract smoke. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution scope and check reporting.

The existing release workflow installs Google and MCP extras, runs the checks above, builds the wheel and source distribution, and invokes `bash scripts/release-smoke.sh dist /tmp/auditex-release-smoke`. That script creates isolated environments for base, Google, and MCP package checks. The release tag must be `v` followed by the packaged version. These are workflow definitions, not a statement that a particular release has passed.

## Lab tools

`tenant-bootstrap/` seeds lab tenant data and contains writable operations. `run-enterprise-audit.sh` runs bootstrap before audit by default; it is not a production audit shortcut. Inspect its `--help` and the selected configuration before any separately authorized lab work. Keep lab credentials and outputs separate from customer audits.

The response plane is hidden by default and guarded separately. Do not enable it for an ordinary audit. Agent command templates under `agent/` include lab tools as well as audit commands; inspect the selected tool before execution.
