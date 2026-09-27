<p align="center">
  <img src="https://raw.githubusercontent.com/magrathean-uk/magrathean-uk/main/assets/icons/auditex.png" width="96" height="96" alt="">
</p>

<h1 align="center">Auditex</h1>

<p align="center">A read-only Microsoft 365 and Google Workspace tenant-audit toolkit, for auditors and admins.</p>

<p align="center">
  <a href="https://auditex.hu">Website</a> ·
  <a href="docs/index.md">Documentation</a> ·
  <a href="https://auditex.hu/privacy/">Privacy</a>
</p>

## Overview

Auditex is a Python CLI and MCP toolkit for read-only Microsoft 365 and Google Workspace tenant audits. It collects local evidence, normalizes results, and produces report, export, comparison, and customer handoff artifacts.

The public audit surface does not write to production tenants. It also does not read message bodies or file contents in audit mode. The separate `tenant-bootstrap/` kit is for lab setup and rehearsal; treat it as a writable lab tool with its own credentials, outputs, and safeguards.

## What is included

- Microsoft 365 collection through the `auditex` and `azure-tenant-audit` CLIs.
- Google Workspace collection through the optional `google` dependencies.
- Guided setup and audit flows, capability probes, local auth-context management, and diagnostics.
- Offline fixtures for contract checks and demonstrations.
- Report rendering, CSV/JSON and other exporters, comparison and drift gates, customer handoff packs, and a local MCP server.

The package is Python 3.11 or newer. Its required runtime dependencies are `requests` and `msal`. Google Workspace and MCP support are optional extras.

## Install and check locally

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install pytest
auditex doctor --json
```

Optional dependencies:

```bash
python -m pip install -e '.[google]'
python -m pip install -e '.[mcp]'
```

Useful repository checks are:

```bash
make lint
make test
make contract-smoke
./scripts/oss-taint-scan.sh
```

`make contract-smoke` runs an offline sample and checks the finalized bundle contract. See [the runbook](docs/development/runbook.md) for the complete local and release check matrix.

## Main commands

Generate a provider-specific permission and scope plan before requesting access:

```bash
auditex setup-guide m365 --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

Guided operator flow:

```bash
auditex guided-run
auditex guided-run --flow gr-audit --include-exchange
auditex guided-run --flow app-audit
```

The `ga-setup-app` flow is a separate setup operation. Run it only when you are authorized to create or configure the app registration and its permissions:

```bash
auditex guided-run --flow ga-setup-app
```

Offline runs are safe for local checking:

```bash
auditex run --offline --tenant-name demo --out outputs/offline
auditex google run --offline --sample examples/google_workspace_sample.json \
  --domain example.com --tenant-name demo --out outputs/google
```

For an authorized live Microsoft 365 audit with an existing Azure CLI sign-in, authenticate first and use the resulting delegated read-only context:

```bash
make login TENANT=contoso.onmicrosoft.com
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com \
  --use-azure-cli-token \
  --auditor-profile global-reader --out outputs/live
```

Use `auditex probe live` after auth or scope changes to identify capability blockers before a full run. For app-based runs, use an already authorized read-only app context and follow the generated setup guide.

Google Workspace supports domain-wide delegation and OAuth. The full Google path requires the optional dependencies and provider credentials kept outside the repository:

```bash
auditex google doctor --json
auditex google probe --auth domain-delegation --domain example.com \
  --service-account-key /path/to/service-account.json --subject admin@example.com
```

## Read a run and prepare a handoff

Each finalized run contains a manifest, summary, report pack, evidence index, AI context, and validation result. The current contract version is recorded in `run-manifest.json`; required files and evidence rules are documented in [the output contract](docs/reference/output-contract.md).

```bash
auditex report render <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex compare --run-dir run-a --run-dir run-b
auditex export list
```

Start customer review with the handoff output, then inspect the API and permission ledgers, proof table, `data-handling.json`, and `validation.json`. Partial runs should be explained with their blocker and readiness artifacts rather than presented as complete coverage.

## MCP

Run the local MCP server after installing the `mcp` extra:

```bash
auditex-mcp
```

The MCP registry exposes inventory and contract inspection, offline validation, Microsoft 365 and Google Workspace audit/probe operations, run summaries and comparisons, reports and proof tables, customer-pack verification, exports, notifications, rules, auth status, and setup guides. Audit operations retain the same read-only and no-content-read boundary as the CLI.

## Documentation

Use [docs/index.md](docs/index.md) as the documentation index.

- [The runbook](docs/development/runbook.md) covers setup, operator flows, local checks, and the separate lab bootstrap kit.
- [The product manual](docs/guides/product-manual.md) explains the product workflows.
- [The setup guide](docs/guides/setup-guide.md) and [the administrator permission guide](docs/guides/admin-permission-guide.md) cover access planning.
- [The security and privacy model](docs/reference/security-privacy.md) describes data handling and audit boundaries.
- [The customer handoff guide](docs/guides/customer-handoff-guide.md) covers review packs.
- [The troubleshooting guide](docs/guides/troubleshooting.md) covers common failures.
- [AGENTS.md](AGENTS.md) contains repository-specific development rules.
- [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) covers development setup and review expectations.
- [.github/SUPPORT.md](.github/SUPPORT.md) explains how to request help and report product issues.

Keep `.venv/`, `.secrets/`, tenant evidence, and generated output directories local. Never commit tokens, OAuth caches, service-account keys, or tenant evidence. Do not add external telemetry.

## Licence

Auditex is open source under the Apache License 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE); the fuller dependency inventory is in
[third-party notices](docs/legal/third-party-notices.md). Security reporting instructions
are in [.github/SECURITY.md](.github/SECURITY.md). Trademark information is in
[docs/legal/trademarks.md](docs/legal/trademarks.md). Contributions: see
[CONTRIBUTING](.github/CONTRIBUTING.md).

<sub>© 2026 MAGRATHEAN UK LTD · [Legal](https://github.com/magrathean-uk/.github/blob/main/LEGAL.md)</sub>
