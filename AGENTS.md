# Auditex Agent Guide

Read `README.md`, `RUNBOOK.md`, `docs/README.md`,
`docs/OUTPUT_CONTRACT.md`, and `docs/SECURITY_PRIVACY.md` before changing the
related surface. `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, and
`docs/provenance/provenance.md` hold security, legal, and provenance context.

## Repo map

- `src/azure_tenant_audit/`: Microsoft 365 audit engine, collectors,
  normalization, findings, bundle finalization, and core CLI.
- `src/auditex/`: product CLI, guided flows, Google Workspace path, reports,
  exports, notifications, MCP server, and auth/setup helpers.
- `configs/`, `profiles/`, and `schemas/`: shipped collection and contract data.
- `agent/` and `skills/`: shipped operator/runtime content.
- `tests/`: core, product, Google, contract, report, export, and safety tests.
- `tenant-bootstrap/`: portable lab helper kit; keep it aligned with root
  behavior.
- `scripts/`: setup, login, audit, taint-scan, Python selection, release smoke,
  and Pages build helpers.

## Rules

- Inspect `git status --short` first and preserve unrelated work.
- Use Python 3.11 or newer and match nearby style.
- Public Auditex is audit-only. Audit, probe, report, export, MCP audit tools,
  and customer-pack verification must not write to production tenants.
- Do not read Gmail or Exchange bodies, or Drive, SharePoint, or OneDrive file
  content in audit mode.
- Keep Google Workspace as a separate read-only provider path.
- Keep collector definitions, permission maps, setup-guide output, permission
  ledgers, and API inventories aligned when scope truth changes.
- Update schemas, docs, tests, and contract expectations together when public
  commands or bundle artifacts change.
- Never commit tenant evidence, tokens, OAuth caches, service-account keys,
  secrets, or bearer material. Do not add external telemetry.
- Treat `.venv/`, `.secrets/`, `.pytest_cache/`, `outputs/`, `audit-output/`,
  `src/auditex.egg-info/`, `site/`, and tenant-bootstrap run/secret folders as
  generated or local.

## Setup and verification

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
make lint
make test
make contract-smoke
./scripts/oss-taint-scan.sh
python3 scripts/build-pages-site.py /tmp/auditex-pages
auditex --help
auditex doctor --json
auditex guided-run --help
auditex-mcp --help
```

`make test` uses `scripts/select-python.sh`; `make lint` compiles `src` and
`tests`; `make contract-smoke` recreates `outputs/ci-contract` and validates an
offline bundle. No dedicated formatter or static typecheck command is
configured.

Run `make contract-smoke` when collectors, reports, schemas, evidence refs, API
inventory, or customer-pack behavior changes. Report any skipped check and its
blocker.
