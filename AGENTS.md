# Auditex Agent Notes

## First read

- Start with `README.md` for product shape and quick commands.
- Use `RUNBOOK.md` for local setup, live audit flow, tenant bootstrap, and verification.
- Use `docs/README.md` as the product docs index.
- Use `docs/OUTPUT_CONTRACT.md` for bundle artifact rules.
- Use `docs/SECURITY_PRIVACY.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, and `docs/provenance/provenance.md` for safety, reporting, legal, and provenance context.
- Treat `docs/AUDITEX_NEXT_5_RELEASE_ROADMAP.md` as planning context, not operator runbook truth.
- Deleted plan, status, and duplicate AI docs are not working canon.

## Repo shape

- `src/azure_tenant_audit/` is the core Microsoft 365 audit engine, collectors, normalization, findings, contract finalization, and CLI module.
- `src/auditex/` is the product wrapper: CLI, guided flows, Google Workspace path, reporting/export/notify surfaces, MCP server, setup guide, and auth helpers.
- `tests/` holds pytest coverage for core, product CLI, Google Workspace, contracts, reports, exports, and security hygiene.
- `.github/workflows/` runs tests, compliance taint scan, Pages redirect build, and offline audit/SARIF/OSCAL gate.
- `configs/`, `profiles/`, `schemas/`, `agent/`, and `skills/` are shipped runtime/operator content; update tests when their contract changes.
- `tenant-bootstrap/` is a portable helper kit. Keep it aligned with root behavior instead of inventing separate commands or docs.
- `scripts/` contains local setup, login, tenant audit wrappers, taint scan, Python selector, and Pages redirect build.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Optional extras:

```bash
python -m pip install -e '.[google]'
python -m pip install -e '.[mcp]'
auditex setup --exchange
auditex setup --pwsh
```

Makefile setup helpers:

```bash
make install
make bootstrap
make setup
make doctor
```

## Test, lint, smoke, format, typecheck

Use discovered repo commands only:

```bash
make test
make lint
make contract-smoke
./scripts/oss-taint-scan.sh
python3 scripts/build-pages-site.py site
auditex --help
auditex doctor --json
auditex guided-run --help
auditex google --help
auditex report --help
auditex-mcp --help
```

- `make test` runs `python -m pytest` through `scripts/select-python.sh`.
- `make lint` runs `python -m compileall -q src tests`.
- `make contract-smoke` recreates `outputs/ci-contract`, runs the offline sample, and asserts valid `validation.json`, valid manifest status, and `index/evidence.sqlite`.
- No dedicated formatter command was found.
- No dedicated static typecheck command was found.
- CI uses Python 3.13, installs with `python -m pip install -e . pytest`, runs pytest, command help, contract smoke, taint scan, Pages build, and scheduled offline audit gate. Locally, prefer `python3` or the active venv because bare `python` may not exist.

## CLI surfaces

```bash
auditex guided-run
auditex run --offline --tenant-name demo --out outputs/offline
auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name demo --out outputs/google
auditex compare --run-dir run-a --run-dir run-b
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex-mcp
```

Use `auditex setup-guide ...` before asking for tenant roles, OAuth scopes, or admin consent.

## Generated and local-only paths

Do not hand-edit or commit:

- `.venv/`
- `.secrets/`
- `outputs/`
- `audit-output/`
- `.pytest_cache/`
- `src/auditex.egg-info/`
- `tenant-bootstrap/runs/`
- `tenant-bootstrap/.secrets/`
- wheels, tarballs, and generated Pages output under `site/`

Generated audit bundles must be fixed at the collector, normalizer, report, or finalizer source, then rerun.

## Editing rules

- Use Python 3.11+ and match nearby style.
- Keep collector, adapter, and report changes narrow by provider or concern.
- Do not change public command shapes, schemas, or bundle artifacts without updating docs, tests, and contract expectations.
- Keep `configs/collector-definitions.json`, `configs/collector-permissions.json`, setup guide output, permission ledger, and API inventory aligned when collector scope truth changes.
- Keep Google Workspace as a separate read-only path unless an explicit architecture task says otherwise.
- Keep raw tenant evidence, tokens, service-account keys, OAuth caches, app secrets, and bearer material out of git and out of docs.
- Do not add Sentry, analytics, or external crash telemetry. Diagnostics stay local unless a runbook says otherwise.
- Public Auditex is audit-only. Do not add production tenant write actions to audit, probe, report, export, MCP audit tools, or customer-pack verification.
- Do not read Gmail bodies, Drive file content, Exchange mailbox bodies, SharePoint file content, or OneDrive file content in audit mode.

## Done when

Future Codex tasks should finish with:

- relevant docs or code updated together;
- focused tests added or updated when behavior changes;
- `make lint` run for Python edits when practical;
- `make test` or a focused pytest target run for behavior changes when practical;
- `make contract-smoke` run when bundle schema, reports, collectors, evidence refs, API inventory, or customer pack behavior changes;
- docs updated when commands, scopes, artifacts, setup, or handoff flows change;
- explicit blockers listed when live tenant auth, optional tools, network, credentials, or customer-specific access prevents verification.

If verification is skipped, say which command was skipped and why.
