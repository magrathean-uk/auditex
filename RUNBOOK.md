# Auditex Runbook

This is the live operator and local-dev path for Auditex.

## Setup

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

Health check:

```bash
auditex doctor
auditex doctor --json
auditex setup-guide m365 --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

## Local development checks

Use the Makefile and CI-discovered commands as the local truth:

```bash
make test
make lint
make contract-smoke
./scripts/oss-taint-scan.sh
python3 scripts/build-pages-site.py site
```

What each check covers:

- `make test` runs `python -m pytest`.
- `make lint` runs `python -m compileall -q src tests`.
- `make contract-smoke` rebuilds the offline sample bundle in `outputs/ci-contract` and asserts valid contract status plus `index/evidence.sqlite`.
- `./scripts/oss-taint-scan.sh` checks forbidden research/derived paths and taint markers.
- `python3 scripts/build-pages-site.py site` builds the GitHub Pages redirect artifact.

Provider run note:

- Microsoft 365 and Google `run` and `probe` now stamp the same shared provider finalization metadata in `run-manifest.json`: `provider_adapter_version` and `api_inventory_recorder_version`. Use those fields when checking whether two bundles came through the same orchestration path.

Command help smoke:

```bash
auditex --version
auditex --help
auditex doctor --json
auditex guided-run --help
auditex google --help
auditex report --help
auditex-mcp --version
auditex-mcp --help
```

No dedicated formatter or static typecheck command is currently defined in the repo. Do not invent one in docs or CI without adding the actual tool config.

## Auth and profiles

- `make login TENANT=<tenant-id-or-domain>` opens Azure CLI login with `--allow-no-subscriptions`.
- Exchange-backed collection needs `m365`.
- Saved app credentials live only in `.secrets/m365-auth.env`.
- Google Workspace credentials stay local: use a service-account key path for domain-wide delegation or an OAuth client/token cache path for delegated OAuth.

Shipped profile notes:

- [profiles/global-reader.md](profiles/global-reader.md)
- [profiles/security-reader.md](profiles/security-reader.md)
- [profiles/app-readonly-full.md](profiles/app-readonly-full.md)
- [profiles/exchange-reader.md](profiles/exchange-reader.md)
- [profiles/intune-reader.md](profiles/intune-reader.md)

## Guided audit flows

Default operator path:

```bash
auditex guided-run
```

Common flows:

```bash
auditex guided-run --flow gr-audit --include-exchange
auditex guided-run --flow ga-setup-app
auditex guided-run --flow app-audit
```

Repo-local wrapper:

```bash
./scripts/tenant-audit-flow --flow gr-audit --include-exchange
```

## Direct CLI flows

Offline sample:

```bash
auditex run --offline --tenant-name demo --out outputs/offline
auditex run --offline --sample examples/sample_audit_bundle/known_bad_result.json --tenant-name demo --run-name known-bad --out outputs/offline-known-bad
auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name demo --out outputs/google
python3 tenant-bootstrap/scripts/replay-known-bad-fixtures.py --out tenant-bootstrap/fixture-output --clean
python3 tenant-bootstrap/scripts/replay-known-bad-fixtures.py --bootstrap-run-dir tenant-bootstrap/runs/<seed-run> --out tenant-bootstrap/fixture-output --clean
```

Compare, render, export, notify:

```bash
azure-tenant-audit --version
auditex compare --run-dir run-a --run-dir run-b
auditex report render <run-dir> --format md
auditex export list
auditex export run <exporter-name> <run-dir>
auditex notify send <run-dir> --sink teams
```

Default compare suppresses volatile churn like raw sync timestamps and usage report refresh dates. Use `auditex compare --classic ...` when raw timestamp-only changes still matter.

## Google Workspace

Install optional Google libraries only when needed:

```bash
python -m pip install -e '.[google]'
auditex setup-guide google --auth domain-delegation --collector-preset everything --format md
auditex google doctor --json
```

Domain-wide delegation is the preferred full-domain path:

```bash
auditex google run \
  --auth domain-delegation \
  --service-account-key /path/to/service-account.json \
  --subject admin@example.com \
  --domain example.com \
  --customer-id C123 \
  --tenant-name EXAMPLE \
  --out outputs/google
```

Run `auditex google probe ...` first after scope changes. It performs tiny endpoint reads and reports the capability matrix before a full collection. Use `--collector-preset everything` when Drive metadata, Google Groups settings, and Calendar sharing posture are in scope; add these extra DWD scopes when enabling that preset:

```text
https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly,https://www.googleapis.com/auth/calendar.calendarlist.readonly,https://www.googleapis.com/auth/calendar.acls.readonly
```

## Tenant bootstrap

The bootstrap kit stays in `tenant-bootstrap/` and shares the root runtime when the full repo is present.

Install bootstrap-only requirements:

```bash
python3 -m pip install -r tenant-bootstrap/requirements.txt
```

Recommended full chain:

```bash
cd tenant-bootstrap
./run-enterprise-audit.sh --tenant-name "Example Tenant" --inspect
```

Other common entrypoints:

```bash
cd tenant-bootstrap
./run-bootstrap-azurecli.sh --tenant-name "EXAMPLE-LAB"
./run-enterprise-lab-max.sh --run-name enterprise-lab-max-dryrun --days 1
./run-enterprise-lab-max.sh --live --run-name enterprise-lab-max-live --days 30
```


## Contract smoke

Before handing off a build, run:

```bash
python -m compileall -q src tests
python -m pytest
auditex run --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
```

The resulting `outputs/ci-contract/ci-contract/validation.json` must be valid and the final manifest must report `contract_status: valid`.

Release CI also runs `make contract-smoke`, `./scripts/oss-taint-scan.sh`, `python3 scripts/build-pages-site.py /tmp/auditex-pages`, and a built-wheel offline smoke.

For local release packaging proof, build `dist/` and run `bash scripts/release-smoke.sh dist /tmp/auditex-release-smoke`. That smoke path validates base wheel install plus `google` and `mcp` extras in separate virtualenvs.
Release tags must match the packaged version from `auditex --version`: for example `1.0.0` ships as git tag `v1.0.0`.

Product docs live under [docs/README.md](docs/README.md). Update the manual, setup guide, admin permission guide, customer handoff guide, security/privacy model, and troubleshooting guide when commands, scopes, artifacts, or checks change.

For enterprise evidence review, render the API call ledger:

```bash
auditex report customer-pack outputs/ci-contract/ci-contract --output-dir outputs/ci-contract/customer-pack
auditex report verify-pack outputs/ci-contract/customer-pack
auditex report handoff outputs/ci-contract/ci-contract --format md
auditex report api-calls outputs/ci-contract/ci-contract --format md
auditex report permissions outputs/ci-contract/ci-contract --format md
auditex report proof-table outputs/ci-contract/ci-contract --format md
```

Use `customer-pack` when handing material to a reviewer. It writes `README.md`, handoff, full Markdown report, API ledger, permission ledger, proof table, JSON copies, selected customer-safe source artifacts under `source-artifacts/`, `checksums.sha256`, and `pack-manifest.json` with hashes. Run `verify-pack` before handoff to catch missing or tampered files. Start with the handoff output, then use the API call ledger, permission ledger, and proof table for detail. Use them beside `data-handling.json`, `audit-plan.json`, `reports/report-pack.json` (`proof_table`), and `validation.json` to show what APIs were attempted, which scopes were needed or missing, which exact evidence rows prove each finding, and whether the run stayed read-only.
Use `--output reports/<name>.md` or `--output reports/<name>.json` when creating a persisted customer handoff pack.

When a run is partial, start with `live-readiness.json`. Its blocker summary separates missing scopes, admin role limits, unlicensed or absent services, local toolchain gaps, tenant policy blocks, runtime errors, and unverified collectors.

## Local safety

- Keep `.venv/`, `.secrets/`, and tenant outputs local.
- Keep raw evidence local; AI should read normalized artifacts by default.
- Use [docs/provenance/provenance.md](docs/provenance/provenance.md) when provenance questions matter.

## Verification notes

- Public Auditex is audit-only. Lab response tools are hidden unless `AUDITEX_ENABLE_RESPONSE=1` is set for local development.
- Imported token contexts should keep the raw token on disk in the secrets sidecar, not inside the context JSON.
- When checking exposure, verify the public route, direct-IP / Host-header path, and the blocked path separately. One green check is not enough.

## Done criteria for repo changes

- Setup, command, scope, artifact, or handoff changes are reflected in `README.md`, this runbook, or product docs as applicable.
- Behavior changes have focused pytest coverage.
- Bundle, report, collector, API inventory, evidence ref, or customer-pack changes pass `make contract-smoke`.
- Python edits pass `make lint` when practical.
- Live tenant work records blockers honestly when auth, scopes, licenses, optional tools, network, or customer access prevent verification.
