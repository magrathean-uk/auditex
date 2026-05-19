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
```

## Auth and profiles

- `make login TENANT=<tenant-id-or-domain>` opens Azure CLI login with `--allow-no-subscriptions`.
- Exchange-backed collection needs `m365`.
- Saved app credentials live only in `.secrets/m365-auth.env`.

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
```

Compare, render, export, notify:

```bash
auditex compare --run-dir run-a --run-dir run-b
auditex report render <run-dir> --format md
auditex export list
auditex export run <exporter-name> <run-dir>
auditex notify send <run-dir> --sink teams
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


## Release and contract smoke

Before shipping a build, run the release checklist in [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md). At minimum, every release must pass:

```bash
python -m compileall -q src tests
python -m pytest
auditex run --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
```

The resulting `outputs/ci-contract/ci-contract/validation.json` must be valid and the final manifest must report `contract_status: valid`.

## Local safety

- Keep `.venv/`, `.secrets/`, and tenant outputs local.
- Keep raw evidence local; AI should read normalized artifacts by default.
- Use [docs/provenance/provenance.md](docs/provenance/provenance.md) when provenance questions matter.

## Verification notes

- Treat `auditex response run` as lab-only. Execution needs explicit intent, a lab tenant allowlist, and the matching allow flags for write actions and any adapter or command override.
- Imported token contexts should keep the raw token on disk in the secrets sidecar, not inside the context JSON.
- When checking exposure, verify the public route, direct-IP / Host-header path, and the blocked path separately. One green check is not enough.
