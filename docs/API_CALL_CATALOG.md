# Auditex API Call Catalog

Auditex writes `api-inventory.json` into every finalized bundle. This artifact is the customer-facing ledger for what the tool attempted to read, which collector attempted it, which permission family was needed, and whether any content or write action occurred.

## Contract

`api-inventory.json` contains:

- `declared_collectors`: planned collector coverage, status, required permissions, observed permissions, and missing permissions.
- `observed_calls`: endpoint-level calls observed during live runs and probes.
- `counts`: declared collector count, observed call count, mutating call count, and content-read call count.
- `safety`: read-only status, no-content-read status, write-capable scopes, and any mutating/content-read exceptions.

The bundle validator fails audit-plane bundles when this artifact reports tenant writes or body/file content reads.

## Read-Only Rules

Auditex 1.0 audit paths are read-only:

- No Gmail body reads.
- No Drive file content reads.
- No Exchange mailbox body reads.
- No SharePoint or OneDrive file content reads.
- No Graph or Google tenant writes from audit, probe, report, export, or MCP audit tools.

Some providers expose settings through broad scopes. When that happens, `data-handling.json` and `api-inventory.json` both record the scope risk and the fact that Auditex used read methods only.

## Customer Use

For enterprise review, provide the full bundle directory. Review these artifacts first:

1. `run-manifest.json`
2. `data-handling.json`
3. `api-inventory.json`
4. `audit-plan.json`
5. `live-readiness.json`
6. `reports/report-pack.json` (`proof_table` maps findings to exact evidence rows)
7. `validation.json`

These files show what was planned, what was called, what was blocked, what was proven, and what limitations remain.

For command-line handoff:

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex report handoff <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
```

Add `--output <path>` to persist any of these review files in the customer handoff pack.

The permission ledger joins `api-inventory.json` and `audit-plan.json` so reviewers can see required, observed, and missing scopes per collector. The `customer-pack` command also copies selected customer-safe source artifacts, including `data-handling.json`, `api-inventory.json`, `audit-plan.json`, `reports/report-pack.json`, `validation.json`, and `ai_context.json`, under `source-artifacts/` with hashes in `pack-manifest.json` and `checksums.sha256`. Run `verify-pack` before handoff.
