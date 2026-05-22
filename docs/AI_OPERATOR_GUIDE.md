# Auditex AI Operator Guide

Use this when an AI agent prepares or runs an Auditex tenant audit.

## Rules

- Start with `auditex setup-guide`.
- Run probe before full live collection.
- Keep audit mode read-only.
- Do not request extra permissions until a probe proves a blocked surface.
- Do not paste auth files or raw tenant evidence into chats, issues, or reports.
- Answer from bundle artifacts, not memory.

## Preflight

Google Workspace:

```bash
auditex setup-guide google --collector-preset everything --format json
auditex google doctor --json --collector-preset everything
auditex google probe --collector-preset everything --top 1 --page-size 1
```

Microsoft 365:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format json
auditex doctor --json
auditex probe live --tenant-name CLIENT --tenant-id <tenant-id> --auditor-profile global-reader --mode delegated --surface all --use-azure-cli-token
```

If probe returns partial, summarize the blockers exactly. Do not claim complete coverage.

## Live Run

Google Workspace:

```bash
auditex google run --collector-preset everything --tenant-name CLIENT-GOOGLE --out outputs/google
```

Microsoft 365:

```bash
auditex run --tenant-name CLIENT --tenant-id <tenant-id> --auditor-profile global-reader --plane full --use-azure-cli-token --probe-first --throttle-mode safe --out outputs/live
```

## Review Order

1. `validation.json`
2. `summary.json`
3. `live-readiness.json`
4. `audit-plan.json`
5. `api-inventory.json`
6. `data-handling.json`
7. `reports/report-pack.json`
8. `auditex report analyze <run-dir>`

## Customer Pack

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

Only share a pack when verification passes.

## Answer Shape

Report:

- status: complete, partial, or unusable,
- top findings by severity,
- blocked surfaces and exact reason,
- read-only proof from `api-inventory.json` and `data-handling.json`,
- artifact paths for evidence.

Do not report a finding without evidence refs.
