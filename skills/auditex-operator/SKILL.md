---
name: auditex-operator
description: Use when operating this repo as a Codex-led Microsoft 365 audit tool and choosing how to authenticate, collect evidence, and summarize blocked coverage.
---

# Auditex Operator

## Overview

Use Auditex as the stable local product surface, not the older homelab scripts, unless the task is specifically about tenant seeding.

## Run order

1. Validate the local package with offline mode.
2. Generate a provider setup plan with `auditex setup-guide`.
3. Prefer delegated Azure CLI token reuse for the first Microsoft 365 live pass.
4. Run probe before full collection.
5. Capture the signed-in context from the run manifest.
6. Inspect `summary.json`, `run-manifest.json`, and `diagnostics.json`.
7. Escalate only when blockers justify it.

## Commands

Offline:

```bash
auditex --offline --tenant-name demo --out outputs/offline
```

Delegated:

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format json
auditex --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --use-azure-cli-token --auditor-profile global-reader --out outputs/live
```

Google:

```bash
auditex setup-guide google --collector-preset everything --format json
auditex google probe --collector-preset everything --top 1 --page-size 1
```

## Evidence review

- `run-manifest.json`
- `audit-log.jsonl`
- `summary.json`
- `diagnostics.json`

Treat `partial` and `failed` collectors as structured gaps, not silent omissions.
