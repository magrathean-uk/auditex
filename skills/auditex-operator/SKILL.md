---
name: auditex-operator
description: Use when operating Auditex for an authorized Microsoft 365 or Google Workspace audit and summarizing evidence coverage.
---

# Auditex Operator

Use the `auditex` product surface for normal audit work. Keep the public audit
plane read-only. Tenant-bootstrap is a separate lab helper surface and may
contain write-capable actions.

## Run order

1. Validate the package with an offline sample.
2. Generate provider setup guidance.
3. For an authorized live Microsoft 365 pass, prefer delegated Azure CLI token
   reuse before requesting app consent.
4. Run a probe before full collection.
5. Record the signed-in context and the evidence paths.
6. Inspect the summary, manifest, data-handling record, API inventory, and
   diagnostics when present.
7. Treat `partial` and `failed` collectors as coverage gaps.

## Commands

```sh
auditex run --offline \
  --sample examples/sample_audit_bundle/sample_result.json \
  --tenant-name demo \
  --out outputs/offline

auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format json
auditex setup-guide google --collector-preset everything --format json
auditex google probe --collector-preset everything --top 1 --page-size 1
```

Use local Git-excluded authentication material where it is needed. Do not put
secrets or tokens into commands, prompts, logs, or handoff material.
