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
3. For an authorized live Microsoft 365 pass, the tenant administrator sets up
   the reader app once (`docs/guides/reader-app-permissions.md`); the run uses
   its client ID, certificate thumbprint and key file.
4. Run a probe before full collection.
5. Record the reader app's client ID, the tenant and the evidence paths.
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
auditex probe live --tenant-name demo --tenant-id <tenant> --mode app \
  --client-id <app-id> --certificate-path <key file> --certificate-thumbprint <sha1>
auditex google probe --collector-preset everything --top 1 --page-size 1
```

Keep the certificate key and its password file local, owner-only and
Git-excluded. Do not put secrets or tokens into commands, prompts, logs, or
handoff material; a key password goes in a file or an environment variable,
never on the command line.
