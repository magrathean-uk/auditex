---
name: delegated-auth
description: Use when starting an authorized Microsoft 365 audit without an app registration and assessing delegated coverage before an app-consent escalation.
---

# Delegated Authentication

Start with delegated `Global Reader` or an equivalent authorized role before
asking for app consent. If delegated visibility provides the required coverage,
do not request broader access.

## Preferred path

```sh
az login --tenant <tenant>
auditex guided-run --flow gr-audit --include-exchange
auditex run --tenant-name <label> --tenant-id <tenant> --use-azure-cli-token --auditor-profile global-reader --out outputs/live
```

## Record

- signed-in identity;
- visible role context;
- blocked collectors and their evidence;
- any additional delegated role or permission that would add coverage.

Do not disclose tokens or raw evidence. Keep the audit operation read-only and
run a probe before full collection when the workflow does not do so itself.
