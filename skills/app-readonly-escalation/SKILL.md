---
name: app-readonly-escalation
description: Use when a delegated Microsoft 365 audit is blocked and a customer-local app registration may provide a documented second pass.
---

# App-Readonly Escalation

Use app consent only after the delegated pass identifies blocked collectors.

## Requirements

- Use a customer-local app registration.
- Request only the permissions justified by the blocked collectors.
- Keep the Auditex operation read-only and do not use the app to mutate a
  production tenant.
- Record the expected permission blast radius. A provider permission name can
  be write-capable even when the intended Auditex calls are reads.
- Verify the resulting `api-inventory.json` and `data-handling.json` before
  treating the run as read-only.

## Handoff

State what delegated mode collected, what was blocked, the exact additional
permissions that would add coverage, and why the intended collector calls are
read-only for that tenant. Do not share credentials or raw tenant evidence.
