---
name: app-readonly-escalation
description: Use when a Microsoft 365 reader-app audit or probe reports a blocked collector and the tenant administrator may add a documented permission, role or setting.
---

# App-Readonly Escalation

Auditex audits Microsoft 365 only as the reader app, with a certificate. Use this when a probe or run names a blocked collector. The full grant is in `docs/guides/reader-app-permissions.md`; do not restate it, point to it.

## Requirements

- Use the customer's own reader app registration.
- Request only the permission, role or setting that the blocked collector's
  probe result justifies, and check it against the reader app guide first.
- Keep the Auditex operation read-only and do not use the app to mutate a
  production tenant.
- Record the expected permission blast radius. A provider permission name can
  be write-capable even when the intended Auditex calls are reads.
- Verify the resulting `api-inventory.json` and `data-handling.json` before
  treating the run as read-only.

## Handoff

State what the reader app collected, what was blocked, the exact additional
permissions that would add coverage, and why the intended collector calls are
read-only for that tenant. Do not share credentials or raw tenant evidence.
