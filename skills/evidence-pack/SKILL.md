---
name: evidence-pack
description: Use when reviewing or handing off an Auditex run and preparing a customer-safe evidence pack with integrity checks.
---

# Evidence Pack

## Review the run

Start with `run-manifest.json`, `summary.json`, `validation.json`,
`data-handling.json`, and `api-inventory.json`. Use `diagnostics.json` when
blockers exist. The output contract also requires `reports/report-pack.json`,
`index/evidence.sqlite`, and `ai_context.json` for a successful bundle.

Keep raw evidence local. Do not include secrets, tokens, OAuth caches, or raw
tenant evidence in summaries or transfer channels.

## Handoff

Create a customer pack only from an authorized completed run. Verify it before
handoff:

```sh
auditex report verify-pack <customer-pack-dir>
```

Use the handoff, API ledger, permission ledger, and proof table to cite actual
artifact paths. If coverage is partial or pack verification fails, say so
plainly and include the blocker evidence.
