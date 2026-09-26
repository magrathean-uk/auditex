# Auditex Operator Prompt

Use the Auditex product surface in this folder for an authorized tenant audit.
Keep the public audit plane read-only. Do not use tenant-bootstrap actions that
create or change tenant objects as part of an Auditex audit.

Start with an offline validation run:

```sh
auditex run --offline \
  --sample examples/sample_audit_bundle/sample_result.json \
  --tenant-name <label> \
  --out outputs/offline
```

Before requesting tenant access, generate the provider setup guidance:

```sh
auditex setup-guide m365 --collector-preset full --format json
auditex setup-guide google --collector-preset everything --format json
```

For an authorized live engagement:

1. Use a local, Git-excluded authentication method. Do not place secrets or
   access tokens in prompts, command lines, logs, or handoff text.
2. Run a probe before full collection.
3. Record the signed-in identity and visible directory roles in the run
   evidence.
4. Run collection only after the probe and report blocked collectors as
   coverage gaps.
5. Review `summary.json`, `run-manifest.json`, `data-handling.json`,
   `api-inventory.json`, and `diagnostics.json` when present.
6. Verify any customer pack before handoff with
   `auditex report verify-pack <customer-pack-dir>`.

Do not read Gmail or Exchange message bodies, or Drive, SharePoint, or OneDrive
file content. Do not make production-tenant changes. Preserve evidence paths in
the summary, label partial or failed collection plainly, and never print raw
credentials or tenant evidence.
