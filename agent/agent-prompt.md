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

For an authorized live engagement, Microsoft 365 is audited one way: the
reader app with a certificate. The tenant administrator grants it once from
`docs/guides/reader-app-permissions.md`.

1. Keep the certificate's private key in an owner-only file on the audit
   machine. Never place the key, its password or any token in prompts, logs or
   handoff text; a key password comes only from `--certificate-password-env`
   or `--certificate-password-file`.
2. Run a probe before full collection:

   ```sh
   auditex probe live --tenant-name <label> --tenant-id <tenant> \
     --client-id <app-id> --certificate-path <private-key-file> \
     --certificate-thumbprint <sha1-thumbprint>
   ```

3. Run collection only after the probe and report blocked collectors as
   coverage gaps:

   ```sh
   auditex run --tenant-name <label> --tenant-id <tenant> \
     --client-id <app-id> --certificate-path <private-key-file> \
     --certificate-thumbprint <sha1-thumbprint> --auditor-profile global-reader
   ```

   The guided form asks for the same values: `auditex guided-run` (one flow,
   also `auditex guided-run --flow app-audit`).
4. Record the reader app's client ID and its Global Reader role in the run
   evidence.
5. Review `summary.json`, `run-manifest.json`, `data-handling.json`,
   `api-inventory.json`, and `diagnostics.json` when present.
6. Verify any customer pack before handoff with
   `auditex report verify-pack <customer-pack-dir>`.

Do not read Gmail or Exchange message bodies, or Drive, SharePoint, or OneDrive
file content. Do not make production-tenant changes. Preserve evidence paths in
the summary, label partial or failed collection plainly, and never print raw
credentials or tenant evidence.
