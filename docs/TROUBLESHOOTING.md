# Auditex Troubleshooting Guide

This guide maps common failures to operator actions. Do not hide blockers; rerun probe after each access change.

## Local Runtime

### `auditex: command not found`

Activate the environment and install the package.

```bash
source .venv/bin/activate
python -m pip install -e .
```

### Google libraries missing

Install the Google extra.

```bash
python -m pip install -e '.[google]'
auditex google doctor --json
```

### MCP libraries missing

Install the MCP extra.

```bash
python -m pip install -e '.[mcp]'
auditex-mcp --help
```

## Microsoft 365

### Azure CLI token unavailable

Run:

```bash
az login --allow-no-subscriptions --tenant <tenant-id-or-domain>
auditex probe live --tenant-name CLIENT --tenant-id <tenant-id-or-domain> --mode delegated --use-azure-cli-token
```

If the token still fails, verify the account is in the tenant and has the expected reader role.

### `Authorization_RequestDenied`

The signed-in account or app lacks the required role or Graph permission. Review:

- `live-readiness.json`,
- `audit-plan.json`,
- `auditex report permissions <run-dir> --format md`.

Add the smallest read permission or role needed, then rerun probe.

### Empty Defender, Intune, or risk data

This often means the tenant lacks the product, license, or data retention window. Treat it as a documented limitation unless the customer confirms the service exists and should have data.

### Exchange coverage missing

Install optional adapter tooling only when Exchange posture is in scope.

```bash
auditex setup --exchange
auditex setup --pwsh
```

Then rerun probe and check adapter readiness.

## Google Workspace

### `unauthorized_client`

Likely domain-wide delegation is not correctly configured.

Check:

- service account OAuth client ID was added in Admin Console,
- the delegated subject is a Workspace admin,
- the exact scopes were pasted comma-separated,
- the service-account file matches that client ID,
- enough time passed after saving Admin Console changes.

Then rerun:

```bash
auditex google probe --auth domain-delegation --service-account-key /path/key.json --subject admin@example.com --domain example.com --customer-id C123 --top 1 --page-size 1
```

### `invalid_scope`

The OAuth client or DWD entry does not allow one or more requested scopes. Compare the requested preset against the Admin Console scope list. Add missing scopes, save, wait, then rerun `doctor` and `probe`.

### Gmail settings blocked

Confirm these scopes are present:

```text
https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/gmail.settings.sharing,https://www.googleapis.com/auth/admin.directory.user.readonly
```

Auditex reads settings only. It does not read Gmail body content.

### Drive metadata blocked

Confirm the Drive collector is selected and scopes are present:

```text
https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/drive.readonly
```

Auditex does not read Drive file content. Broad Drive scope risk is declared in the data-handling and API inventory artifacts.

### Alert Center blocked

Confirm:

```text
https://www.googleapis.com/auth/apps.alerts
```

Some Workspace editions or admin roles may still limit alert visibility.

## Reports And Contract

### `validation.json` is invalid

Open `validation.json` and fix the specific issue. Common causes:

- missing required artifact,
- malformed finding evidence reference,
- missing normalized artifact,
- API inventory reports a write or content read,
- AI-safe artifact contains sensitive auth material.

Do not hand-edit generated output. Fix the collector, normalizer, or report generation path, then rerun.

### Finding has no proof row

The finding is unsupported for customer handoff. Add or fix `evidence_refs` in the finding source and rerun finalization.

### Customer pack verification fails

Do not send the pack. Check `issues` from:

```bash
auditex report verify-pack customer-pack
```

Common causes:

- file missing,
- file edited after pack creation,
- checksum mismatch,
- bad manifest,
- checksum path outside pack.

Regenerate the pack from the original run directory.

## Release Failures

### Tests pass locally but contract smoke fails

Run the offline sample manually and inspect `validation.json`.

```bash
auditex run --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name ci --run-name contract --out outputs/ci-contract
auditex run --offline --sample examples/sample_audit_bundle/known_bad_result.json --tenant-name ci --run-name known-bad --out outputs/ci-known-bad
```

### Auth-material scan finds a match

Do not ship. Remove the material from source or generated fixtures, rotate if exposed, and rerun the scan.

### Customer pack fails with `stale_accepted_risk`

The bundle includes an accepted-risk finding whose waiver expiry date has already passed.

- Refresh the waiver decision and rerun the audit, or
- remove the stale waiver so the finding is open again and review it normally.

### Docs mention a command that no longer exists

Update the docs and run command help checks:

```bash
auditex --help
auditex google --help
auditex report --help
auditex-mcp --help || true
```
