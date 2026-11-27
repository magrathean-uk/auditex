# Auditex Troubleshooting Guide

This guide maps common failures to operator actions. Do not hide blockers; rerun probe after each access change.

## Local Runtime

Installing, upgrading and removing Auditex, with their failures, are in the [install guide](install-guide.md#troubleshooting).

### `auditex: command not found`

For a pipx install, put pipx's command folder on your `PATH`, then open a new terminal:

```bash
pipx ensurepath
pipx list
```

For a source checkout, activate the environment and install the package:

```bash
source .venv/bin/activate
python -m pip install -e .
```

### Google libraries missing

Install the Google extra, keeping any other extras you use inside the brackets (`auditex google doctor --json`
prints the exact command for your install in `install_hint`):

```bash
pipx install --force "auditex[google]"         # pipx install
python -m pip install -e '.[google]'           # source checkout
auditex google doctor --json
```

### MCP libraries missing

Install the MCP extra:

```bash
pipx install --force "auditex[mcp]"            # pipx install
python -m pip install -e '.[mcp]'              # source checkout
auditex-mcp --help
```

## Microsoft 365

### Certificate refused or token not acquired

Auditex stops before any request, with a fixed message naming the cause. Check, in order:

- the key file is a PEM or PFX owned by the operator, mode `600`, not a symbolic link and under 64 KiB,
- an encrypted key has its password in `--certificate-password-file` (owner-only) or in the environment variable named by `--certificate-password-env`,
- `--certificate-thumbprint` is the SHA-1 thumbprint the Microsoft Entra admin centre shows for the public certificate uploaded to the reader app, and the certificate has not expired,
- `--client-id` and `--tenant-id` are the reader app's Application (client) ID and Directory (tenant) ID.

Every step the tenant administrator has to take is in [Reader app permissions](reader-app-permissions.md).

### `Authorization_RequestDenied`

The reader app lacks the required role or Graph permission. Review:

- `live-readiness.json`,
- `audit-plan.json`,
- `auditex report permissions <run-dir> --format md`.

Add the smallest read permission or role needed, then rerun probe.

### Empty Defender, Intune, or risk data

Check collector status, permissions, service availability, and the data retention window. Empty results alone do not prove the service is absent or the tenant has no findings. Record the supported blocker reason and confirm expected coverage with the customer.

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
https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/admin.directory.user.readonly
```

Auditex reads settings only. It does not read Gmail body content.

### Drive metadata blocked

Confirm the Drive collector is selected and scopes are present:

```text
https://www.googleapis.com/auth/drive.metadata.readonly,https://www.googleapis.com/auth/drive.readonly
```

`https://www.googleapis.com/auth/admin.directory.domain.readonly` is optional for Drive: without it every file stays in scope and its sharing is read one by one. Declining it in an OAuth consent for a Drive-only run does not fail the sign-in, and the saved token is reused as it is; to add it later, delete the token cache and sign in again.

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
- evidence reference that does not resolve (`unresolved_evidence_ref`, `broken_evidence_ref`, `evidence_ref_hash_mismatch`),
- missing normalized artifact,
- API inventory reports a write or content read,
- AI-safe artifact contains sensitive auth material.

Do not hand-edit generated output. Fix the collector, normalizer, or report generation path, then rerun.

### Finding has no proof row

The finding is unsupported for customer handoff. Add or fix `evidence_refs` in the finding source and rerun finalization.

### Evidence reference does not resolve

`validation.json` names the finding (`details.finding_id`), the reference and the reason. `record_not_found` and `json_pointer_not_found` mean the artifact exists but the record is not in it: the finding builder cites a key that the normalized artifact does not contain, which is a bug in the builder. `artifact_missing` means the file is gone; `artifact_outside_run_dir` means the path leaves the run directory. `evidence_ref_hash_mismatch` means the artifact changed after the finding was sealed (a proof row's `content_hash` is checked too). `legacy_unresolved_ref` is the same failure as `unresolved_evidence_ref` in a bundle finalized under a contract version earlier than `2026-10-22` (the fixed version from which references must resolve, not the current one): the old builders cited records that were not there, and the bundle was not edited. A finding whose references do not resolve shows `unsupported` proof rows and lower `confidence`. Fix the builder and rerun; do not edit the bundle.

### Customer pack refused: the run changed since it was finalized

`auditex report customer-pack` exits with status 2 when files in the run directory no longer match `bundle-hashes.json` (or the file was deleted, or a SQLite sidecar was planted beside `index/evidence.sqlite`), or when the bundle no longer validates. `auditex report handoff <run-dir> --format json` shows `handoff_status: unusable` with `status_reasons`, and lists the files under `integrity.modified_paths` and `integrity.missing_paths`. Restore the original files or rerun the audit; see the [customer handoff guide](customer-handoff-guide.md).

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
auditex-mcp --help
```
