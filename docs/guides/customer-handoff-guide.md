# Auditex Customer Handoff Guide

Use this guide when preparing audit evidence for an enterprise customer, legal reviewer, or internal assurance review.

## Handoff Rule

Create each pack in a fresh directory. Review its contents and send it through the customer's approved evidence channel only after integrity verification. The verifier does not prove that every file is safe to disclose or that the audit is complete. Do not send local auth material or unredacted credential material.

A pack vouches for the run it was built from, so `customer-pack` first checks that the run directory still matches the hashes recorded when the run was finalized (`bundle-hashes.json`) and that it validates as it stands now, whatever its `validation.json` says. If a file changed or is missing, or the bundle no longer validates, it refuses to build the pack (see "If The Run Directory Changed").

## Create The Pack

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

The verifier must return:

```json
{
  "valid": true,
  "issue_count": 0
}
```

If verification fails, recreate the pack from the run directory. Do not edit generated pack files by hand.

### If The Run Directory Changed

`auditex report customer-pack` exits with status 2 and writes nothing when the run directory no longer matches its hash manifest, or does not validate when checked again:

```text
auditex report customer-pack: refusing to create a customer pack from <run-dir>: 1 artifact(s) changed and 0 are missing since the run was finalized.
auditex report customer-pack: refusing to create a customer pack from <run-dir>: The bundle does not validate as it stands (2 error(s)).
```

Run `auditex report handoff <run-dir> --format json`. `handoff_status` is `unusable` and `status_reasons` says why:

- `bundle_integrity_mismatch`: `integrity.modified_paths` and `integrity.missing_paths` name the files that changed or are gone.
- `bundle_integrity_invalid`: `bundle-hashes.json` is unreadable, or it was deleted (the run manifest still lists it, so deleting it does not make the run look unchecked).
- `recomputed_validation_failed`: `contract.recomputed` shows the validation as it stands now, and `issue_codes` which checks failed. A bundle can pass the hash check and still fail this one if someone rewrote the hash manifest to match an edit.
- `legacy_unresolved_refs`: every failure is a `legacy_unresolved_ref`, an evidence reference written by a version before references had to resolve. That is an old bundle, not a sign of editing; the pack is still refused, and the explorer says "Legacy evidence references do not resolve". Rerun the audit with the current version.

For a changed run, restore the files from the original run, or rerun the audit and hand off the new run. Do not regenerate `bundle-hashes.json` to make the check pass: that discards the one record of what the run produced. `handoff` and `report explorer` still work on a changed run and say so (a `bundle_integrity` or `contract_validation` limitation, a banner on the explorer page), so you can see what changed before deciding.

A run finalized before the hash manifest existed has `integrity.status: absent`. The pack is still built if the run validates, and records that the run could not be checked.

## Pack Contents

The pack includes:

- `README.md` - reviewer start point.
- `handoff.md` and `handoff.json` - audit status, contract status (including the validation recomputed when the handoff was built), bundle integrity, safety, quality gate, blockers, and review commands.
- Accepted-risk review is part of handoff. Expired accepted risks are treated as stale and should block sharing until re-approved or removed.
- `report.md` - report for customer review.
- `reports/report-pack.json` inside `source-artifacts/` now carries both raw `citations` and typed `citation_summary`. Pack verify checks that those stay aligned with proof rows.
- `reports/report-pack.json` also carries `reviewer_index` with `start_here`, `prove_this`, and `known_limits` so customer reviewers can jump from posture to proof fast.
- Generated helper JSON files like `handoff.json`, `api-calls.json`, `permissions.json`, and `proof-table.json` also keep `citations` and `citation_summary`. Pack verify checks those too.
- `api-calls.md` and `api-calls.json` - API call ledger: the declared calls and, for runs with a transport ledger, every Graph request and command the audit log recorded and any call outside the declared set. For Google Workspace it says the list is declared, not observed.
- `permissions.md` and `permissions.json` - required, observed, and missing permission ledger.
- `proof-table.md` and `proof-table.json` - finding-to-evidence proof rows.
- `source-artifacts/` - selected customer-safe source artifacts copied from the run, including `bundle-hashes.json`, the SHA-256 of every artifact of the run as it was finalized. `verify-pack` checks every copied source artifact against it and its own SHA-256 against `integrity.manifest_sha256`.
- `checksums.sha256` - SHA-256 list of the pack's files. It is stored inside the pack and is not signed, so `verify-pack` detects corruption and edits that were not also re-hashed; it does not authenticate who produced the pack. When origin matters, send the SHA-256 of this file and the SHA-256 of `bundle-hashes.json` (the handoff's `integrity.manifest_sha256`) to the customer through a separate channel; `verify-pack` prints both as `digests` and takes the values received back with `--expect-checksums-sha256` and `--expect-manifest-sha256`.
- `pack-manifest.json` - pack manifest with generated and source artifact hashes, plus `validation_summary`, `reviewer_summary` and `integrity` copied from handoff truth.

## Reviewer Order

1. Read `handoff.md`.
2. Check `source-artifacts/validation.json` and contract status, and that the README and `handoff.json` show bundle integrity `verified`.
3. Read `source-artifacts/data-handling.json` to confirm read-only and no-content-read assertions.
4. Read `report.md`, especially the reviewer index and executive summary.
5. Read `proof-table.md` for evidence behind each finding.
6. Read `api-calls.md`: the declared calls, then the calls the audit log recorded (and any outside the declared set). Google Workspace runs are declared, not observed.
7. Read `permissions.md` to see missing scopes, roles, or licenses.
8. Use `checksums.sha256` or `auditex report verify-pack` to verify integrity, and check that `verify-pack` reports no `unexpected_file`.

## Explaining Partial Runs

A partial run is acceptable only when limitations are explicit. The pack must show:

- which collectors ran,
- which collectors were blocked,
- why each blocked surface failed,
- whether the blocker is permission, role, license, service absence, tenant policy, local tool, runtime, or unverified,
- which findings are proven and which claims are unsupported.

Do not remove blockers from the pack. They are part of the audit result.

## Explaining Read-Only Behavior

Point reviewers to:

- `data-handling.json`,
- `api-inventory.json`,
- `audit-plan.json`,
- `validation.json`,
- `api-calls.md`.

These artifacts show whether Auditex attempted writes or body/file content reads. Audit-plane validation fails if recorded tenant writes or content reads are present.

## Evidence Proof Rules

Every finding should have:

- finding ID,
- rule ID,
- severity and status,
- affected object,
- evidence reference,
- artifact path,
- artifact kind,
- collector,
- record key,
- optional JSON pointer or endpoint.

If a finding has no proof row, treat it as unsupported until fixed.

A proof row is `supported` only when its evidence reference resolved: the artifact is a file inside the run, and the record (or JSON pointer) it names is in that file. A row that did not resolve is `unsupported` and carries `unresolved_reason`. Each row also carries `content_hash` (the SHA-256 of the artifact it cites, which matches the entry in `bundle-hashes.json`) and `collected_at`, so a reviewer can open the cited record and confirm they are looking at the file the finding was built from. A finding's `confidence` is `high` only when every one of its references resolved; treat `medium` and `low` as needing a human to find the evidence. `report_qa.unsupported_claims` lists the findings with no resolved reference; none should remain before handoff.

## Customer Questions

### Did Auditex read emails or files?

No audit path should read Gmail bodies, Drive file content, Exchange mailbox bodies, SharePoint file content, or OneDrive file content. Confirm through `data-handling.json` and `api-inventory.json`.

### Did Auditex change the tenant?

No audit, probe, report, export, MCP audit, or pack verification path should mutate a production tenant. Confirm through `api-inventory.json` and validation.

### Why are broad scopes listed?

Some provider APIs expose read settings behind broad OAuth scopes. Auditex records this as scope risk and still uses read calls only.

### Can the customer reproduce the report?

Yes. Keep the run directory and pack together. Use `auditex report render`, `auditex report api-calls`, `auditex report permissions`, and `auditex report proof-table` against the run directory.

## Handoff Checklist

- Inspect the actual run's `validation.json` and contract status. An unrelated offline contract smoke does not validate this customer run.
- Generate the customer pack.
- Run `auditex report verify-pack`. This now also checks that the copied `report-pack.json` still carries citation rows.
- Confirm `pack-manifest.json` and `handoff.json` agree on validation summary and reviewer summary.
- If pack verify reports `stale_accepted_risk`, stop handoff and refresh the acceptance decision before sharing.
- Confirm `data-handling.json` says read-only and no content reads.
- Confirm the actual run's `validation.json` is valid and coverage limitations are explained.
- Confirm no local auth files are inside the pack.
- Confirm customer-safe source artifacts are present.
- Confirm every high or critical finding has proof-table evidence, with every row `supported`.
- Confirm `handoff.json` shows `handoff_status` other than `unusable`, `integrity.status` `verified` and `contract.recomputed.valid` true with `matches_validation_json` true. A pack cannot be built from a run that no longer matches its hash manifest or no longer validates.
- Send through the approved evidence channel.
