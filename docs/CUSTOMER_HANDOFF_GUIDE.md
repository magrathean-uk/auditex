# Auditex Customer Handoff Guide

Use this guide when preparing audit evidence for an enterprise customer, legal reviewer, or internal assurance review.

## Handoff Rule

Send the verified customer pack through the customer's approved evidence channel. Do not send local auth material or unredacted credential material.

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

## Pack Contents

The pack includes:

- `README.md` - reviewer start point.
- `handoff.md` and `handoff.json` - audit status, contract status, safety, quality gate, blockers, and review commands.
- `report.md` - client-ready report.
- `api-calls.md` and `api-calls.json` - API call ledger.
- `permissions.md` and `permissions.json` - required, observed, and missing permission ledger.
- `proof-table.md` and `proof-table.json` - finding-to-evidence proof rows.
- `source-artifacts/` - selected customer-safe source artifacts copied from the run.
- `checksums.sha256` - file integrity hash list.
- `pack-manifest.json` - pack manifest with generated and source artifact hashes.

## Reviewer Order

1. Read `handoff.md`.
2. Check `validation.json` and contract status.
3. Read `data-handling.json` to confirm read-only and no-content-read assertions.
4. Read `report.md` for executive and technical findings.
5. Read `proof-table.md` for evidence behind each finding.
6. Read `api-calls.md` to see exactly which APIs were attempted.
7. Read `permissions.md` to see missing scopes, roles, or licenses.
8. Use `checksums.sha256` or `auditex report verify-pack` to verify integrity.

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

- Run contract validation or `make contract-smoke` for release samples.
- Generate the customer pack.
- Run `auditex report verify-pack`.
- Confirm `data-handling.json` says read-only and no content reads.
- Confirm `validation.json` is valid or limitations are explained.
- Confirm no local auth files are inside the pack.
- Confirm customer-safe source artifacts are present.
- Confirm every high or critical finding has proof-table evidence.
- Send through the approved evidence channel.
