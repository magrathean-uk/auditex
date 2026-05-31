# Auditex Output Contract

Contract version: `2026-04-21`.

Auditex treats completed run directories as product contracts, not incidental implementation output. Public `run` and `probe` flows must finish through the shared bundle finalizer so the same required artifacts and validation semantics are applied.

## Required root artifacts

Every successful bundle must contain:

- `run-manifest.json`
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite`
- `ai_context.json`
- `validation.json`

`validation.json` is built last and records the contract version, required artifact list, issue count, and issue details. The final `run-manifest.json` mirrors this with `schema_contract_version`, `contract_status`, and `contract_issue_count`.

Current bundles may also stamp `provider_adapter_version` and `api_inventory_recorder_version`. These are internal conformance markers for the shared provider finalization path, not customer-facing contract breaks.

Known-bad or seeded offline bundles may also stamp optional `fixture_provenance` metadata in `run-manifest.json` and `reports/report-pack.json`. This is replay metadata for regression fixtures, not live tenant evidence.

New bundles also include `data-handling.json`, `audit-plan.json`, and `api-inventory.json`; validation keeps the required artifact list stable so older bundles remain readable.

## Evidence discipline

Findings must include `evidence_refs`. Each reference must identify at least `artifact_path`, `artifact_kind`, `collector`, and `record_key`. Bundle validation checks duplicate finding IDs, missing references, malformed references, and references pointing at missing artifacts.

`reports/report-pack.json` includes `proof_table` for board, CLI, and MCP review. New proof rows flatten every finding evidence reference into `finding_id`, `rule_id`, `proof_status`, `collector`, `artifact_path`, `artifact_kind`, `record_key`, and optional JSON pointer or endpoint fields. The same pack now also carries `reviewer_index` with `start_here`, `prove_this`, and `known_limits` rows so customer reviewers can move from posture to proof faster. The validator accepts older per-finding proof summaries, and validates the stricter row shape when the new fields are present. Operators can render the same rows with `auditex report proof-table <run-dir> --format md`. Enterprise handoff starts with `auditex report customer-pack <run-dir> --output-dir <dir>`, `auditex report verify-pack <dir>`, or `auditex report handoff <run-dir> --format md`. The pack writes a README, handoff, full report, API ledger, permission ledger, proof table, JSON copies, selected customer-safe source artifacts, `checksums.sha256`, and generated-file/source-artifact hashes. `pack-manifest.json` source now also carries `validation_summary` and `reviewer_summary`; `verify-pack` checks those against `handoff.json` so customer start-point truth cannot drift. The handoff, API call, permission, and proof-table commands all accept `--output <path>` for persisted customer packs.

Raw evidence remains local-only. `ai_safe/` artifacts are checked for sensitive key names and token-like values so redacted reasoning surfaces do not drift into raw credential or claim storage.

`data-handling.json` records whether the bundle is read-only, whether body/file content was read, whether write actions ran, provider-specific no-content assertions, and scope risk. Google Workspace audit bundles must assert no Gmail body reads and no Drive file content reads. When a provider requires write-capable OAuth scopes for read-only settings visibility, `scope_risk` and `write_capable_scopes` make that blast radius explicit.

`audit-plan.json` records the autopilot evidence gates, expected collectors, required scopes, and quality gate (`complete`, `partial`, or `unusable`). When optional artifact paths are present in the manifest, validation checks the referenced file and its core semantics.

`live-readiness.json` and `audit-plan.json` classify each blocker as `auth_scope`, `admin_role`, `license`, `service_absent`, `local_tool`, `tenant_policy`, `runtime`, or `unverified`. They now share the same per-collector evidence-gate rows so reviewer wording, blocker kind, and next-step guidance stay aligned across both artifacts. This distinction is required for enterprise handoff because a missing local module, an unlicensed tenant workload, and a missing OAuth scope need different customer actions.

`api-inventory.json` records the enterprise API call ledger: declared collectors, observed endpoint calls, required and missing permissions, status, item counts, read/write classification, data class, and no-content-read safety. Audit-plane bundles fail validation when this artifact reports tenant writes or body/file content reads. See `docs/API_CALL_CATALOG.md` for the customer-facing review path.

`framework_mappings` uses canonical keys only: `cis_m365_v3`, `google_workspace_baseline`, `nist_800_53`, `iso_27001`, `soc2`, `nis2`, `dora`, and `mitre_attack`. Exporters treat those keys as stable taxonomy labels for SARIF and OSCAL output.

## Normalized and indexed surfaces

`normalized/*.json` payloads may expose `records`. Record rows need a stable machine key via `key`, `id`, `name`, `display_name`, `collector`, or `surface`.

`index/evidence.sqlite` is rebuilt during finalization. The required tables are:

- `run_meta`
- `section_stats`
- `normalized_records`

Report and compare code can use this database as the durable lookup surface instead of rewalking every JSON file.

## MCP contract surface

`auditex_summarize_run` returns the same contract status and evidence index path exposed by CLI output. `auditex_api_inventory` exposes the API call ledger, `auditex_permissions_ledger` exposes required and missing scopes, `auditex_proof_table` exposes finding-to-evidence rows, `auditex_enterprise_handoff` exposes the customer handoff index for review, and `auditex_verify_customer_pack` verifies generated customer pack integrity. `auditex_contract_schema_manifest` lists shipped schema files and the active contract version so MCP clients can detect drift before interpreting a bundle.
