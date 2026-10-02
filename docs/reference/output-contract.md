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

Microsoft 365 report packs can also carry `detection_coverage` (`signals[]` with `name`, `title`, `status` of `on`, `off`, or `unknown`, `reason`, `why_it_matters`, and an `evidence_ref` into `normalized/detection_signal_objects.json`, plus `score`, `counts`, `assessed_ratio`, and `limitations`) and the informational `public_footprint` (`domains[]` with discovery status, authentication type, and an `evidence_ref` into `normalized/public_footprint_objects.json`). `score` is computed over `on` and `off` signals only; `unknown` is never counted as `off`. Both sections survive the coverage-gap refresh of the report pack. New normalized sections: `detection_signal_objects`, `public_footprint_objects`, and `identity_protection_objects`.

Raw evidence remains local-only. `ai_safe/` artifacts are checked for sensitive key names and token-like values so redacted reasoning surfaces do not drift into raw credential or claim storage.

`data-handling.json` records whether the bundle is read-only, whether body/file content was read, whether write actions ran, provider-specific no-content assertions, and scope risk. Google Workspace audit bundles must assert no Gmail body reads and no Drive file content reads. When a provider requires write-capable OAuth scopes for read-only settings visibility, `scope_risk` and `write_capable_scopes` make that blast radius explicit.

`audit-plan.json` records the autopilot evidence gates, expected collectors, required scopes, and quality gate (`complete`, `partial`, or `unusable`). When optional artifact paths are present in the manifest, validation checks the referenced file and its core semantics.

`live-readiness.json` and `audit-plan.json` classify each blocker as `auth_scope`, `admin_role`, `license`, `service_absent`, `local_tool`, `tenant_policy`, `runtime`, or `unverified`. They now share the same per-collector evidence-gate rows so reviewer wording, blocker kind, and next-step guidance stay aligned across both artifacts. This distinction is required for enterprise handoff because a missing local module, an unlicensed tenant workload, and a missing OAuth scope need different customer actions.

`api-inventory.json` records the enterprise API call ledger: declared collectors, observed endpoint calls, required and missing permissions, status, item counts, read/write classification, data class, and no-content-read safety. Audit-plane bundles fail validation when this artifact reports tenant writes or body/file content reads. See `docs/reference/api-call-catalog.md` for the customer-facing review path.

`framework_mappings` uses canonical keys only: `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, `mcsb`, `google_workspace_baseline`, `nist_800_53`, `iso_27001`, `soc2`, `nis2`, `dora`, `mitre_attack`, and the deprecated `cis_m365_v3`. The validator still accepts `cis_m365_v3` for older bundles and operator overrides, but shipped mappings no longer emit it. Exporters treat those keys as stable taxonomy labels for SARIF, OSCAL, and the CSV `framework_mappings` column. `configs/framework-catalog.json` records the source version, date, URLs, and verified control ids for each benchmark key; see `docs/reference/framework-mappings.md`.

`reports/report-pack.json` carries `baseline_alignment`. For each of `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, and `mcsb` it lists the controls the shipped rules map to, with `status` (`fail`, `accepted_risk`, `pass`, or `not_assessed`), the mapped `rule_ids`, per-rule `rule_statuses`, and open `finding_ids`. A control passes only when every mapped rule's evidence collector completed and produced no finding. `baseline_alignment.secure_score` reconciles the latest Microsoft Secure Score snapshot with Auditex findings: `overall` (score, maximum, percentage) and one row per mapped control profile with Microsoft's score and maximum, `microsoft_state`, `auditex_state`, and `agreement` (`agrees`, `auditex_only`, `microsoft_only`, or `no_microsoft_data`). `normalized/security_score_control_profiles.json` holds the control profile ids, titles, and maximum scores used for that table.

### Attack paths

`reports/report-pack.json` carries `attack_paths` and, for Microsoft 365 runs with directory data, `attack_graph`. Both are derived offline from `normalized/*.json`; no extra tenant call is made to build them.

Graph-derived paths come first and have `kind: "privilege_graph"`. Each path has `id`, `source`, `source_type`, `foothold` and `foothold_reasons` (`ordinary_user`, `guest`, `no_mfa`, `third_party_app`, `multi_tenant_app`, `expired_secret`, `long_lived_secret`), `target` (a tier-0 directory role or a tier-0 Microsoft Graph permission), `hops`, `hop_count`, `eligible`, `risk_score`, `severity`, `techniques`, `summary`, `breakpoints`, `foothold_count`, and `also_reachable_from`. Each hop has `from`, `to`, `edge`, `technique` (MITRE ATT&CK id), and `evidence_ref` with the same required fields as finding evidence references, pointing at the normalized record the hop came from. Edge types are `member_of`, `has_role`, `guest_with_role`, `owns`, `owns_group`, `authenticates_as`, `has_app_role`, `consented`, `can_reset`, and the entry edges `no_mfa`, `credential`, and `third_party`. An entry edge is an optional first hop that shows how the foothold is reached; `hop_count` and the depth bound (5) count only the privilege hops after it. `breakpoints` lists the hops whose single removal leaves the source with no route to any tier-0 target within the bound. At most 10 paths are kept, ordered by `risk_score`.

For compatibility, graph paths also carry `chain` (edge types), `stage_count`, and `findings` rows (`stage`, `title`, `severity`, `finding_id`, `technique`). High and critical paths also produce a finding (`attack_path.app_owner_to_tier0`, `attack_path.no_mfa_to_tier0`, or `attack_path.privilege_escalation`) whose `id` equals the path `finding_id` and whose `evidence_refs` are the hop references. When the graph has no path, `attack_paths` falls back to the keyword stage path `attack_path:primary`.

`attack_graph` summarises the graph: `node_count`, `edge_count`, `edge_counts`, `tier0_targets`, `tier0_principals`, `tier0_principal_labels`, `disabled_tier0_principals`, `footholds`, `foothold_counts`, `paths_found`, `path_count`, `max_depth`, `max_paths`, and `read_only`. `edge_counts` and `foothold_counts` are lists of `{edge|foothold, count}` rows so that names such as `credential` never become JSON keys.

## Normalized and indexed surfaces

`normalized/*.json` payloads may expose `records`. Record rows need a stable machine key via `key`, `id`, `name`, `display_name`, `collector`, or `surface`.

`index/evidence.sqlite` is rebuilt during finalization. The required tables are:

- `run_meta`
- `section_stats`
- `normalized_records`

Report and compare code can use this database as the durable lookup surface instead of rewalking every JSON file.

## MCP contract surface

`auditex_summarize_run` returns the same contract status and evidence index path exposed by CLI output. `auditex_api_inventory` exposes the API call ledger, `auditex_permissions_ledger` exposes required and missing scopes, `auditex_proof_table` exposes finding-to-evidence rows, `auditex_enterprise_handoff` exposes the customer handoff index for review, and `auditex_verify_customer_pack` verifies generated customer pack integrity. `auditex_contract_schema_manifest` lists shipped schema files and the active contract version so MCP clients can detect drift before interpreting a bundle.
