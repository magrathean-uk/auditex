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

Tenant identity is mirrored in the manifest, summary, report summary, AI-context
run metadata and SQLite `run_meta`. `tenant_id_requested` preserves the operator's
input; `tenant_id` contains the canonical observed UUID for Microsoft 365.
`tenant_identity` records status, source artifact pointers and conflicts.
`verified` means the recorded organization/token tenant observations agree;
it does not authenticate a saved bundle or verify a token signature. Input
labels and aliases alone produce `unknown`; explicit synthetic fixtures retain
that status. Google customer identifiers use separate provider semantics.
Conflicting evidence or mirrored metadata invalidates a bundle. Comparisons,
explorers and drift gates reject conflicting identities and different established
tenant UUIDs, while allowing renamed labels for the same UUID. Legacy fallback
is explicit in `compare_context.identity_basis` and `legacy_fallback`.

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

New graph-derived paths are explicitly conditional hypotheses:
`classification` is `conditional_hypothesis`, `execution_verified` is `false`,
and `unmet_preconditions` records the initial-access, authentication-policy,
credential-possession or PIM activation evidence still needed. Legacy
`no_mfa` identifiers remain for compatibility; their registration-report basis
does not establish that sign-in bypasses MFA. Expired or not-yet-valid app
credentials do not create credential entry edges by themselves.
Disabled users and service principals retain their observed inventory links,
but are excluded as footholds and from traversable privilege paths. This models
configured account state; it does not establish outstanding session state.

`reports/report-pack.json` carries `attack_paths` and, for Microsoft 365 runs with directory data, `attack_graph`. Both are derived offline from `normalized/*.json`; no extra tenant call is made to build them.

Graph-derived paths come first and have `kind: "privilege_graph"`. Each path has `id`, `source`, `source_type`, `foothold` and `foothold_reasons` (`ordinary_user`, `guest`, `no_mfa`, `third_party_app`, `multi_tenant_app`, `expired_secret`, `long_lived_secret`), `target` (a tier-0 directory role or a tier-0 Microsoft Graph permission), `hops`, `hop_count`, `eligible`, `risk_score`, `severity`, `techniques`, `summary`, `breakpoints`, `foothold_count`, and `also_reachable_from`. Each hop has `from`, `to`, `edge`, `technique` (MITRE ATT&CK id), and `evidence_ref` with the same required fields as finding evidence references, pointing at the normalized record the hop came from. Edge types are `member_of`, `has_role`, `guest_with_role`, `owns`, `owns_group`, `authenticates_as`, `has_app_role`, `consented`, `can_reset`, and the entry edges `no_mfa`, `credential`, and `third_party`. An entry edge is an optional first hop that shows how the foothold is reached; `hop_count` and the depth bound (5) count only the privilege hops after it. `breakpoints` lists the hops whose single removal leaves the source with no route to any tier-0 target within the bound. At most 10 paths are kept, ordered by `risk_score`.

For compatibility, graph paths also carry `chain` (edge types), `stage_count`, and `findings` rows (`stage`, `title`, `severity`, `finding_id`, `technique`). High and critical paths also produce a finding (`attack_path.app_owner_to_tier0`, `attack_path.no_mfa_to_tier0`, or `attack_path.privilege_escalation`) whose `id` equals the path `finding_id` and whose `evidence_refs` are the hop references. When the graph has no path, `attack_paths` falls back to the keyword stage path `attack_path:primary`.

`attack_graph` summarises the graph: `node_count`, `edge_count`, `edge_counts`, `tier0_targets`, `tier0_principals`, `tier0_principal_labels`, `disabled_tier0_principals`, `footholds`, `foothold_counts`, `paths_found`, `path_count`, `max_depth`, `max_paths`, and `read_only`. `edge_counts` and `foothold_counts` are lists of `{edge|foothold, count}` rows so that names such as `credential` never become JSON keys.

## Normalized and indexed surfaces

`normalized/*.json` payloads may expose `records`. Record rows need a stable machine key via `key`, `id`, `name`, `display_name`, `collector`, or `surface`.

Paged Graph collection stores the collected rows in the raw section's
`chunk_files`, with an inline `value` sample capped at 20 rows. `item_count`
counts the collected rows; `sample_truncated` indicates that the inline sample
is smaller. Normalization reads all declared chunks beneath the run directory
without appending the inline sample. Findings, graph analysis, evidence indexing
and normalized comparisons therefore use all readable **collected** rows.
Missing, malformed, duplicate or unsafe chunks and count mismatches produce
`normalized/normalization_coverage.json` issues and `incomplete_evidence`
blockers; the run finalizes as partial. Symlink escapes and paths outside the run
are rejected. Successfully saved pages survive a later-page collection failure.

`normalized/snapshot.json` and the AI-safe summary expose
`normalization_complete`, `normalization_issue_count`,
`normalization_incomplete_sections` and `collection_limited_sections`.
Normalization completeness describes collected evidence, not the whole tenant;
`result_limit`, collection errors and fan-out limits still bound coverage.
`full_counts` uses the maximum reported per-source inventory count rather than
adding duplicate inventories; `full_counts_basis` is
`maximum_per_source_not_unique_union`. Normalized counts describe actual records.
The chunk reader streams, while the final normalized snapshot is memory-resident.

The optional `directory_relationships` collector emits
`directory_relationship_objects` and `directory_relationship_coverage`.
Relationships have stable parent/relation/object keys; failed owner/member
reads retain an unknown count rather than claiming zero. Graph evidence points
to the individual observed relationship. Its bounded inventories and link reads
are documented in the [API call catalog](api-call-catalog.md).

Probe capability records use an explicit `key` derived from the surface,
collector, probe mode, operation name, endpoint or command, and toolchain.
Repeated observations of the same operation receive an occurrence suffix.
Shared labels such as `organization` or `servicePrincipalOwners` therefore
remain distinct across collectors and target objects; changing a result's
status, count or duration does not change its operation key.
Graph probe rows also carry `observed_permissions` from the sanitized token
claims, so the probe's API inventory records write-capable scope risk even
though its operations are read-only.

`index/evidence.sqlite` is rebuilt during finalization. The required tables are:

- `run_meta`
- `section_stats`
- `normalized_records`

Report and compare code can use this database as the durable lookup surface instead of rewalking every JSON file.

## MCP contract surface

External assessment review is a separate local contract. Normalized imports
carry a source version, tenant identity, source SHA-256, original JSON pointers
and checks with `pass`, `fail`, `unknown`, `not_applicable` or `error` status.
They do not alter finalized run artifacts or become native findings.
`auditex_normalize_external_assessment` returns an import in memory;
`auditex_compare_external_assessments` compares explicit control identifiers
within one tenant and optionally includes a valid finalized Auditex run.
Both tools are read-only and make no tenant or inference calls. See
[external assessment comparison](../guides/external-assessments.md).

`auditex_summarize_run` returns the same contract status and evidence index path exposed by CLI output. `auditex_api_inventory` exposes the API call ledger, `auditex_permissions_ledger` exposes required and missing scopes, `auditex_proof_table` exposes finding-to-evidence rows, `auditex_enterprise_handoff` exposes the customer handoff index for review, and `auditex_verify_customer_pack` verifies generated customer pack integrity. `auditex_contract_schema_manifest` lists shipped schema files and the active contract version so MCP clients can detect drift before interpreting a bundle.
