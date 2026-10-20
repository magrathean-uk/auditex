# Auditex Output Contract

Contract version: `2026-10-20`. This version records every list that was cut short as a coverage gap (see "Collection limits and coverage gaps") and adds the `truncated_list_reported_ok` and `collection_gap_not_recorded` validation codes. Bundles written under `2026-04-21` stay valid: a coverage row is checked only when it carries a `truncation_reason`, and older rows that flag `collection_truncated` on an `ok` row carry none.

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

Microsoft 365 runs that include the `conditional_access` or `consent_policy` collector also write `normalized/identity_control_verdicts.json`, one record per tenant and control, keyed `identity_control_verdict:<control>`. `control` is `effective_mfa`, `legacy_authentication_block` or `user_consent` (the last only when `consent_policy` ran). `verdict` is `enforced`, `not_enforced` or `unknown` for `effective_mfa`; `blocked`, `not_blocked` or `unknown` for `legacy_authentication_block`; `restricted`, `unrestricted` or `unknown` for `user_consent`. A negative verdict needs a complete read: a policy list that was blocked, truncated or never collected gives `unknown`, with the cause in `reasons` and the endpoint states in `policy_collection`, `security_defaults` and `authorization_policy`. `basis` lists what establishes a positive verdict (`security_defaults`, `conditional_access_policy`). For `effective_mfa`, `qualifying_policies` are the enabled policies that require MFA for all users on all cloud apps, `excluded_principals` are the principals excluded from every qualifying policy (`type`, `id`, resolved `display_name`), `non_qualifying_mfa_policies`, `report_only_mfa_policies` and `unverified_policies` carry each near-miss policy with its `reasons`, and `registration_context` repeats the registration counts as context only: registration never produces `enforced`. Findings from these verdicts cite the verdict record and the Conditional Access policy records it names. `normalized/conditional_access_graph.json` policy records gain `targeting`: the raw include and exclude lists for users, groups, roles and guests, applications, `client_app_types`, platforms, locations, risk levels, the device filter (`device_filter_mode` and `device_filter_rule`) and the grant (`operator`, `built_in_controls`, `authentication_strength`). A policy that excludes platforms, applications or devices (exclude-mode filter) never qualifies as enforcing MFA or blocking legacy authentication; the near-miss `reasons` are `excludes_platforms`, `excludes_applications` and `device_filter_excludes_devices`, and the policy summary records `excluded_platforms`, `excluded_applications` and `device_filter`. `normalized/consent_policy_objects.json` authorization policy records gain `permission_grant_policies_assigned`, `allowed_to_create_apps` and `guest_user_role_id`. New rules: `ca.mfa_not_enforced`, `ca.legacy_auth_not_blocked`, `consent_policy.user_consent_unrestricted` and `identity.privileged_mfa_not_registered`, plus the diagnostic `ca.enforcement_unverified` and `consent_policy.user_consent_unverified`, which an `unknown` verdict raises instead.

Raw evidence remains local-only. `ai_safe/` artifacts are checked for sensitive key names and token-like values so redacted reasoning surfaces do not drift into raw credential or claim storage.

`data-handling.json` records whether the bundle is read-only, whether body/file content was read, whether write actions ran, provider-specific no-content assertions, and scope risk. Google Workspace audit bundles must assert no Gmail body reads and no Drive file content reads. When a provider requires write-capable OAuth scopes for read-only settings visibility, `scope_risk` and `write_capable_scopes` make that blast radius explicit.

`audit-plan.json` records the autopilot evidence gates, expected collectors, required scopes, and quality gate (`complete`, `partial`, or `unusable`). When optional artifact paths are present in the manifest, validation checks the referenced file and its core semantics.

`live-readiness.json` and `audit-plan.json` classify each blocker as `auth_scope`, `admin_role`, `license`, `service_absent`, `local_tool`, `tenant_policy`, `runtime`, or `unverified`. They now share the same per-collector evidence-gate rows so reviewer wording, blocker kind, and next-step guidance stay aligned across both artifacts. This distinction is required for enterprise handoff because a missing local module, an unlicensed tenant workload, and a missing OAuth scope need different customer actions.

`api-inventory.json` records the enterprise API call ledger: declared collectors, observed endpoint calls, required and missing permissions, status, item counts, read/write classification, data class, and no-content-read safety. Audit-plane bundles fail validation when this artifact reports tenant writes or body/file content reads. See `docs/reference/api-call-catalog.md` for the customer-facing review path.

`framework_mappings` uses canonical keys only: `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, `mcsb`, `cyber_essentials`, `google_workspace_baseline`, `nist_800_53`, `iso_27001`, `soc2`, `nis2`, `dora`, `mitre_attack`, and the deprecated `cis_m365_v3`. The validator still accepts `cis_m365_v3` for older bundles and operator overrides, but shipped mappings no longer emit it. Exporters treat those keys as stable taxonomy labels for SARIF, OSCAL, and the CSV `framework_mappings` column. `configs/framework-catalog.json` records the source version, date, URLs, and verified control ids for each benchmark key; see `docs/reference/framework-mappings.md`.

`reports/report-pack.json` carries `baseline_alignment`. For each of `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, and `mcsb` it lists the controls the shipped rules map to, with `status` (`fail`, `accepted_risk`, `pass`, or `not_assessed`), the mapped `rule_ids`, per-rule `rule_statuses`, and open `finding_ids`. Each `rule_statuses` entry has `rule_id`, `status`, and `evaluated`; a rule that was not evaluated also has a `reason`. A rule passes only when it was evaluated: every collector that feeds it completed and the evidence it reads was present. A control passes only when every mapped rule passed. `baseline_alignment.unmapped_findings` (`count`, `open_count`, `accepted_count`, `collectors` as a list of `{collector, count}`, `finding_ids`) counts findings with no `rule_id`, which no control can see. Every finding this version emits carries a `rule_id` (the finalizer refuses one without), so `count` is 0 for these bundles; a non-zero count marks a bundle from an earlier version or findings imported from elsewhere, and its open findings are not in any control row. `baseline_alignment.frameworks.cyber_essentials` is the exception: it lists every requirement in the catalog (Cyber Essentials Requirements for IT Infrastructure v3.3), not only the mapped ones, and each row adds `theme`, `requirement_status` (`automated`, `partial`, `manual`, `ce_plus_assessor_test`, or `provider_responsibility`), `citation`, `evidence_limits`, an `evidence` count object, a per-rule `confidence` (`full` or `partial`), and `ce_plus_test` where one applies. Its `status` keeps the four values above, but a `manual`, `ce_plus_assessor_test` or `provider_responsibility` row is always `not_assessed` with `reason` `requirement_status:<status>`, and it is never `pass`. A `partial` row can be `fail` or `accepted_risk`; when its mapped rules are all evaluated and clean it is `not_assessed` with `reason` `partial_requirement_no_gap_found`, never `pass`. Only an `automated` row can be `pass`, and v3.3 has none. The section also carries `requirement_status_counts`, `uncatalogued_requirement_ids`, `document_url`, `effective_date` and a `disclaimer` that the output is assessor evidence, not a certification. `baseline_alignment.schema_version` is `2026-10-20` for this shape. `baseline_alignment.secure_score` reconciles the latest Microsoft Secure Score snapshot with Auditex findings: `overall` (score, maximum, percentage) and one row per mapped control profile with Microsoft's score and maximum, `microsoft_state`, `auditex_state`, and `agreement` (`agrees`, `auditex_only`, `microsoft_only`, or `no_microsoft_data`). `normalized/security_score_control_profiles.json` holds the control profile ids, titles, and maximum scores used for that table.

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
`result_limit`, collection errors and fan-out limits still bound coverage, and
each cut list is recorded under "Collection limits and coverage gaps" below.
`full_counts` uses the maximum reported per-source inventory count rather than
adding duplicate inventories; `full_counts_basis` is
`maximum_per_source_not_unique_union`. Normalized counts describe actual records.
The chunk reader streams, while the final normalized snapshot is memory-resident.

### Collection limits and coverage gaps

Compatibility notes for consumers of earlier bundles:

- The coverage row `result_limit` is now the effective limit: `null` without `--top`,
  the sample bound for a sampled list (500 for event logs, 100 for the hybrid sync
  sample), and the operator's limit otherwise. It used to repeat the raw `--top` value
  even when the list was unlimited or sampled.
- Google Workspace `truncated_sections` in `normalized/snapshot.json` and the manifest
  changed format and meaning. It lists `<collector>.<list>` (for example
  `google_directory.users`) for each list that was cut, where it used to list the names
  of collectors whose total item count had reached `--top`. `sample_truncated` is true
  only when a list was cut. Consumers that matched collector names must change; this is
  a breaking change. The Google `--top` default also changed from 100 to no limit, and
  `top_limit` is omitted from the manifest unless an operator set one.
- `normalized/normalization_coverage.json` records gain `truncation_reason` (null unless
  the list was cut) and `derived_fanout` (true for a fan-out wrapper section, which
  restates its own coverage row and is not a list). The AI-safe summary
  (`ai_safe/run_summary.json`) gains `collection_gap_count`.
- The audit log (`audit-log.jsonl`) records `graph.request.next_link_refused` with the
  refused host when a next-page link or absolute first URL outside Microsoft Graph is
  refused, and `collector.endpoint.finished` events carry `collection_truncated`.

Without `--top`, every list is paged to its last row: users, user registration
details, role assignments, Conditional Access policies, groups and applications on
Microsoft 365, and users, groups, OAuth tokens and devices on Google Workspace.
`--top N` is an explicit operator limit for very large tenants, applied to every
list (`--top 0` means no limit). A list that stops before its last row is a
coverage gap, never a silent pass:

- The list's coverage row (`coverage.json`) has `collection_truncated: true` and a
  `truncation_reason`: `operator_limit` (the `--top` limit was reached and the list
  continued), `pagination_failed` (a later page could not be read, so the rows read
  so far are a prefix), `next_link_refused` (a next-page link outside Microsoft
  Graph was not followed), `fanout_limit` (a collector's own bound on how many
  objects it expands) or `input_limited` (a derived result built from a list that
  was cut). A limit hit sets the row `status` to `partial` with `error_class`
  `collection_limit`, and `item_count` is the rows collected. A page that failed or
  was refused keeps `failed` and its error. A first page that cannot be read is a
  blocked read, not a truncation.
- The collector is `partial`, so the run is `partial` (exit status 1) and baseline
  rules that read it report `not_assessed` with `collector_not_complete:<collector>`
  instead of `pass`. Findings that name the collector issue are raised from the row.
- `normalized/collection_gaps.json` has one record per cut list: `collector`, `list`,
  `rows_collected`, `reason`, and `result_limit` and `endpoint` where known, keyed
  `collection_gap:<collector>.<list>`. The file exists only when a list was cut.
  `normalized/snapshot.json` carries `collection_gap_count`; the Google snapshot
  also lists the cut lists in `truncated_sections` (`<collector>.<list>`) with
  `sample_truncated`.
- Each affected `coverage_gaps` row in `run-manifest.json` and `summary.json` has a
  `truncated_lists` array of the same `{collector, list, rows_collected, reason}`
  records, and its `message` names them. The manifest records the operator limit as
  `top_limit` when one was set.
- `validation.json` reports `truncated_list_reported_ok` when a cut list sits in a
  manifest whose `overall_status` is `ok`, and `collection_gap_not_recorded` when the
  manifest's gaps do not name it.

Some bounds are samples by design and are not gaps: the Entra sign-in and directory
audit logs and the Google Reports event logs and Drive file crawl keep the most
recent 500 rows (narrow them with `--since` and `--until`), the hybrid sync check
reads the first 100 users, and capability probes and preflights read a few rows to
test access. Their coverage rows carry `bounded_sample: true` and
`collection_truncated: false`. An explicit `--top` below a sample bound is still a
gap; a `--top` at or above it does not raise the bound, on Microsoft 365 or Google Workspace.

Per-object fan-outs are not samples. Each reads only the first objects of its list and
adds a derived `partial` coverage row (`truncation_reason` `fanout_limit`, with
`fanout_total` and `fanout_limit`, `rows_collected` being the objects expanded) when more
exist, so the collector is `partial` and the rules that read it are `not_assessed`:

| Collector | Fan-out | Objects expanded | Coverage row |
| --- | --- | --- | --- |
| `sharepoint_access` | site permissions | first 10 sites | `sitePermissionsFanout` |
| `intune_depth` | device configuration assignments | first 10 policies | `deviceConfigurationAssignmentsFanout` |
| `teams` | team channels | first 10 teams | `teamChannelsFanout` |
| `app_consent` | service principal owners and role grants | first 10 principals plus Microsoft Graph | `servicePrincipalFanout` |
| `identity` | members and owners of role-assignable groups | 50 groups | `privilegedGroupFanout` |
| `directory_relationships` | group members and owners, application owners | 100 groups and 100 applications | `relationshipGroups`, `relationshipApplications` and the per-parent member and owner rows |

A rule that reads a fan-out can still `fail` from what the expanded objects show. The
`intune_depth.policies_without_assignments` finding counts policies from
`intune_depth`'s own `deviceConfigurations`, and `identity_governance.standing_privilege_only`
needs a successful, empty `roleEligibilitySchedules` read; neither is raised when the read
failed or was cut. Baselines evaluate the Intune rule only when
`normalization_coverage` shows both the policy inventory and the assignments were read in
full (`device_configurations_not_collected`, `device_configurations_not_read_in_full`,
`no_device_configurations` and `policy_assignments_not_read_in_full` are the reasons it
reports otherwise).

The Google Workspace fan-outs run one call per object and are the slow part of a large
domain: `google_directory` makes two calls per user (aliases and OAuth tokens) and one or
more per group (members); `google_gmail_settings` makes eight calls per user
(auto-forwarding, filters, forwarding addresses, send-as, IMAP, POP, vacation and
delegates); `google_groups_settings` one per group; `google_calendar_posture` one per
calendar. A 20,000-user domain is about 160,000 Gmail settings calls on its own. For a
large domain set `--top` so the user and group lists, and with them the fan-outs, are
limited; every cut list is then recorded as a gap, which is the point.

Reads are kept as far as they got: when a later page fails or is refused after rows were
read, those rows stay in the evidence in both the chunked and the in-memory path, and the
list is recorded with `pagination_failed` or `next_link_refused`.

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
