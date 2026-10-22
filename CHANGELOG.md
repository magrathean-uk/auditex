# Changelog

All notable changes to Auditex are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The run-bundle contract has its own
date-based version, `CONTRACT_VERSION` (see `docs/reference/output-contract.md`).

## [Unreleased]

### Bundle compatibility

- **Contract version.** `CONTRACT_VERSION` is `2026-10-22` (was `2026-10-20`). Evidence is now
  traceable: the validator resolves every evidence reference, and five new validation codes report one
  that does not (`unresolved_evidence_ref`, `evidence_ref_hash_mismatch`,
  `unresolved_report_proof_table_ref`, `unresolved_report_evidence_ref`, `legacy_unresolved_ref`;
  `broken_evidence_ref` also covers an artifact outside the run directory). Older bundles whose
  references name records that do not exist now fail validation when it is recomputed (handoff, the
  explorer, the gates, the customer pack); their files are not rewritten. In a bundle finalized under an
  earlier contract version the failure is reported as `legacy_unresolved_ref`, so that it reads as the old
  builders' citations and not as tampering. It is still an error and the gate still fails closed.
- **New fields.** Evidence references gain `resolved`, `unresolved_reason`, `content_hash` and
  `collected_at`; proof rows gain `collected_at`, `content_hash` and `unresolved_reason`; each finding's
  `proof` summary gains `supported_count`. `proof_status` is `supported` only for a reference that
  resolved, and a finding's `confidence` follows from how many of its references resolved. A new
  normalized section, `intune_policy_assignment_objects`, holds one row per Intune policy the assignment
  read returned.
- **Removed.** The collector-failure rows in `diagnostics.json` and `blockers/blockers.json` no longer
  carry `evidence_refs` (the incomplete-evidence rows from normalization still do); a collector issue cites its row of `blockers/blockers.json` instead (Google Workspace
  collector issues cite the collector's `normalized/coverage_ledger.json` row, not `blockers.json`).
  Consumers that read `evidence_refs` from those rows must read them from the finding.
- **New artifact.** Finalization writes `bundle-hashes.json`, the SHA-256 of every artifact. Handoff,
  the explorer and customer-pack creation recompute it. A bundle whose hash manifest is missing but still
  listed in `run-manifest.json` is `invalid`, not `absent`. A changed or invalid bundle makes the handoff
  `unusable` (see `status_reasons`) and `auditex report customer-pack` refuses to build a pack from one, or
  from a bundle that no longer validates (exit status 2).
- **Breaking for consumers of the OSCAL export.** The export now validates against the OSCAL 1.1.2
  Assessment Results schema, which the earlier shape did not. A finding has a `target` instead of
  `target-ids` and `remediation`; mapped controls are `framework-control` properties; observation
  subjects use `subject-uuid`; the collection time is the run's `created_utc`, not the export time.
- **Citations.** The Global Administrator, standing-privilege and Intune assignment findings cite
  records that exist; they used to cite invented keys.

### Added

- The SARIF and OSCAL exports are validated in the tests against the official schemas, vendored under
  `tests/schemas/` with the NIST and OASIS notices. `pip install -e '.[test]'` (which `make install` now
  runs) installs `jsonschema` for that.
- The explorer shows a banner when the bundle changed since it was finalized, when it does not validate
  now, or when the only failures are legacy citations.

### Fixed

- `build_run_evidence_index` closes its SQLite connection, so `index/evidence.sqlite` holds the whole
  index as soon as the run is finalized instead of leaving it in a `-wal` sidecar.

## [1.1.0] - 2026-10-22

Everything below is new since the `v1.0.0` tag of 2026-04-18. The package and the bundle contract
changed together, so read the compatibility note before upgrading a pipeline that reads bundles.

### Bundle compatibility

- **Contract version.** `CONTRACT_VERSION` is `2026-10-20` (previously `2026-04-21`). The contract
  changes are additive: new artifacts, new optional fields and two new validation codes
  (`truncated_list_reported_ok`, `collection_gap_not_recorded`). The required root artifact list is
  unchanged.
- **Older bundles still validate.** Bundles written under `2026-04-21` stay valid. A coverage row is
  checked for a recorded truncation reason only when it carries a `truncation_reason`, and older rows
  that flag `collection_truncated` on an `ok` row carry none.
- **Breaking for consumers of one field.** In Google Workspace bundles, `truncated_sections` in
  `normalized/snapshot.json` and in the manifest changed format and meaning. It now lists
  `<collector>.<list>` (for example `google_directory.users`) for each list that was cut, where it
  used to list the collectors whose total item count had reached `--top`. `sample_truncated` is true
  only when a list was cut. Code that matched collector names in this field must change.
- **Related collection changes.** The Google `--top` default changed from 100 to no limit, and
  `top_limit` is omitted from the manifest unless an operator set one. The coverage row
  `result_limit` now holds the effective limit (`null` without `--top`, the sample bound for a sampled
  list, otherwise the operator's limit) instead of repeating the raw `--top` value.
- **New rule ids with contract `2026-10-20`.** `ca.mfa_not_enforced`, `ca.legacy_auth_not_blocked`,
  `ca.enforcement_unverified`, `consent_policy.user_consent_unrestricted`,
  `consent_policy.user_consent_unverified` and `identity.privileged_mfa_not_registered`, plus nine
  rules for builders that previously had none: `ca.break_glass_exclusion_missing`,
  `ca.policy_report_only`, `exchange.mailbox_forwarding_configured`,
  `identity_governance.standing_privilege_only`, `intune_depth.policies_without_assignments`,
  `onedrive.external_sharing_enabled`, `sharepoint.site_orphaned`,
  `sharepoint.site_weak_ownership` and `teams.external_federation_open`. Earlier rule ids arrived with
  the work under "Also since v1.0.0". No finding template (rule id) was removed or renamed since
  `v1.0.0`; the shipped templates grew from 5 to 82.
- **Registration rules reworded, not renamed.** `identity.global_admin_mfa_not_registered` and
  `identity.user_mfa_not_registered` keep their ids. Their text now says they report MFA
  registration only, not whether MFA is required at sign-in; that is what `ca.mfa_not_enforced`
  assesses. `identity.privileged_mfa_not_registered` covers other accounts that hold an
  administrator role, including PIM-eligible assignments; Global Administrators stay on their own
  critical rule.
- **Findings without a `rule_id`.** Every finding this version emits carries a `rule_id`, and the
  finalizer refuses one without. A bundle from an earlier version, or findings imported from
  elsewhere, may still have findings with none; baselines count them under
  `baseline_alignment.unmapped_findings`.
- **Gates and waivers.** `auditex gate` and `auditex gate-drift` now exit non-zero for runs they
  used to read as clean (see Changed). Waiver files that relied on matching a single field are
  refused or narrowed.

### Added

- **Complete evidence normalisation.** Collected evidence is normalised in full through a streaming
  chunk reader, with `normalization_complete`, `normalization_issue_count`,
  `normalization_incomplete_sections` and `collection_limited_sections` in the bundle. The opt-in
  `directory_relationships` collector records group members and owners and application owners as
  bounded relationship inventories.
- **Tenant identity guards.** The operator's input is kept as `tenant_id_requested`, the canonical
  observed UUID is `tenant_id`, and `tenant_identity` records status, source pointers and
  conflicts across the manifest, summary, report pack, AI context and SQLite `run_meta`.
  Conflicting evidence invalidates a bundle; comparisons, explorers and drift gates reject
  different established tenants. `verified` does not authenticate a saved bundle.
- **Collection gaps instead of silent truncation.** Without `--top`, every list is paged to its last
  row. An operator limit, a failed later page, a refused next link or a bounded fan-out is recorded
  per list as a coverage gap in `normalized/collection_gaps.json`, the manifest and validation, and
  marks the collector partial so baselines stop reporting a pass. Google Workspace has the same
  treatment.
- **Effective-MFA verdicts.** `normalized/identity_control_verdicts.json` carries tenant-level
  verdicts for effective MFA, legacy authentication block and user consent, derived from security
  defaults, Conditional Access targeting and the authorization policy. A verdict is `unknown`
  whenever the policy read was blocked, truncated or absent, and registration alone never means
  enforced. The `conditional_access` collector now reads
  `identitySecurityDefaultsEnforcementPolicy` (read-only, within `Policy.Read.All`).
- **Per-rule baseline status.** `baseline_alignment` lists `rule_statuses` (`rule_id`, `status`,
  `evaluated`, and a `reason` when not evaluated) for each control. A rule passes only when it was
  evaluated, and a control passes only when every mapped rule passed.
- **Cyber Essentials v3.3 framework key.** `cyber_essentials` maps the 30 requirements of
  Cyber Essentials Requirements for IT Infrastructure v3.3 (April 2026) with honest statuses
  (`partial`, `manual`, `ce_plus_assessor_test`, `provider_responsibility`) to the identity, access
  and consent rules that evidence them. A partial requirement never reads as a pass, and manual and
  assessor requirements carry no verdict. Reports and the explorer show the section with its
  reasons.
- **External assessment imports.** `auditex assessment sources|import|compare` normalises Maester,
  CISA ScubaGear and Monkey365 JSON reports offline and compares them by explicit control id. It
  runs no external tool and calls no tenant. Each report records whether its tenant identity came
  from the source or the operator, and an unbound report cannot be compared.
- **Model-development tooling.** `auditex model sources|stage|evaluate|combine|prepare` stages
  reference data, checks recorded answers against reviewed cases and writes guarded LoRA recipes and
  reviewed data exports, all offline. Scripts: `scripts/build-lab-model-cases.py`,
  `scripts/build-model-examples.py` and `scripts/run-model-benchmark.py` (local GGUF benchmark). A
  `model_train` extra pins a candidate training environment.
- **Oracle tooling.** `scripts/build-oracle-cases.py` mines labelled cases from CISA ScubaGear's Rego
  policies under OPA, deriving each case's evidence view from the policy's own input dependencies.
  `scripts/split-oracle-cases.py` keeps whole policy groups and reasoning templates in one split,
  deduplicates by masked prompt hash and writes a frozen holdout hash. Cases accept
  `provenance.evidence_view` and `provenance.oracle_outcome`.
- **Prowler consensus.** `scripts/build-prowler-cases.py` and `configs/oracle-policy-map.json` run
  mapped Prowler Microsoft 365 checks offline over the same tenant variants and write per-policy
  verdicts with agree, disagree and unmapped outcomes. Prowler is imported at run time and nothing
  is vendored.
- **Thinking-on benchmark arm.** `scripts/run-model-benchmark.py --enable-thinking` (mutually
  exclusive with `--disable-thinking`) records reasoning presence, length and a best-effort token
  count per case; the thinking-off protocol is unchanged.
- **Checkpoint scoring.** `scripts/score-adapter-checkpoints.py` selects a LoRA checkpoint by greedy
  generated answers on held-out cases, by strict pass rate and then lowest overconfidence and
  over-abstention, never by eval loss.
- **Free-directory lab scenarios.** `tenant-bootstrap/scripts/seed-free-directory.py` and
  `exercise-free-directory.py` seed and exercise isolated Entra Free directory fixtures. These are
  lab tools with write operations, outside the audit-only scope.
- `scripts/generate-rule-packs.py --check` and `make release-check` (lint, tests, contract smoke,
  rule-pack drift, taint scan and a gitleaks scan of the tree).

### Changed

- `auditex gate` and `auditex gate-drift` fail closed. A missing, empty or invalid run, a contract
  that does not validate when recomputed, a findings list that disagrees with the report pack, or
  partial coverage (unless `--allow-partial`) is a blocked result with a `code` and exit `2`.
  Accepted risk is reported, not dropped, and `gate-drift` marks a vanished finding resolved only
  when every collector its rule reads completed.
- Waivers match by AND over every populated field of `finding_id`, `rule_id`, `collector` and
  `category`, and need a `finding_id` or a `rule_id`. Expired waivers do not match. A waiver file
  that is missing, unreadable, malformed or contains an invalid row or date stops the run before
  any tenant call.
- Baselines report a rule as `pass` only when it was evaluated, and read the verdict records.
- The `mcp` extra is capped at `>=1.30.0,<2`. A Dependabot update had widened it to `<3`, but the
  MCP server is only tested against a stand-in for `FastMCP`, so an untested 2.x could silently
  drop the read-only tool annotations. Dependabot is told to skip major `mcp` updates.
- The README, demo and handoff guide call the customer pack checksum-verified; the earlier wording
  overstated the guarantee. `checksums.sha256` is stored inside the pack and is not signed, so
  `verify-pack` detects corruption and edits that were not also re-hashed; it does not authenticate
  who produced the pack.
- Product-site links and the support address use the Magrathean forms:
  `https://magrathean.uk/solutions/auditex/` and `contact+auditex@magrathean.uk`.
  `.github/SECURITY.md` gains a supported-versions table and handling targets, and
  `.github/SUPPORT.md` gains the support address.
- Pre-commit runs Ruff and the trailing-whitespace and final-newline checks on every commit (they
  were manual-only). The tree was cleaned so those hooks pass.

### Also since v1.0.0

Earlier work in the same cycle, listed by headline only; the git history has the detail.

- New collectors (`dns_posture`, `app_credentials`, `mailbox_forwarding`, `cross_tenant_access`,
  `power_platform` and capability-gated stubs), SARIF 2.1.0 and OSCAL exporters, `auditex gate` and
  `auditex gate-drift`, and Jira and GitHub Issues notification sinks.
- Attack paths (conditional hypotheses with ATT&CK techniques and break points), detection
  coverage and public-footprint signals, and current baselines (CIS Microsoft 365 v7, CISA SCuBA,
  Microsoft Secure Score, Zero Trust and MCSB).
- `auditex demo` (a synthetic tenant, offline) and `auditex report explorer` (one self-contained
  HTML page).
- Apache-2.0 licence, and removal of Sentry telemetry.

## [1.0.0] - 2026-04-18

Tagged as `v1.0.0`. The tag predates the work listed under 1.1.0, which is not itemised here.

[1.1.0]: https://github.com/magrathean-uk/auditex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/magrathean-uk/auditex/releases/tag/v1.0.0
