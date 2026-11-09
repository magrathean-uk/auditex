# Changelog

All notable changes to Auditex are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The run-bundle contract has its own
date-based version, `CONTRACT_VERSION` (see `docs/reference/output-contract.md`).

## [Unreleased]

### Removed

- **The parked model layer.** The `auditex model` command is gone with its `sources`, `stage`, `evaluate`,
  `combine`, `prepare`, `assess` and `doctor` subcommands, the model client and prompt builders, the training,
  evaluation and benchmark tools, the oracle and lab case builders, the model catalogue and
  the model-development examples. The `model_train` optional dependency extra is removed. No product answer ever
  came from the model: every SCuBA answer comes from the value rules, unchanged.
- **The legacy model options and settings.** `--endpoint`, `--model`, `--dry-run`, `--no-redaction` and
  `--shadow-model-on-precheck` are no longer accepted (exit 2), `AUDITEX_MODEL_*` and
  `AUDITEX_DISABLE_VALUE_RULES` are no longer read, and `model_assessment_prompts.jsonl` is no longer written.
  The model endpoint is no longer a permitted outbound destination.

### Added

- **`auditex assess <run-dir>`** writes the same private, rule-only `model_assessment.json` that
  `auditex model assess` wrote, with `--policies` and the `--projection-*` budget and scan flags. Existing
  assessment files, their schema and every verdict are unchanged. See `docs/guides/ai-assessment.md`.

### Changed

- The AI assessment guide now holds the rule pre-check description; `docs/guides/model-development.md` is a short
  retirement note that keeps its anchors.

## [1.3.0] - 2026-11-08

Highlights, ordered by user impact. The detailed entries follow.

### Security and privacy

- **Secret flags are redacted on every parser.** Abbreviated and rejected arguments no longer leak a secret into
  logs, diagnostics or command history records; the vendored bootstrap CLI rejects abbreviations as well.
- **Shareable output applies the D3 redaction profile.** Reports, built-in exports, MCP payloads, notifications and
  customer packs mask GUIDs and the free-text keys `owner`, `justification`, `comment`, `comments` and `notes`.
  Limit: person names in free text and identifiers are not masked, and domains, group names and role names remain.
  Local reports keep their data; incomplete or unstable evidence refuses shareable output.
- **Content cmdlets are refused at runtime.** The PowerShell read guard now rejects Exchange and other cmdlets that
  can return message or file content, instead of accepting any `Get-*` cmdlet.
- **Google Workspace text is excluded at the request.** Gmail settings (vacation, send-as and filter text), Alert
  Center and group-settings text is no longer requested, so it never reaches the collector. Live Gmail output
  drops the text-derived length and presence fields (for example vacation message and signature lengths); no value
  rule read them. Offline fixtures and the contract follow.
- **Google Alert Center severity and status are read from alert metadata.** Alert severity and status now come from
  the `metadata` object the field mask keeps, so alerts whose metadata is HIGH or CRITICAL are rated high; they were
  previously read from absent top-level fields and rated medium.
- **The `gmail.settings.sharing` scope is removed.** Nothing used it. The remaining write-capable Google scopes
  (`admin.directory.user.security`, `apps.alerts`, `gmail.settings.basic`, `apps.groups.settings`) have no
  read-only form; they stay on by default for list and get calls only, with their blast radius documented.
- **Exchange transport-rule disclaimer text is no longer collected** (`ApplyHtmlDisclaimerText`). The
  `PrependSubject` text stays because MS.EXO.7.1 judges it.
- **Intune custom-profile payloads are stripped on receipt.** The profiles are still read; the payload never reaches
  evidence or reports.

### Bundle contract

- **`CONTRACT_VERSION` is now `2026-11-08`** (was `2026-10-22`). The fields new since 1.2.4 (Teams skip reasons and the PIM role policy artefact, records, rows and gap reasons) and the removal of the Google text-derived length and presence fields (see Security and privacy) are listed under "Contract history" in `docs/reference/output-contract.md`. Consumers that read a removed field must stop; bundles finalized under `2026-10-22` stay readable and compare and drift across the two versions still work. The legacy-reference cut-off stays `2026-10-22`.

### Assessment

- **SCuBA answers come from value rules only.** All 102 policies have rules (spec v3.9.1); the model is never
  called and the model layer is parked. Explainer wiring is shipped: supported assessment rows and the JSON,
  Markdown and HTML reports carry a redacted deterministic explanation.

### Collection and trust

- Collector trust needs a successful live read; readiness, audit plans and reports reflect it.
- Sensitive-user and partner-domain operator inputs feed SS 2.1 and SS 2.3 privately.
- Exchange policy and DNS posture join app-mode defaults; Teams reads skip cleanly without a certificate token.

### Detail

- Preserve blocked JSON for gate input refusals and constant-code incomplete-evidence issues for refused chunks, without reading refused bytes or falling back to inline samples. Keep owned bundle directories private without changing existing caller-owned parent permissions.
- Refuse unsafe sensitive-user and partner-domain pair aliases in guarded run reads
  and retain admitted descriptors across selected inputs. SQLite index inspection
  uses a protected temporary copy when available and otherwise reads the admitted
  file in place with SQLite immutable mode. Hard-linked backups require an
  independent copy; the boundary and its exclusions are in the privacy reference.
- Discover enclosing runs from the selected file when callers supply a nested
  root, prevent private-directory manifests from becoming trust roots, and guard
  optional training-pack file reads and hashes.
- Require a successful live read for collector trust; successful empty reads count, but skipped, failed, derived-only and offline rows do not. Readiness includes preflight-skipped requests, and audit-plan trust counts and permission ledgers reflect the same gates. Reports, JSON exports, handoffs, MCP and notification previews surface the revised trust; explorer marks unscoped all-skipped collectors not verified and recognises successful empty reads alongside skips. Run status, exit code, coverage and autopilot quality verdicts, and customer limitation reasons remain unchanged: with all reads skipped and no section-scoped gap or blocker, quality can be `complete` and require no human review with zero trusted gates while readiness is `setup_only`. After a preflight skip, the manifest and audit plan list the remaining collectors in `selected_collectors`, while readiness includes the original selection. Response-mode lab probes have no read rows, so their response and toolchain collectors are no longer live-verified.
- Add redacted deterministic explanations to supported value-rule assessment rows and validated JSON, Markdown and HTML reports; incomplete model-case evidence and optional-collection gaps leave the explanation absent.
- Apply the D3 redaction profile to shareable reports, built-in exports, MCP payloads, notifications and customer packs. GUIDs and the free-text keys `owner`, `justification`, `comment`, `comments` and `notes` are redacted; domains, group names and role names remain. Local reports retain their data. Incomplete or unstable normalised evidence refuses shareable output. URL userinfo passwords are recognised for schemes of up to 32 characters; known immutable IDs in narrative need at least four characters and word-character boundaries.
- Raise the shareable identity-discovery limits to 64 MiB per normalised file and 256 MiB per run. Synthetic 25,000- and 90,000-user runs fit; their HTML previews used about 0.5 GiB and 1.5 GiB peak resident memory on the test machine. The scan limits are not memory ceilings. Over-limit output is refused without naming files.
- Guard MCP bundle artefacts and customer-pack source reads against unsafe types and links, including shareable normalised report sections; bound data reads, stream bundle hashing without a size cap, and treat uncheckpointed legacy WAL indexes as untrusted on every host instead of replaying them.
- Keep all `AUDITEX_*` variables and operator-input flags out of MCP offline validation sample runs, and close child stdin; real audits retain their environment.

- Let SS 2.1 decide from verified SensitiveUsers and a bound `TargetedUsersCoverage` summary. Collection compares protected-user targets transiently, applies raw-entry, UTF-8 byte and streamed stdout bounds, and removes target strings before evidence or diagnostics are saved. Offline replay recomputes fresh membership and resume checks the original summary against the current input binding. Missing input remains not assessed and invalid private pairs are refused. SS 2.3 independently consumes verified PartnerDomains in its own private rule view; the ScubaGear export path keeps literal comparison.
- Reduce unsupported target-bearing replay layouts to safe settings and closed diagnostics. Failed Exchange re-runs after an input-binding change preserve safe earlier settings without retaining or rebinding membership proof.
- Add the strict `targeted_users_coverage` schema and local normalised/index retention. Shareable, customer-pack and explainer outputs drop the whole summary and private binding, and retain at most boolean `supplied` from sensitive-user manifest metadata. Counts and HMAC stay local; customer-pack seals cover the transformed manifest.
- Retain exit-0 JSON evidence with stderr warnings in the shared PowerShell adapter.
  Every adapter command uses `$ErrorActionPreference = 'Stop'`, including
  Microsoft365DSC and lab-only response actions; empty stdout with stderr remains
  `command_error`. Only legitimately empty Exchange lists are array-wrapped;
  default-bearing configuration requires an answer and empty accepted-domain
  evidence falls back to Graph for DNS. Proxy-function error propagation remains
  unverified without PowerShell.
- Preserve explicitly named and profile-selected Microsoft 365 CLI `exchange`
  collection in guided app flows. Keep Windows 365 in generated probes, disclose
  explicit app-only names omitted from delegated setup commands, and print session
  and resolver notices before standalone probe reads. Clarify the permission
  catalogue's `ipps_session_not_opened` skip.
- Add `--partner-domains` and `AUDITEX_PARTNER_DOMAINS_FILE` for bounded local customer-confidential SS 2.3 input, with sanitised domain validation, private bundle storage, separate per-run HMAC key, resume consistency and report/export/pack exclusions; the manifest schema defines the field and deterministic SS 2.3 rules consume only the verified private snapshot. Neither input enters model views or the shape gate.

- Remove the dead internal row-level scope post-check; the envelope caveat and historical validation stay unchanged, with no output change.
- Add `--sensitive-users` and its environment fallback for local confidential operator input, with private bundle storage, sanitised validation and output exclusions; record `hmac_sha256` with a per-run private `operator-inputs/sensitive-users.key` and list the private files under the `redacted_operator_input` exclusion in `bundle-hashes.json`. SS 2.1 private rule-view integration is described above.

- Skip the Teams reads and say so when no Teams certificate token is available, instead of failing the run; record teams_token_unavailable as a collector error class; with a token, messaging and app setup are skipped as teams_powershell_not_supported.

- App-mode `auto`/`global-reader` defaults and the `full` preset include read-only
  Exchange policy sessions and public DNS posture through Cloudflare DoH. Profile
  defaults (including `exchange-reader` and `app-readonly-full`) and presets omit
  both for delegated, interactive and access-token modes, even with `--include-exchange`;
  that flag retains the Microsoft 365 CLI `exchange` collector. Only explicit
  `--collectors` overrides this boundary. Guided `app-audit` keeps both defaults. Use the
  existing `--exclude exchange_policy`, `--exclude dns_posture` or both to deselect.
  Disclose the resolver, domain scope and Exchange permission/reader-role blast radius.
- Preserve legitimately empty Exchange policy lists as successful reads; keep real
  command failures partial. Resolve generated setup commands and requirements per
  authentication mode, including app disclosures in the default delegated guide.
  Name skipped sections in explorer rows even when other policy rows were collected.
- Record the unopened IPPS alert-policy session as a named by-design section skip:
  healthy Exchange collection and the run stay `ok`, with a passing coverage gate
  and visible limitations. Real Exchange/DNS failures leave policies not assessed
  and the run `partial`, with collection exit 0 when they are the only failures;
  coverage gates still block partial runs unless `--allow-partial` is supplied.
  Live runs and offline replays print one stderr line naming the incomplete
  collectors and put the same notice in the run summary, without error details.
- Include Exchange/DNS in app-mode probe surfaces and avoid a duplicate full pass
  for these collectors during `--probe-first`; redact collector crash diagnostics.

- Preserve `unsupported_environment` in assessment collector diagnostics when Teams policy collection is unavailable for the environment.
- Use complete same-run Exchange accepted domains for SPF, DKIM and DMARC TXT records, excluding coexistence domains and preserving first-seen spelling; fall back to Graph-verified mail domains when evidence is unusable. HTTPS reads remain limited to Graph-verified domains.
- Move the value-rule catalogue and loader from the v3.9 content to spec v3.9.1 content with addenda A1 and A2. The shipped
  catalogue already carried the `v3.9.1` label, 102 policies and 1,084 cells; the migration adds `evidence_kind`, `limitations` and
  `recommendations` to the 746 not-assessed cells that lacked them (all 761 now carry them), moves the citation variants (A1 and A2)
  and the AAD 6.1 two-code pairing from the separate `cell_contracts` table onto the cells, and replaces the
  `rule_failure` entry by `shared_reasons`. The loader pins the variant contract by digest and refuses the old table and entry.
  A rule that raised was answered as a catalogue cell named `rule_evaluation_failed`; it is now a shared reason with a null
  cell, dispatched before any cell lookup, so the fault record's `cell` changes from `rule_evaluation_failed` to `null`. Assessment
  schema `2026-11-05` accepts a null `rule_precheck.cell` and the validator rejects the old sentinel: a fault record written before
  this change no longer validates, so assessment bytes are not preserved for that one path. `rule_not_implemented` stays the
  row-level reason of the rule-only route; its constant text is catalogued under `shared_reasons`. A v3.9.1 vectors replay (a
  bounded sample by default, all 26,898 vectors plus A2's as an explicit acceptance job) checks the engine.
- Add the deterministic template explainer (`azure_tenant_audit.explainer`): a pinned CISA ScubaGear baseline reader and vendored baseline data, product-owned
  collection wording, a renderer that derives every cell's closed explanation, remediation and evidence references from the
  v3.9.1 catalogue, and a generated template (`scripts/generate-explainer.py`, drift-gated). It never calls a model, changes a
  verdict or reads evidence outside the rule's cited, redacted sections. Eight independent hard checks (S, a, b, c, d, e, e2, e3)
  test it: the test set, base pairs, mutants (19,354 harmful, 2,522 benign) and canary twins are generated in memory from the
  value-rule vector fixtures, which hold only constructed rows and pack train/validation rows, and a small manifest pins counts and
  stream digests; the red-team candidates are re-bound to allowed bases at test time. Fixtures stay under 1 MB and a test refuses test-split, pilot,
  sealed or diagnostic rows, machine paths and large files. Report wiring landed in the explanation entry above.

- Explain unassessed Power BI / Power Platform policies when optional collection was not enabled; preserve generic reasons for unknown selection and existing failures for selected collectors.

- Add value-rule contract A1 within assessment schema `2026-11-05`: distinguish collected but unusable evidence from missing collection, preserve legacy assessments and pack parity, and accept the exact 68 reason/citation contract exceptions for subsequent rule stages.

Model-development tooling (round 2 of the specialist-model programme) and an internal
engine/product boundary rework, plus the deterministic value-rule route and collection changes below.
`CONTRACT_VERSION` stayed `2026-10-22` for that work (1.3.0 moves it to `2026-11-08`); report, export and MCP tool contracts are unchanged; command-response diagnostics are masked as described below.
The `identity_governance` collector also gains two GET-only PIM role-policy reads and
the bundle gains the `privileged_roles` artefact, both additive.

### Rule-only SCuBA assessment

- **Rules answer every policy; the model is never called.** The model verdict fallback and shadow mode are removed.
  All 102 catalogue policies have value rules. A policy without a rule (none today) reports not assessed with
  `rule_not_implemented` and "Not assessed: Auditex has no rule for this policy yet." The model layer is parked.
- **`model_assessment.json` changed shape** within the unreleased `2026-11-05` schema: `endpoint_host` is `none`,
  `model_name` is `rules-only` and `serving` is gone. A file that carries either marker must carry both and no
  serving block, model-answered row or shadow; historical assessment files still validate.
- **`model assess` no longer exits 2 when no model name is given.** Legacy `--endpoint`, `--model`,
  `--no-redaction`, `--shadow-model-on-precheck`, `AUDITEX_MODEL_*` and `AUDITEX_DISABLE_VALUE_RULES` are accepted,
  ignored and warned once without echoing values; they cannot change answers.
- **`--no-redaction` can no longer unmask anything.** It used to leave e-mail local parts in the Conditional Access
  policy names listed under `scope_post_check` when the endpoint was a loopback host; redaction now always stays on.
  Model client, configuration and offline tooling remain available for development. Explainer report wiring is shipped (see the explanation entry above).

### Command-output privacy

- Mask e-mail and UPN local parts and dashed GUIDs in adapter audit-log samples,
  adapter error dictionaries (`stdout`, `stderr`, `output`, `error`), doctor/auth errors
  and toolchain probe details (including the capability matrix), alongside existing
  credential redaction. These diagnostics are now clipped to 500 characters;
  collected evidence and classification/parsing inputs retain their original values.
- Mask full MCP command-response streams without clipping, preserving explicitly
  supplied operator identifiers and resolved output/run paths so clients can chain
  tools. Exemptions cannot start inside another e-mail local part; credential
  redaction takes precedence over them.
- Bound e-mail matching and make JWT matching linear, preventing crafted output
  from stalling diagnostics. Inspect only a sample plus a fixed safety margin when
  clipping, dropping the trailing non-delimiter run if the input exceeded that
  window. Decode common address/GUID separators once and emit the decoded forms;
  retain URL hosts and paths, numeric npm versions, conventional Git SSH addresses,
  undashed hashes and labelled trace/correlation IDs. Graph request IDs retain the
  ordinary dashed-GUID masking rule. Credentials are masked before and after decoding,
  including literal secrets containing encoded separators; query/filter-glued addresses
  are masked separately. Accepted limits include unsupported or double-encoded separators,
  overlong local parts, numeric/IP-literal domains, GUIDs followed by hex characters and
  partial quoted or apostrophe local parts at a clipped scan edge; see the privacy model.

### Model projection correctness

- **ScubaGear export assessments:** a policy whose `scuba_config` view was not
  projected now receives not-collected evidence. On the shipped export fixtures,
  this changes prompts for MS.SECURITYSUITE.2.1v1, 2.3v1 and 3.2v1. Real exports
  can change more: declared break-glass exclusions affect nine AAD Conditional
  Access policies and MS.AAD.7.4v1; a non-commercial M365 environment affects
  MS.AAD.9.1v1, MS.TEAMS.2.2v2, MS.TEAMS.2.3v2 and MS.TEAMS.4.1v1. These model policy views
  remain withheld for non-commercial environments, including `gcchigh` and `dod`, as before.
  Private rule views retain recognised environments (`commercial`, `gcc`, `gcchigh`, `dod`).
  Run-bundle assessments are unchanged.

### Microsoft 365 user inventory

- **The user list now has a safety ceiling of 250,000 user objects, guests included.** Auditex reads `onPremisesImmutableId` on the
  main user list, so administrators beyond the first 100 users reach the privileged-user checks (MS.AAD.7.1 to 7.3). A tenant larger
  than the ceiling completes with a `pagination_not_followed` coverage gap on `identity.users` and a partial run (exit status 1);
  user-dependent checks are reported as not assessed rather than passed. The ceiling also applies with `--top 0` and with a `--top`
  above 250,000. Previous releases read the full list. The page size for this list is between 100 and 500 rows.

### Conditional Access projection

- **The Conditional Access section is withheld only for restrictions that restrict.** `auditex.scuba_projection` withheld the whole
  `conditional_access_policies` section whenever a restriction key (`sessionControls`, `locations`, `platforms`, `devices` and the
  rest) was present, whatever its value, and never used a policy's `State`. A null, empty or all-empty restriction is now read as
  absent, as `docs/reference/output-contract.md` always said. A restriction with a value withholds only when its policy is
  `enabled`: every pinned ScubaGear Conditional Access rule requires `policy.State == "enabled"` (`AADConfig.rego`), so a disabled or
  report-only policy (a Microsoft-managed policy that was turned Off, which cannot be deleted) stays in the projection with its state
  and its dropped keys are listed as `dropped_conditions` (`<policy id>:<path>`). A schema list field that Graph returns as `null`
  is read as `[]` (the pinned Rego does) and listed as `null_lists_read_as_empty`. Both keys are optional additions to the
  `2026-10-29` assessment schema; the whole-shape gate still applies.

### Model assessment schema

- **Deterministic value rules cover 102 SCuBA policies without a model call:** Entra ID 31, Exchange Online 12,
  Power BI 8, Power Platform 8, Defender 21, SharePoint 8 and Teams 14. The `2026-11-05` assessment schema adds
  class `value_rule` and inventory-validated cell, reason code and constant text; legacy `2026-10-29` is preserved.
  Both run-bundle and internal ScubaGear export paths capture a private in-memory rule view after collection-health
  withholding and before pruning, shape gates, model budgets and redaction; it is never persisted. Teams applicability
  gates are recorded as `value_rule` / `closed_gate`.
  Rules are always enabled in product assessment; legacy `AUDITEX_DISABLE_VALUE_RULES` is ignored. Offline
  `evaluate_precheck` scoring leaves them off. The deterministic explainer is wired into assessment rows and reports.
- **A value rule that fails on collected evidence has its own answer.** It was answered as "section not collected"; it now
  answers the catalogued `rule_evaluation_failed` reason ("Not assessed: Auditex could not evaluate this policy on the collected
  evidence. This is a product fault, not a tenant setting.") with no limitation and the new recommendation `report_product_fault`
  (report to `contact+auditex@magrathean.uk`). Both are additive within the unreleased `2026-11-05` schema. The log line still
  names only the rule id and the exception class, and `MemoryError` still propagates.

### Collection (1.2.2.dev5)

- **Exchange 1:** select transport and organisation config names, remote-domain trust and transport-rule scope,
  and add `Get-SharingPolicy`. Normalised `transportConfig` keys now use `Name`; `organizationAuditConfig` keys use
  `Identity`, changing record keys and dependent finding ids. Live organisation-identity serialisation is still unverified.
- **Exchange 2:** save raw SPF, DKIM and DMARC answers and resolver logs for verified Email-service domains,
  with bounded fan-out, a retry and explicit failure/truncation coverage.
- **Exchange 3:** project remote domains, transport rules and the sharing policy on the run path, with failed reads
  withheld and sharing partner domains retained as configuration metadata.
- **Teams 1:** widen meeting-policy fields and add broadcast/client configuration reads without new permissions.
  Federation records now carry `Identity`; the finding id becomes
  `teams_policy:tenantFederationConfiguration:Global:external_federation_open`, a one-off comparison change.
- **Teams 2:** project app-permission, client, broadcast and federation policy sections on the run path;
  only the exact open allow-list marker is treated as unrestricted federation.
- **AAD and SharePoint 1:** collect additional AAD policy evidence: beta directory settings, app management
  policies and their targets, the default app management policy, authentication method configurations and
  delegated-permission classifications. Detect paging cycles for every Graph list, bound strict policy reads
  and remove endpoint chunks when the shared endpoint runner withholds their evidence.
- **AAD and SharePoint 2:** add private AAD Conditional Access and SharePoint rule-view variants, retried only
  for identified shape failures, plus six AAD section adapters. Pin the ScubaGear delegated risky-permission
  subset in `configs/risky-delegated-permissions.json`.
- **Teams 3:** add certificate-only Teams admin API reads through five allowlisted GETs for commercial and GCC;
  remove the unused `TeamSettings.Read.All` requirement and expose coverage reasons. REST authentication and
  response shapes remain unverified live.
- **Exchange 5:** a DKIM selector CNAME pointing at a non-existent target now walks on to selector2 as ScubaGear
  does: NXDOMAIN advances the selector walk even with CNAME data; a CNAME-only NOERROR answer still stops it.
  This RFC 6604 inference has not been observed live.
- **Value-rule performance:** make the DMARC address regex linear and replace repeated DKIM, Safe Links and
  Power Platform DLP scans with indexed joins or set operations, preserving verdicts.
- **Value-rule addendum A2:** accept SS 1.3 and SS 6.x citation variants and compare AAD 3.3v2 pack parity through
  the permitted label overrides.
- **Held Defender rules:** enable MS.SECURITYSUITE.1.1v1, 6.1v1 and 6.2v1 after the unsuccessful-command projection
  and A2 citation variants landed; deterministic rules now cover 102 policies.
- **Defender 1:** add 14 read-only Exchange Online `Get-*` commands for Defender for Office 365 and EOP policy
  evidence, with no new Graph scope. Recipient lists are minimised; paired ATP `command_error` failures after
  a healthy EOP read are reclassified as `license_required` with `licence_inferred: true`. Other failure classes stay gaps.
- **Defender 2:** project 16 Exchange/Defender list sections and the licence flag on the run path. An inferred licence refusal
  withholds the flag and dependent sections; it is not evidence of no licence.
- **Power Platform 1:** add seven run-path section adapters for Power BI and Power Platform; failed, skipped
  or truncated reads withhold evidence instead of becoming empty lists.
- **Power Platform 2:** collect Power BI tenant settings and Power Platform environments, DLP scope, tenant
  isolation and tenant settings through GET-only clients, with separate token audiences and coverage gaps on failure.
- **Power Platform 3:** add the deliberate `power-platform` preset for both optional collectors; they stay disabled
  in other presets. Document customer setup and write-capable administrative roles used read-only. Environment
  records no longer retain `display_name` or use it as a label.

- **PIM schedule start dates preserve explicit nulls.** The `privileged_roles` artefact now keeps
  `StartDateTime: null` when Graph returns `scheduleInfo.startDateTime: null`; an omitted source key
  stays omitted. This lets AAD 7.5 distinguish the rule's non-PIM signal from missing evidence.

- **PIM role policy collection (new reads, no new required scope).** The `identity_governance` collector reads the PIM role
  policies of the directory roles with two GET-only operations: `roleManagementPolicyAssignments`
  (`/policies/roleManagementPolicyAssignments`, Graph v1.0, with the `scopeId eq '/' and scopeType eq 'DirectoryRole'`
  filter the API requires and no `$top`) and `roleManagementPolicyRules` (`/policies/roleManagementPolicies/{id}/rules`
  once per distinct policy, through `$batch` when available, at most 250 policies; a rule row keeps only the fields the
  artefacts read, never the approvers' names or ids). **No new required scope:** `RoleManagement.Read.Directory`, which
  the collector already requires, covers these reads, so a registration that grants the existing set needs no change and
  is not shown as `blocked_by_scope` or asked to consent again (scope names are compared exactly).
  `RoleManagementPolicy.Read.Directory` is the least-privilege alternative for a new app registration and appears only in
  the permission notes and the documentation. PIM for Groups (`RoleManagementPolicy.Read.AzureADGroup`) is not read.
  - `normalized/governance_objects.json` gains `role_management_policy_assignment` and `role_management_policy_rule`
    records (rule keys carry the policy id, since rule ids repeat across policies). `normalized/privileged_roles.json`
    is now written, in the ScubaGear ProviderExport shape `auditex.scuba_projection` reads (one row per privileged
    directory role with `Assignments` from the role assignment schedules in the pack's `/Date(ms)/` form and the
    expiration, notification and approval `Rules`), with a `collection_status`/`complete` envelope. It is written only
    when every read behind it succeeded in full and nothing is defaulted; each row also carries the normalized `key`
    the bundle contract requires, which the projection accepts and never projects.
  - A refused policy read (403) is `blocked_permission` in the coverage ledger and a `collection_gaps` record
    (`read_failed`, with the error class); an HTTP 404 on the assignment list (or Graph's 400 "Resource not found for the
    segment") is a gap with the new reason `endpoint_unavailable`. Either leaves no artefact, so `privileged_roles` is `missing_artifact`, never an empty list,
    and the failure is listed under `ignored_failures` for the sections that do not read it. A licence refusal is a
    licence-gated section like the PIM schedules; when every failed rule read was a licence refusal, the derived
    `roleManagementPolicyRulesFanout` row carries `license_required` too, so the collector reads as licence-limited and not
    as incomplete evidence. A policy id is percent-encoded as a path segment.
  - When every read succeeded and the artefact is withheld all the same (an empty policy assignment list, a privileged role
    without a policy, with a conflicting pair of policies, with no rules or with no exportable rule, an unreadable rule or an
    unreadable schedule), `collection_gaps` gains one record `identity_governance.privileged_roles` with the new reason
    `artefact_withheld` and `reasons` (for example `role_without_policy:<role definition id>`). The collector stays `ok`, the
    projection still reports `missing_artifact` and lists the gap under `ignored_failures`.
  - Inference to confirm on a live tenant before the shape gate opens: `Assignments` come from `roleAssignmentSchedules`,
    which also lists administrative-unit scoped schedules (copied without their scope), whereas ScubaGear may read the
    schedule instances.
  - The demo carries the policies of the roles its schedules name (five policies, 85 rules), and its twin is regenerated.
    The demo bundle now writes `privileged_roles.json` (four roles), but the section is still withheld: the whole-shape
    gate of the frozen v7 pack holds no expiration rule without `NotificationRecipients` and `Setting` and no approval rule without
    `IsExpirationRequired`, `MaximumDuration` and `NotificationRecipients`, which Graph does not return (the pack has no null or empty
    form to stand in, and the rows are ScubaGear Rego test inputs, not exporter output; nothing is padded), so the status moves from `missing_artifact` to `incomplete_shape` (detail `unseen_shape`). The demo now
    projects five sections; all 102 policies receive value-rule answers.
    Notification recipients are e-mail addresses, collected as evidence and masked in local prompt exports;
    legacy `--no-redaction` is ignored and assessment calls no model endpoint.

### Historical model and serving parity (superseded by rule-only assessment)

- **One model catalogued for development.** `configs/model-sources.json` (catalogue `schema_version` `2026-10-30`) gains
  the `product_model` entry `auditex-ministral3-8b-scuba-v10`: Ministral 3 8B Instruct 2512 (BF16 base at
  `f6fae979...`) with LoRA checkpoint-500 trained on oracle pack v10, merged and quantised Q5_K_M with llama.cpp
  `620d2225...` (`model-Q5_K_M.gguf`, 6,058,747,104 bytes, sha256 `840fb447...`, two `split` parts with their
  hashes), the adapter archive and weights hashes, training pack and card, the validated serving flags and request, four scores with their
  definitions (product 419/435, model alone 403/435, twin-free 282/298, per-policy 89.1 %), the known weak classes, a
  licence (Apache-2.0, read on the base model card; see "Adapter hash pairing and licence" below) and its availability (public Hugging Face repository
  `magrathean-uk/auditex-ministral3-8b-scuba-v10-GGUF` pending upload, `revision` null until then). The catalogue's
  `inference_executed`, `training_executed` and `external_execution` flags are now true. `auditex model sources`
  validates the catalogue and fails closed: unique ids, 64-hex hashes, 40-hex revisions for every other entry,
  exactly one product model with all required keys, parts that sum to the artefact, scores as counts or rates.
- **Adapter hash pairing and licence.** The catalogue's `adapter` block pinned the archive name
  `results-round5-adapter-ministral3-8b-20261030T0250Z.tar` with the hash of the weights file inside it. `sha256` is now
  the archive's (`40db5b31...`) and the new required `weights_file` (`adapter_model.safetensors`) and `weights_sha256`
  (`b477f2b6...`) pin the checkpoint-500 weights; `auditex model sources` fails closed on a missing or malformed weights
  hash and on identical archive and weights hashes (the error names both fields). Catalogue `schema_version` stays
  `2026-10-30` (the entry has never been released). The base model's licence was read on its Hugging Face card at the
  pinned revision on 31 October 2026: Apache-2.0. The catalogue now records the merged and quantised weights as
  distributed under Apache-2.0 as a modified work, with the training labels CC0 1.0; the licence is no longer "to be
  verified". The Hugging Face upload is still pending.
- **Historical serving protocol (superseded by rule-only assessment above).** Requests send `cache_prompt: false` (a 400 rejecting it
  is negotiated away like `response_format`). A reply lost in transit (connection error, timeout, cut-short, empty
  or non-JSON body, no chat-completion choice or assistant text) is now retried once after a 2 s pause and, if lost
  again, recorded as `unknown` with the new reason `model_transport_failed` and no response hash, instead of
  `model_response_invalid` with the hash of an empty answer (the P5 real-tenant relay drops) or a single-attempt
  `model_endpoint_unavailable`. That reason now means an HTTP error status or an oversized reply, not retried.
  Model rows (and shadows) record `finish_reason`. Schema `2026-10-29` is extended in place, additively: the new
  reason and limitation, the optional `finish_reason` (rejected on rule and skipped rows) and `attempts` up to 5.
- **Review fix-ups.** The product entry's `serving` now separates `benchmark_protocol` (the recorded G4 benchmark
  manifest's request verbatim, `max_tokens` 512, `seed` 42, `top_k` 1, no `response_format`) from
  `production_request` (what the parked development client sends, `max_tokens` 1024 and `response_format` `json_object`;
  a test pins it to the client's payload), with `protocol_difference` stating that production parity was checked
  only on the two P5 bundles. Catalogue validation is stricter: required fields must be non-empty and well typed,
  nested `base`, `adapter`, `conversion`, `training`, `serving` and `parts` contracts are checked, part sizes must
  be positive with unique names, and a malformed score (`scores: [null]`) is a clean `Model command failed` exit 2
  instead of a traceback. Assistant text holding a lone surrogate (a JSON `\ud800` escape) no longer aborts the
  assessment: it is hashed with `surrogatepass` and retried as `model_response_invalid`. The envelope gains the
  optional `serving` record (`cache_prompt` `disabled`/`server_default`, `response_format` `json_object`/`not_sent`),
  additive within schema `2026-10-29`, so a server that rejected `cache_prompt: false` is visible as a departure
  from the measured protocol. The memory guidance is an estimate (about 7.5 to 8 GB free); laptop suitability is
  unverified.
  Evidence text containing a lone surrogate (a JSON `\ud800` escape) is refused by the projection's typed field checks
  (the section withholds as an invalid type), and the serving client hashes prompts and encodes request bodies with
  `surrogatepass` as defence in depth, so such a value records a row instead of aborting the assessment.
- **Historical operator chapter (superseded by rule-only assessment above).** `docs/guides/ai-assessment.md`: historical rule and model behaviour (four rule classes, scope
  post-check, shadow mode), obtaining and verifying the model, serving it with `llama-server`, memory needs, running
  and reading the assessment, the measured accuracy with its caveats and the January 2027 re-pick. README, index,
  product manual, model-development guide, output contract and provenance notes point to it.

### Historical model serving (removed from product assessment)

The following notes record superseded development stages. Current assessment answers all 102 policies
with value rules. The model is parked, shadow mode is removed,
legacy model options are ignored, and projection is implemented. Historical file contracts remain readable.

- **`scuba_config` is synthesised, no longer withheld.** The 19 policies that read ScubaGear's operator
  configuration were answered unknown by rule on every real tenant. `auditex model assess` now synthesises the
  section from ScubaGear's default configuration, the tenant's cloud (`dns_posture` OpenID discovery, else US
  Government licence SKUs, else `commercial`) and the run's `--break-glass-accounts` list (resolved to object IDs and
  placed under the `Aad[...]` entry each policy's Rego reads, which for MS.AAD.3.2v2 is `MS.AAD.3.2v1`, a shape the frozen training data never held, so that policy is withheld as `unseen_shape` whenever an exclusion list exists; for the nine CapExclusions policies and MS.AAD.7.4v1), in the shape each policy family's
  training rows carry. The three SecuritySuite policies stay `not_collected` (`operator_input_required`). The
  cloud derivation fails closed: discovery or licence evidence that exists but cannot be read, an answer without cloud
  fields, a sovereign cloud or disagreeing signals withhold the environment-gated policies instead of assuming commercial. The
  projection report entry carries `synthesis` (`source: synthesised:default-config`, the cloud and its evidence,
  emergency-access counts and each reading policy's outcome); schema `2026-10-29` gains that optional field and the
  shape gate gains the 99 frozen v7 `scuba_config` shapes. On the 30 Oct 2026 P5 tenant run 16 of 102 prompts change and
  9 policies move from a rule `unknown` to the model.
- **The DNS sections say why they are missing.** `spf_records`, `dkim_records` and `dmarc_records` are reported as
  `dns_posture_not_run` or `dns_records_not_saved` instead of `missing_artifact`: the `dns_posture` collector keeps
  parsed posture only and is in no default collector set, so no run produces them yet (model-development guide).

- **Evidence projection (1.2.2.dev4).** `auditex model assess` reads saved bundle
  evidence into complete tier-1 ScubaGear shapes, with fail-closed markers and
  zero model calls for missing-section rule answers. Schema `2026-10-29` adds a
  per-section projection/provenance report, privacy counters and configurable
  bounds (40 items or 12,000 characters by default). Person names and immutable
  IDs use stable run-salted pseudonyms; e-mail local parts are masked.
  The former `--no-redaction` option required a loopback endpoint; it is now ignored. The `2026-10-28` schema is
  preserved byte-for-byte. Complete object shapes and enum domains from the frozen
  v7 packs gate every projection; unsupported CA restrictions, failed evidence and
  unseen variants withhold the whole section. The salt stays in memory. Synthetic
  demo evidence first projected two sections, with 102 rule rows and zero model rows
  (three sections, 99 rule rows and three model rows after the P2 follow-up below);
  its original SharePoint findings and explorer score of 65 are preserved.
  No collectors or network reads are added.
- **P2 projection follow-up.** Withheld `incomplete_shape` sections now identify the
  first failing field and failure kind, with only safe enum values in diagnostics.
  The optional detail extends schema `2026-10-29` without a version bump. Known
  Graph default-role security-group creation and user-read settings are accepted
  and dropped; other unexpected permissions and unseen pack enums, including
  `allowInvitesFrom=everyone`, still withhold the section.
  - Collection health reads `status` only from collector metadata (operation, normalised
    and coverage envelopes). A Graph record's own `status`, such as a role schedule's
    `Provisioned`, is data and no longer withholds the privileged sections as an unseen
    enum; failed envelopes and the other failure markers still do.
  - **Projection budget and scan bounds.** `--projection-max-items` (40) and
    `--projection-max-chars` (12,000) now budget the projected section, not the source read
    to build it: a tenant with thousands of users still projects `privileged_users` when only
    a handful are administrators. Source reads have their own safety bounds, `scan_max_rows`
    (250,000), `scan_max_bytes` (256 MiB) and `scan_max_chunks` (10,000), set with
    `--projection-scan-max-rows`, `--projection-scan-max-bytes` and
    `--projection-scan-max-chunks`; exhausting one withholds the section as `oversize` with
    detail kind `scan_bound` and the bound's name. `privileged_users` reads the effective
    admin set first and streams `identity.users` keeping only the administrators' rows;
    `service_plans` streams the SKU list and keeps the distinct plans. The section report gains
    an optional `scan` (rows, bytes, chunks) and `bounds` the three scan bounds. Optional
    schema additions only; `2026-10-29` is unchanged and earlier assessments still validate.
  - **Collection health per operation.** A section withholds only for a failure of an operation
    it reads, of the collector as a whole, or of its coverage-ledger, coverage and collection-gap
    rows. A failure of another operation of the same collector (for example `identity.userSignInActivity`
    refused with `license_required`, which no adapter reads) is listed in the section report's
    optional `ignored_failures` and no longer withholds `privileged_users`, `tenant_id` or the
    other sections. A failure that cannot be attributed to such an operation still withholds.
  - The synthetic demo now projects three sections (`service_plans`, `tenant_id`, `privileged_users`):
    99 rule rows and three model rows (`MS.AAD.7.1v1` to `MS.AAD.7.3v1`), where the earlier count
    was two sections, 102 rule rows and none.
- **P5 projection robustness (real-tenant runs of 2026-10-30).** Field presence depends on the token, not the tenant
  (a delegated token returns `servicePlans[].servicePlanType`, the Azure CLI one does not), so an extra Graph field no
  longer withholds a section: every adapter projects the fields the training shape knows and records the rest in the
  section report's optional `ignored_fields` (sorted field paths, names only; a key that is not an identifier is
  masked as `unrecognisedField`). Unseen enum values, wrong types and missing fields still withhold, and the projected
  object still passes the unchanged frozen shape gate. Conditional Access keeps one exception: a known restriction, or a
  populated unknown field inside `conditions` or `grantControls`, can narrow the policy and still withholds.
  - **A failed read names its cause.** The collector's failure marker (`error`, `error_class`) in an operation envelope,
    a coverage row, a ledger diagnostic or a collection gap now withholds with reason `collector_error` and `detail`
    `{error_class, operation}` (the collector's class, `unclassified` outside its vocabulary; never the message), in
    place of `incomplete_shape` / `unseen_shape` on field `error`.
  - **No Entra ID P2.** A PIM schedule read refused with `license_required` and empty no longer withholds
    `privileged_users`: the admin set comes from the directory role assignments, as the effective admin set already
    records, and the refused reads are listed in `ignored_failures`. Any other refusal still withholds.
    `privileged_roles` stays withheld (`collector_error`, `license_required`): every frozen shape carries PIM rules.
  - `privileged_users` takes `onPremisesImmutableId` from `domains_hybrid.syncSampleUsers` when the identity user read
    does not select it; an administrator neither read holds withholds as before. A failed privileged-group fan-out is
    attributed to its operation, so it no longer withholds `tenant_id`.
  - The synthetic demo projects `accepted_domains` too (five sections; totals unchanged). Schema `2026-10-29` gains the
    optional `ignored_fields`, the reason `collector_error` and its detail (the assessment validator learns `anyOf`).
  - **Qualifiers withhold (review round 2).** Where an extra field can scope or qualify a kept one, only an empty or
    demonstrably harmless value is ignored; a populated one withholds as `incomplete_shape`, `detail`
    `{field, kind: unexpected_field}`. `privileged_roles`: an administrative-unit `Assignments.DirectoryScopeId`, any
    `AppScopeId`, `MemberType`, `Status`, a rule `Target` that says more than the rule id, `NotificationLevel`, approval
    stages or any unknown populated field withholds, so a scoped assignment is never read as tenant-wide (`/`, a
    matching role id, a `Target` restating the id and identity metadata are ignored and reported). `privileged_users`:
    a role an administrator holds only below directory scope `/` withholds (`roles.scope`).
  - **`service_plans` keeps only provisioned plans**, as ScubaGear's exporter does (`provisioningStatus` `Success`); a
    disabled or pending plan was projected as one the tenant has. A tenant with none projects an empty list.
  - **Error classes are vocabulary-checked.** One allowlist (`COLLECTOR_ERROR_CLASSES`, plus `graph_http_<status>`),
    shared by the projection and the validator, replaces the lower-case-token check: `alice_smith` reads
    `unclassified`, and the validator rejects an unknown class. A test keeps the list in step with every class literal
    the engine writes.
  - **Every ignored source field is recorded.** The SharePoint settings row, the top-level authorization policy, each SKU
    row, each administrator's user row and the Conditional Access policy metadata (`id`, `createdDateTime`) now list
    their unprojected fields; only OData annotations are excluded, at any depth (`authenticationStrength@odata.context`
    no longer withholds a policy).
  - Projection budgets: a tenant whose admin set exceeds the item budget (one real administrator holds 88 roles)
    withholds `privileged_users` as `oversize`; there is no operator action today, and the budget is unchanged.
- **Field-level absence pre-check (`absent_field`).** `configs/scuba-rule-precheck.json` gains
  `field_rules`: 18 (policy, section, field) tuples whose Rego-read field (v10 leakage report, `rego_ast_field_reads`)
  is missing inside a collected section, registered only where every v10 row the rule would answer is labelled
  unknown (69 rows across train, validation and test, 100 %). Ten SharePoint `SPO_tenant` fields and the eight Power BI
  policies' own `[settingName=...]` entry (with licence found and access not denied). Precedence is closed gate,
  `absent_section`, then `absent_field`; the answer is unknown with `required_evidence_section_not_collected` and
  `collect_missing_evidence_section`, as in the labels. Serving emits it (`precheck_case(..., absent_fields=True)`), the
  assessment schema's `rule_precheck.class` enum and `validate_assessment` accept it (the rule must be a registered field
  rule of the row's policy, naming its section and field, with a null value). `scripts/score-model-precheck.py --absent-fields` scores it; frozen
  v10 test rule rows 167 to 172 (all correct), G4 8B Q5_K_M combined score 417 to 419/435.
- **Empty Conditional Access list pre-check (`empty_required_list`).** `configs/scuba-rule-precheck.json` gains
  `list_rules`: ten AAD policies (1.1, 2.1, 2.3, 3.1, 3.2v2, 3.6, 3.7, 3.8, 3.9, 9.1) that pass only when some
  Conditional Access policy satisfies them, so a collected, exactly empty `conditional_access_policies` list is
  answered not met (confirmed false citing every section, no limitation, `review_policy_against_baseline_text`) without
  the model. Every v10 row it would answer is labelled so (7 rows across train, validation and test, 100 %), and the
  pinned Rego (ScubaGear 2446ad7, OPA 1.20.2) returns not met for all ten over 20 environment, licence and
  Authenticator variants; 2.1, 3.6 and 3.9 have no v10 row of their own and rest on that probe. MS.AAD.3.3v2 is not
  registered (met through the Authenticator configuration alone); MS.AAD.9.1v1 is left to the model in `gcchigh` and
  `dod`, where ScubaGear reports it not applicable. Precedence: closed gate, `absent_section`, `absent_field`, then this
  class. Served by default; the schema enum and `validate_assessment` accept it (a registered list rule of the row's
  policy, its section only, null field and value). `scripts/score-model-precheck.py --empty-lists` scores it; frozen v10
  test rule rows 172 to 173 (all correct; the one new row was already a model pass), combined score unchanged at 419/435.
  On the P5 tenant (no Conditional Access policy) nine prompts move to the rule, including the wrong `met` verdicts for
  MS.AAD.1.1v1 and MS.AAD.3.9v1 and the two invalid answers for 3.1 and 9.1.
- **Scope post-check.** ScubaGear's Rego ignores the location, platform, device-filter, client-application
  (and, for most policies, client-application-type) conditions of a Conditional Access policy, and the grant
  operator of several, so the oracle labels the specialist model is trained on give a clean pass to a policy
  applied to one office. `auditex model assess` now marks a met row of MS.AAD.1.1v1, 2.1v1, 2.3v1, 3.1v1, 3.2v2,
  3.6v1, 3.7v1, 3.8v1, 3.9v1 or 9.1v1 `scope_narrowed` when an enabled policy that could have decided it carries
  such a condition and no compliant unscoped policy could have decided it as well (report-only and disabled
  policies never count; an `OR` operator counts only for the policies whose operator the Rego ignores, and only when
  the grant offers a control the item does not accept). A policy could have decided an item only when it carries
  every check the Rego makes of a deciding policy: all users and all applications included and no role excluded
  where the Rego reads them, both legacy client types for 1.1v1, a phishing-resistant-only authentication strength
  for 3.1v1 and 3.6v1, the exact transfer method for 3.9v1, the risk level, user action or device controls; the
  table cites the Rego line of each, and exclusions (which the ScubaGear allow-list may permit) never drop a
  policy. The verdict, claims and comparison are unchanged; the row gains `post_check` (policies, condition paths,
  count) and the limitation `scope_narrowed`, and `totals.scope_narrowed` counts them. The envelope gains
  `scope_post_check`, which lists the scoped policies whatever the verdicts, for a condition only when the policy could
  have decided an item that ignores it, and reads the bundle's raw `conditional_access` payload (through the
  projection's bounded reader) when the projection withheld the section for a scope key. Reach today: the projection
  withholds a Conditional Access section that carries a location, platform, device or service-principal key, so a
  row can currently be marked only for a client-application-type set, a named agent principal or an `OR` grant; the
  location, platform and device checks reach the envelope record now and the rows once the projection reads those
  fields. The table is `configs/scuba-scope-blind.json`, taken from the v9 dataset card and the pinned Rego. Optional
  additions to schema `2026-10-29` only; earlier assessments still validate, prompts and the limitation catalogue are
  untouched, and no report or explorer surface renders assessment rows, so the "met per ScubaGear, scope narrowed"
  wording is specified for renderers in the output contract. On the synthetic demo the raw payload is read and no
  enabled policy is scoped (count 0).
- **Historical deterministic pre-checks (1.2.2.dev3; model and shadow routes now removed).** A shared, shipped SCuBA rule catalogue answers closed
  applicability gates as inferred true and unavailable inputs as unknown before inference, citing all
  blockers, including the Power BI licence flag alongside missing tenant settings. Oracle generation
  uses the same gates and citation selection and rejects contradictory evaluated verdicts while retaining
  justified missing-input overrides. At that stage `--shadow-model-on-precheck` recorded the model result
  without changing the rule verdict; the flag is now ignored. `model_assessment` schema `2026-10-28` adds pre-check records, shadow results and totals;
  the older assessment schemas remain available. `scripts/score-model-precheck.py` scores pre-checks against
  frozen packs and can combine them with recorded model responses for the remaining cases.
  - A present, usable closed gate now takes precedence over absent dependent evidence, matching
    the training prompt: inferred true, exactly `policy_not_applicable`, no recommendations.
    Missing or unusable gate inputs and other missing dependencies remain unknown when no gate
    is visibly closed; serving and oracle generation share this order. Version stays `1.2.2.dev3`.
- **`auditex model assess <run-dir>`** writes `model_assessment.json` into a finalised run bundle: one row per
  shipped CISA SCuBA policy with the model's claims, limitations and recommendations, validation status,
  attempts, latency, prompt and response hashes, and a comparison with the rule-based `baseline_alignment`
  status of `reports/report-pack.json` (`agree`, `disagree`, `not_assessed`; `baseline_match` records an exact
  or version-suffix match). The model never changes findings, reports or the gate; a malformed or outdated
  assessment file is a validation warning, not an error. `--dry-run` writes the assembled prompts to
  `model_assessment_prompts.jsonl` without calling any endpoint; `--policies` restricts the set.
- **`auditex model doctor`** checks the endpoint (`GET /models`), the served model name and prints the
  configuration without the key.
- **Transport.** `auditex.model_serving` is a standard-library client for any OpenAI-compatible
  chat-completions server (llama.cpp, Ollama, LM Studio, vLLM): `AUDITEX_MODEL_ENDPOINT` (default
  `http://127.0.0.1:8080/v1`), `AUDITEX_MODEL_NAME`, `AUDITEX_MODEL_API_KEY`, `AUDITEX_MODEL_TIMEOUT`
  (seconds, per socket read). Temperature 0, 1,024 max tokens, `response_format` JSON with fallback on HTTP 400,
  `chat_template_kwargs.enable_thinking=false` with the same fallback, a leading `<think>` block stripped and
  recorded, one retry on an invalid answer, then every claim becomes `unknown` with limitation
  `model_response_invalid`. A non-loopback endpoint prints one warning that evidence leaves the machine and the
  host is recorded; an API key over plain HTTP to a non-loopback host is refused unless
  `AUDITEX_MODEL_ALLOW_INSECURE=1`.
- **Prompt fidelity.** `auditex.model_prompt` reproduces the `named-enums-v1` training serialisation byte for byte
  (pinned system prompt with its SHA-256, sorted compact JSON, policy item as trained, not-collected sections as
  `{"collection_status": "not_collected"}` from `azure_tenant_audit.model_evidence.NOT_COLLECTED`, shared with
  `scripts/build-oracle-cases.py`). `configs/scuba-policy-sections.json` carries the 102 policies with their
  dependent ScubaGear sections, criticality, baseline text and applicability (CISA ScubaGear CC0, Microsoft
  CC BY 4.0; see provenance). A 56-row fixture across all seven products asserts byte equality.
- **Original evidence projection.** `auditex.scuba_projection.project_run` was initially a stub returning no
  sections, so every dependency was reported as not collected. Projection from saved evidence was implemented
  in later stages; current assessment uses the separate in-memory rule view.
- **Validator.** The shared response validator (`auditex.model_eval`) now rejects a met or not-met verdict while any
  dependent section is not collected (the inferred not-applicable answer excepted) and contradictory
  limitation/recommendation sets; `evaluate` and `combine` outputs for the shipped fixtures are unchanged.
- **Contract.** `schemas/model_assessment.schema.json` is shipped; `CONTRACT_VERSION` stays `2026-10-22` because
  the artefact is optional and nothing existing changes.

### Internal

- Remove engine-to-product imports using an engine-owned provider registry and shared public auth readers; preserve product metadata and keep the engine usable on its own.

### Model development

- **Ministral 3 bases.** Training and checkpoint scoring load only the `mistral3`
  text backbone alongside `qwen3_5`, remap its language-model weights and reject
  unexpected non-vision weights. A shared tokenizer loader applies the Mistral
  regex fix only to `mistral3` snapshots and records it in runtime reports.
- **Named enums in oracle evidence.** `azure_tenant_audit.external_sharing.annotate_enum_names(section, observed)`
  adds `<Key>_name` beside the seven SharePoint integer enums of a `SPO_tenant` evidence item
  (`SharingCapability` and `ODBSharingCapability` as `<apiName> (<admin-centre label>)`, `DefaultSharingLinkType`,
  `DefaultLinkPermission`, `SharingDomainRestrictionMode`, `FileAnonymousLinkType`, `FolderAnonymousLinkType`);
  an unrecognised integer gets no name. `scripts/build-oracle-cases.py` applies it when the evidence is rendered
  (case ids hash the raw view and do not change) and records `provenance.prompt_convention: named-enums-v1`;
  `scripts/annotate-oracle-cases.py` applies the same rendering to an existing case file and recomputes (or adds)
  `distinct_prompt_sha256`. The v6 adapter answered SharePoint 3.x applicability rows from a shortcut because no
  prompt named the sharing slider values.
- **Oracle pack v9 generators.** `scripts/build-oracle-cases.py` gains the opt-in `v9_variants` API: enum sweeps of the
  finite SharePoint (`DefaultSharingLinkType`, `DefaultLinkPermission`, the anonymous-link types,
  `SharingDomainRestrictionMode`, `ODBSharingCapability`) and authorization-policy (`AllowInvitesFrom`, `GuestUserRoleId`)
  domains on clean base tenants, Graph `AuthenticationStrength` objects for every combination class the Rego tells apart,
  location, platform, device, client-application and finite-enum conditions on the single-purpose Conditional Access
  policies (also on a disabled one), and the MS.AAD.3.3v2 phishing-resistant applicability branch; `assign_v9_splits` keeps
  new templates out of test and every swept value in train. The default miner output and the v7 parity are unchanged.
  `scripts/derive-scuba-projection-shapes.py` is now the single derivation of the projection shape goldens (reproducing the
  v7 fixture; the fixture and the shipped gate are untouched). No version bump.
- **Oracle pack v10 generators.** `scripts/build-oracle-cases.py` gains the opt-in `v10_variants` API for the families
  whose train rows held one class only after round 4: MS.EXO.7.1v1 transport rule sets with a working warning rule among
  decoys, Teams app permission policies with org-wide app settings labelled for MS.TEAMS.5.1v2, 5.2v2 and 5.3v2 together,
  MS.SECURITYSUITE.8.2v1 connection filters and MS.POWERBI.7.1v1 setting lists, each with failing twins. Every variant
  declares the label it expects and the miner stops when OPA disagrees. `v10_near_key` abstracts names, wording, addresses,
  order and repetition; `v10_strict_key` first removes the fields the policy's Rego does not read (`v10_sound_reads` keeps a
  section whole where the Rego-AST reads would mix labels); `assign_v10_splits` keeps each key in one split (an existing
  row's split pins it) and splits the groups about 85/15 within policy and outcome, never into test. The default miner
  output and the v7 parity are unchanged. No version bump.
- **Provenance key.** `validate_case` accepts `prompt_convention` (only `named-enums-v1`); a 1.2.1 wheel rejects
  every row that carries it, so a pack built with this convention needs this version on the cluster.
- **Checkpoint scorer.** `scripts/score-adapter-checkpoints.py` counts an expected-`unknown` claim answered
  `inferred` as overconfidence (it counted `confirmed` only; the v6 figure was 3/80, the true one 5/80), writes a
  per-model `per_policy` table into `evaluation.json` (policy id of the case, family when there is none) and reports
  `per_policy_mean` and `per_policy_count` in `selection.json`. Rule `2026-10-27` counts confirmed/inferred status
  swaps in both directions on the `requirement_met` policy-gate claim as `applicability_errors`, with a rate over
  expected confirmed/inferred `requirement_met` claims, and
  selects within a strict-pass noise band of `max(1, ceil(1.96 * sqrt(N * p * (1 - p))))` by lowest applicability
  errors, highest strict pass count, lowest overconfidence and over-abstention, then earliest step and name. It records
  the band width, member names, best strict pass count and previous strict-first winner, and warns when the
  winner changes. The base floor makes trained checkpoints eligible only when they strictly beat the base
  (step 0 / `checkpoint-0`); otherwise the base wins. Selection schema `2026-10-27` records
  `base_strict_pass_count` and `base_floor_applied`. `ranking` and `checkpoints` are ordered band-first, so
  neither is necessarily monotone in strict pass count; `tied_with` also requires equal applicability errors.
  Earlier `selection.json` overconfidence values are not comparable with new ones.
- **Splitter sub-families and frozen ids.** `scripts/split-oracle-cases.py` takes `--sub-family <policy>=<family>`
  (relabels one policy's rows to a family named `<source family>-...`, so a policy can be sent to validation on its
  own with `--validation-families`) and `--previous-report <split-report.json>`, which refuses any change to the
  test ids (`test_ids_sha256`) or to the split of a family not named on the command line; `--sub-family`
  requires `--previous-report`. The report records `sub_families`, `test_ids_frozen`, `family_split_changes`
  and whether the test content (`test_sha256`) is unchanged.

## [1.2.4] - 2026-11-06

### Security

Packaging fix for the 1.2.2 and 1.2.3 security releases. The v1.2.1, v1.2.2 and v1.2.3 tags
tracked a stale `build/` tree from 1.2.0, so a wheel built in the source tree (for example
`pip install` of a GitHub source archive, or `pip wheel .` in an extracted archive) could install
the 1.2.0 code: for 1.2.2 and 1.2.3 that meant without the argv redaction fixes. Editable installs
and builds through `python -m build` were not affected. 1.2.4 ships the 1.2.3 code with `build/`
removed and ignored.

If you installed 1.2.2 or 1.2.3 from a source archive and passed a secret through an abbreviated
flag, rotate that secret, delete or rebuild the affected run bundles, and upgrade to 1.2.4.

## [1.2.3] - 2026-11-05

### Security

The standalone lab bootstrap kit (`tenant-bootstrap/`) carries its own copy of the command-line
handling. Like the main tool, it accepted abbreviated options and redacted only exact flag names,
so a secret supplied through an abbreviated flag was recorded in clear in the run manifest it
wrote. That copy now rejects abbreviated options and redacts through the shared logic, with a
self-contained fallback when the shared helper is unavailable. The shared redaction defence also
treats an option as sensitive when it is a prefix of any sensitive flag, including an ambiguous
prefix. Options must be spelled in full.

The lab-kit copy is affected in every checked release: v0.9, v1.0.0, release-2026-04-29,
release-2026-05-06, v1.1.0, v1.2.0, v1.2.1 and v1.2.2. The first affected release was v0.9;
releases through 1.2.2 are affected.

Rotate any secret passed through an abbreviated flag to the lab bootstrap kit, delete or rebuild
affected run bundles, and upgrade to 1.2.3. Contact contact+auditex@magrathean.uk for help.

## [1.2.2] - 2026-11-05

### Security

A secret supplied through an abbreviated command-line flag, such as `--client-sec` or
`--access-tok`, was recorded in clear in the `command_line` field of `run-manifest.json`, probe
and response manifests, Google run manifests and customer-pack copies, and in the audit logs
`audit-log.jsonl` and `audit-debug.log`. Values supplied through full flag names were always
redacted. Parsers now reject abbreviated options with exit status 2 before a run bundle or audit
log is created. The standalone lab bootstrap kit copy of the command-line handling was fixed in 1.2.3.

The first affected release was v0.9; releases through 1.2.1 are affected. Google manifest recording
was added later and is present in the checked releases 1.1.0, 1.2.0 and 1.2.1.

Rotate any client secret, access token or certificate password supplied through an abbreviated
flag, delete or rebuild affected run bundles and customer packs, and upgrade to 1.2.2. Contact
contact+auditex@magrathean.uk for help.

## [1.2.1] - 2026-10-25

Model-development tooling only. `CONTRACT_VERSION` stays `2026-10-22`, and the audit, report, export and
MCP surfaces are unchanged.

### Model development

- **Single-purpose Conditional Access oracle bases.** `scripts/build-oracle-cases.py` takes `--ca-bases`
  (default `single-purpose`; `combined` is the earlier behaviour and reproduces its AAD cases byte for
  byte). ScubaGear's unit-test base policy ANDs block, a phishing-resistant strength, user and sign-in
  risk, legacy-only client apps and a user action, so a `met` label mined from it fails the baseline text
  under Entra's AND semantics. The default drops those `met` cases and adds cases from one single-purpose
  policy for each of MS.AAD.1.1, 2.1, 2.3, 3.1, 3.2, 3.6, 3.7, 3.8 and 3.9, with ids salted `conv3-sp`.
  Each variant's label is ScubaGear's own Rego verdict, and the run fails if the verdict disagrees with the
  intent the baseline text implies.
- **Provenance keys.** Oracle case provenance accepts `consensus_weight` (only `scubagear_only`) and
  `adjudication` (`source` and `ruling`). `validate_case` and `validate_training_pack` in 1.2.0 reject a
  training pack that carries either, which blocked a pack built with the new miner.
- **MS.AAD.3.6v1 role exclusion.** The `exclude_privileged_role` variant now excludes the first of the
  base input's own privileged roles. Before, it excluded the real Global Administrator template id while
  the fixture names its roles `Role1` and `Role2`, so the evidence contradicted itself. One case id
  changes. The comment on `not_decoys` now says why MS.AAD.3.7v1's policy is kept out of the 3.8 decoys: an
  All-cloud-apps policy does not cover the register-security-info user action in Entra, so it does not
  satisfy 3.8, and the `not_met` label of `all_applications_instead_of_action` stands.
- **Tests.** An oracle test mines AAD with `--ca-bases combined` and asserts no `conv3-sp` id, a stable
  digest of the cases and, when `AUDITEX_TEST_ORACLE_V4_AAD` names a stored v4 `cases-aad.jsonl`, a byte
  comparison with it. Two more tests assert that the 3.6 excluded role is one of the fixture's privileged
  roles.

## [1.2.0] - 2026-10-23

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

### Microsoft 365 administrators

- **Effective administrator set.** A new normalized section, `effective_admin_set`, resolves who holds an
  administrator role once for every rule: one row per principal, by every route (direct active, PIM-eligible,
  and inherited through a role-assignable group, nested groups included), with the roles and where each comes
  from, the scope, a guest flag and licence flags (an Exchange Online mailbox or a productivity licence).
  Only users are counted; groups and service principals that hold a role are listed with `counted: false`.
  The set is `complete` only when role definitions, role assignments, both PIM schedule lists and the group
  fan-out were read in full, otherwise `unknown` with the reasons. A PIM schedule read refused with
  `license_required` counts as no schedules; a skipped `identity_governance` collector does not. Every
  `identity.global_admin_*` rule, `identity.privileged_mfa_not_registered`,
  `identity.privileged_stale_account` and the `attack_path.no_mfa_to_tier0` check read it. These rules used to
  see only direct active assignments, so a PIM tenant with one permanent and three eligible Global
  Administrators got a false "only one Global Administrator", and eligible or group-inherited administrators
  were never checked for MFA, a disabled account or a stale password.
- **Unknown set.** When the set is `unknown`, `identity.global_admin_singleton` stays silent (a count of one
  proves nothing), the new diagnostic `identity.admin_set_unverified` is raised, and baseline alignment reads
  every rule that depends on the set as `not_assessed` (`admin_set_unknown:<reasons>`), never `pass`.
- **Global Administrator count.** `identity.global_admin_sprawl` is now raised above four (it was above five,
  against text that said two to five), and each finding carries `framework_thresholds`: CIS `1.1.3` allows two
  to four, SCuBA `MS.AAD.7.1v1` two to eight. Five to eight Global Administrators give a `low` finding that fails
  CIS `1.1.3` while SCuBA `MS.AAD.7.1v1` still reads `pass`; nine or more give a `medium` finding that fails
  both. `identity.global_admin_singleton` carries the same list for the minimum. Groups and service principals
  no longer count towards either rule. The bounds are in `_rule_thresholds` in `configs/control-mappings.json`.
- **Mappings.** `MS.AAD.7.2v1` is no longer mapped to `identity.global_admin_sprawl`: it is a ratio of Global
  Administrators to other highly privileged users, which a count cannot establish. CIS `1.1.4` ("administrative
  accounts use licenses with a reduced application footprint") is added to the framework catalog.
- **New rules.** `identity.admin_holds_productivity_licence` (an administrator with a mailbox or productivity
  licence; CIS `1.1.4`, and partial evidence for the Cyber Essentials requirement `ce.uac.separate_admin_accounts`),
  `identity.stale_guest` (no successful sign-in for 90 days, or `AUDITEX_STALE_GUEST_DAYS`; a stale guest is no
  longer also reported by `identity.stale_enabled_account`), `identity.guest_with_privileged_role`, and the
  diagnostic `identity.admin_set_unverified`. The licence and stale-guest rules read `not_assessed` when licences
  or sign-in activity were not collected.
- **Default profiles.** `identity_governance` is added to the `auto` and `global-reader` profiles and to the
  `full` and `config-only` presets, so PIM schedules are read by default. The `global-reader` application
  permission hints gain `AccessReview.Read.All`, `EntitlementManagement.Read.All` and
  `RoleManagement.Read.Directory`. A profile or preset that collects `identity` without `identity_governance`
  (`identity-only`, `reports-reader`, `exchange-reader`) is unchanged and reports the set as `unknown`.
- **Comparison and gates.** `auditex compare` and the gates no longer call a finding resolved when its rule's
  inputs went unknown in the later run (an administrator set or an MFA verdict that could not be established):
  it is `not_reassessed` with `rule_inputs:<reason>`, as is a finding whose rule needs a normalized section the
  later run did not write.
- **Bundle fields.** `role_assignments` records gain `directory_scope_id` when the source returns it. The
  remediated demo twin now also removes the disabled administrator's PIM schedule.
- **Known gap and follow-up.** PIM for Groups eligible membership of a role-assignable group is not read, so a
  user who is only eligible to join such a group is not in the set. ScubaGear's `MS.AAD.7.1v1` instructions
  count them. Collecting those schedules is a follow-up.

### Microsoft 365 devices, updates and malware (Cyber Essentials)

Product review action 6: device, update and malware evidence for the Cyber Essentials requirements. Every
new read is a GET or a read-only `Get-*` cmdlet that passes the shared read guard, and no Graph scope is
added: each read uses a permission its collector already required. Every check is three-valued; a field that
is absent, `Unknown` or unparseable, a list that was cut, and a read that was blocked are unknown and read
`not_assessed` in baseline alignment, never `pass`.

- **Devices.** `intune` reads `isEncrypted`, `jailBroken`, `managedDeviceOwnerType` (the v1.0 name of the owner
  field; `ownerType` is beta only), `enrolledDateTime` and `deviceEnrollmentType` as well as `lastSyncDateTime`,
  `complianceState`, `osVersion` and `operatingSystem`. `devices` records gain `is_encrypted`, `jail_broken`,
  `owner_type`, `enrolled_at`, `enrollment_type` and `os_family`, and the new `device_posture` section counts the
  devices each check cannot judge. New rules: `intune.device_encryption_off`, `intune.device_jailbroken` (iOS and
  Android only), `intune.device_os_end_of_life`.
- **Stale sync.** `intune.device_stale_sync` now defaults to 14 days (it was 90), the Cyber Essentials window for
  installing updates, and is configurable with `--stale-sync-days` or `AUDITEX_STALE_SYNC_DAYS` (1 to 3650; an invalid
  value is ignored). A device with no last-sync time is unknown. The demo tenant is judged as of its snapshot date, so
  only its April device is stale there.
- **End of life.** `configs/os-end-of-life.json` is a dated table (`verified_on` 2026-10-22, a source for every
  entry) for Windows 10 and 11 builds, macOS, iOS and iPadOS, and Android. Windows dates are Microsoft's; Apple and
  Android publish none, so their dates are marked `derived`. A Windows build whose Home/Pro date has passed and whose
  Enterprise/Education date has not depends on the edition, which `osVersion` does not show, so it is unknown. So is a
  build that a Long-Term Servicing edition shares (LTSC 2019 on 17763, LTSC and IoT LTSC 2021 on 19044, LTSC and IoT
  LTSC 2024 on 26100): between the general date and `ltsc_end_of_support` the device is `edition_dependent`, and only
  after the Long-Term Servicing date is it past end of life. Windows Server is not a Windows client here. iOS and
  iPadOS 17 are not called end of life (Apple issued iPadOS 17.7.11 on 2026-05-11). A Windows 10 device may be
  enrolled in paid Extended Security Updates, which Auditex cannot see, so its finding is medium while that window is
  open.
- **Compliance policies.** `deviceCompliancePolicies` records keep their platform, the settings that matter
  (passcode, encryption, minimum OS, jailbreak block, Defender and firewall requirement where the policy type has
  them) and their assignments (`GET .../deviceCompliancePolicies/{id}/assignments`), in the new
  `compliance_policy_objects` section. New rule: `intune.compliance_policy_missing_platform`. This closes the
  "compliance policy evidence is too thin" finding; Graph v1.0 returns no Defender settings for a Windows policy.
- **Updates.** `intune_depth` identifies Windows Update for Business update rings from the `deviceConfigurations` list
  it already reads, reads their assignments, and reads the quality and feature update profiles and their assignments
  from Graph beta (v1.0 has no equivalent), in the new `update_management_objects` section. New rules:
  `intune_depth.update_ring_not_assigned` and `intune_depth.update_ring_deferral_excessive` (quality deferral, or
  deferral plus deadline and restart grace period, over 14 days; or paused). A tenant that manages updates through an
  assigned update profile or Configuration Manager co-management reads `not_assessed` for the first rule, not failed;
  settings catalog policies, group policy and WSUS are not read.
- **Defender antivirus.** `intune` reads `GET /deviceManagement/managedDevices/{id}/windowsProtectionState` for each
  Windows device (at most 100; beyond that a `fanout_limit` gap in `collection_gaps`). The Intune reports API is a POST export job
  and is not used. A device Intune has no state for is `not_reported`. New rules: `intune.defender_av_off`,
  `intune.defender_realtime_protection_off`, `intune.defender_signatures_stale`. New section `defender_av_objects`.
- **Exchange.** `exchange_policy` adds `Get-MalwareFilterPolicy`, `Get-TransportConfig` and `Get-DkimSigningConfig`.
  New rules: `exchange.malware_filter_weakened` (default policy has the common attachment filter or zero-hour auto
  purge off), `exchange.smtp_auth_enabled_tenant_wide`, `exchange.dkim_signing_disabled` (CIS `2.1.9`, `MS.EXO.3.1v1`;
  a domain `dns_posture.dkim_missing` already reports is left to that rule, and this rule reads `not_assessed` for it).
- **Gaps stay in their own section.** A cut Defender read (more than 100 Windows devices), one failed compliance or update
  assignment read and a failed beta update profile list no longer make the `intune` or `intune_depth` collector `partial`, which
  would have turned every Intune rule, `intune.device_noncompliant` and `intune.device_stale_sync` included, `not_assessed`.
  Their coverage rows carry `section_scoped`, the gap is listed under `collection_gaps`, and only the rules that read the
  section say so (`defender_state_truncated`, `policy_assignments_not_read_for_every_policy`). A failed or cut base list still
  makes the collector `partial`.
- **Mail rules judged on their own rows.** The three Exchange rules read `not_assessed` unless their own command rows were
  read in full, instead of waiting for the whole `exchange_policy` collector, which is partial in every app-only run
  (`Get-ProtectionAlert` needs a Security & Compliance session). `auditex compare` reassesses their findings the same way.
  CIS `2.1.9` and ScubaGear `MS.EXO.3.1v1` no longer pass on DNS evidence alone: `exchange.dkim_signing_disabled` is now
  required as well. The adapter writes Exchange enumerations as names (`ConvertTo-Json -EnumsAsStrings`, used only where
  PowerShell has the switch) and the normalizer reads `DomainType` and `DomainName` whether they arrive as names,
  integers or objects.
- **Evaluation date.** `run_offline`, `build_normalized_snapshot` and `auditex demo` take an evaluation instant (`as_of`) so
  stale sync and end of life are judged as of a fixed day. The bundled demo tenant is pinned to 3 October 2026, the day its
  fictional snapshot was taken, so its scores no longer drift with the clock (they would have moved on 2026-11-11, when
  Windows 11 23H2 Enterprise ends).
- **Detection coverage.** The `defender_alert_api` signal is `on` only when a Defender service raised an alert or a
  Defender service plan is licensed and the alerts API answers; an API that merely answers is `unknown`
  (`alerts_api_answered_no_defender_evidence`). It was `on` for any tenant whose alerts API answered. Its title is now
  "Defender alert source present".
- **Cyber Essentials.** `ce.sum.supported_software`, `ce.sum.automatic_updates`, `ce.sum.vulnerability_fixes_14_days`
  and `ce.mp.antimalware` move from `manual` or `ce_plus_assessor_test` to `partial`: a rule can fail them, and a clean
  result is `not_assessed` (`partial_requirement_no_gap_found`), never `pass`. `ce.mp.app_allow_listing` and the
  provider-responsibility rows are unchanged. The rule mappings and their confidence (all `partial`) are in
  `configs/control-mappings.json`.
- **Bundle fields.** New normalized sections `device_posture`, `compliance_policy_objects`,
  `update_management_objects` and `defender_av_objects`; `exchange_policy_objects` records gain
  `is_default`, `enable_file_filter`, `zap_enabled`, `smtp_client_auth_disabled`, `dkim_enabled`, `dkim_status`,
  `domain_type` and `default_domain`; `update_management_summary` gains `profiles_assigned` and `windows_comanaged_device_count`. `auditex compare` treats `device_posture.os_lifecycle_evaluated_on` as volatile. Two
  offline samples (`endpoint_posture_result.json`, `update_rings_missing_result.json`) join the contract smoke, and
  `docs/provenance/` records the sources of the end-of-life dates.

### Microsoft 365 false positives

Rule id changes (old to new; ids not listed are unchanged):

- `onedrive.external_sharing_enabled` keeps its rule id but is one finding for the tenant,
  `onedrive_posture:tenant:external_sharing_enabled`, instead of one `high` finding per personal site
  (`onedrive_posture:<site id>:external_sharing_enabled`). It is graded by the OneDrive sharing capability:
  anyone links `high`, new and existing guests `low`, existing guests only or off no finding. `medium` replaces
  `high` only when a site inventory shows fewer than half of the personal sites at the anyone level, which needs
  sites that carry a value of their own: a tenant value copied onto every site puts them all at the tenant's level,
  so the usual grade is `high`. The personal sites at that level are listed in the evidence (up to 50, with the
  full count).
- `ca.break_glass_exclusion_missing` keeps its rule id but is one finding for the tenant,
  `conditional_access:ca_break_glass_exclusion:tenant`, naming each policy, instead of one `high` finding per
  policy (`conditional_access:ca_break_glass_exclusion:<policy id>`). It judges enabled policies that require MFA,
  block, or require a compliant or hybrid-joined device with no MFA alternative (judged at `medium`: an emergency
  account on an unmanaged device would be refused), and that can reach the accounts; report-only policies and
  policies whose grant is a session control or a password change are no longer flagged. It takes the operator's accounts from `--break-glass-accounts` or
  `AUDITEX_BREAK_GLASS_ACCOUNTS`; without a list the accounts are inferred from names and Global Administrator
  holders (Security Administrator, Security Operator, Exchange Administrator, Intune Administrator, Global Reader and
  Privileged Role Administrator holders no longer count), and the severity is `medium` at most. `high` needs an
  operator list and a policy that can lock every administrator out.
- `teams.external_federation_open` now fires only when `AllowFederatedUsers` is true and no allow list restricts
  federation. It used to fire on `AllowFederatedUsers` or `AllowPublicUsers`, which are commonly on by default. The collector
  selects `AllowedDomains` and `BlockedDomains`; a bundle that does not carry the allow list, or carries an empty or
  unrecognised one, raises nothing and reads `not_assessed` (`federation_allow_list_not_read`), and an
  `AllowFederatedUsers` that is not a boolean reads `federation_setting_not_read`. An allow list object with no
  domains is an allow list (federation with none), not open federation.
- `intune_depth.policies_without_assignments` (the rule behind the earlier `intune.intune_policies_without_assignments`
  false positive) now also stays silent when the assignment read stopped at the fan-out limit
  (`policy_assignments_not_read_for_every_policy`). It counts device configuration profiles from `intune_depth`
  only and needs both reads in full, as before.
- New rules, graded against what each benchmark accepts (ScubaGear v1.8.0 `SharepointConfig.rego` for SCuBA), each
  finding carrying `framework_thresholds` so that a control fails only where its benchmark does:
  `sharepoint.external_sharing_broad` (CIS `7.2.3`, SCuBA `MS.SHAREPOINT.1.1v1`: anyone links `high`, or `medium`
  when expiring view-only links were read; new and existing guests `low`, which fails SCuBA but not CIS),
  `sharepoint.sharing_domains_unrestricted` (CIS `7.2.6`, `MS.SHAREPOINT.1.3v1`: no list `medium` or `low`; a block
  list `low`, which fails SCuBA, whose requirement is an allow list, but not CIS) and
  `sharepoint.default_link_type_broad` (CIS `7.2.7`, `MS.SHAREPOINT.2.1v1`: anything but specific people fails both;
  anyone `high`, organisation-wide or no default `low`). The findings are `sharepoint_tenant:<rule suffix>`. Microsoft
  Graph returns the sharing capability and the domain restriction but not the default link type or the anonymous-link
  settings, so on a Graph-only run the last rule, and CIS `7.2.7` and `MS.SHAREPOINT.2.1v1` with it, read
  `not_assessed` where the controls used to read `pass` on per-item evidence alone.

New bundle fields (within contract `2026-10-22`): the sections `sharepoint_tenant_settings` and
`break_glass_assessment`; `sharing_capability_source` on `onedrive_posture_objects`; `allow_teams_consumer`,
`allowed_domains_state`, `allowed_domain_count` and `blocked_domain_count` on the Teams federation record; and
`break_glass_*` fields on Conditional Access policy records. A consumer that keyed on the old per-site OneDrive
or per-policy break-glass finding ids must read the tenant-level ones.

### Identity controls and Cyber Essentials rows (CE+ review of 2026-10-22)

- **Exclusions are judged.** A Conditional Access policy that targets all users but excludes the Global
  Administrator role, a staff group or every guest used to read `enforced` (MFA) or `blocked` (legacy
  authentication) and pass CIS `5.2.2.2`/`5.2.2.3` and SCuBA `MS.AAD.3.2v1`/`MS.AAD.1.1v1`. The verdicts gain
  `enforced_with_exclusions` and `blocked_with_exclusions`: `enforced` and `blocked` now need every principal
  excluded from all of the qualifying policies to be an emergency access account the operator listed with
  `--break-glass-accounts` (a role or a guest type is never acceptable). The two rules are raised for the new
  values at medium. Verdict records gain `unsanctioned_exclusions`, `unsanctioned_exclusion_count`,
  `sanctioned_exclusion_source`, `limitations` and `sanctioned` on each excluded principal. **List your
  emergency access accounts**, or a policy that excludes them reads "with exclusions".
- **Administrator MFA is judged.** New `administrator_mfa` verdict (`identity_control_verdicts.json`), read
  against the effective administrator set: security defaults, or a policy for all users or for every role an
  administrator holds, with no administrator role or administrator excluded (an excluded group or guest type
  reads `enforced_with_exclusions`). New rules `ca.admin_mfa_not_enforced` (CIS `5.2.2.1`, SCuBA `MS.AAD.3.6v1`,
  Secure Score `AdminMFAV2`, Cyber Essentials `ce.uac.mfa_admin_accounts`) and
  `ca.admin_phishing_resistant_mfa_not_enforced` (SCuBA `MS.AAD.3.6v1`; low). The registration rules
  (`identity.global_admin_mfa_not_registered`, `identity.privileged_mfa_not_registered`,
  `identity.user_mfa_not_registered`, `attack_path.no_mfa_to_tier0`) no longer map to CIS `5.2.2.1`/`5.2.2.2`, SCuBA
  `MS.AAD.3.1v1`/`3.2v1`/`3.6v1` or `AdminMFAV2`: they showed capability, and passed those controls in a
  tenant where nothing required MFA. `MS.AAD.3.1v1` has no rule until an all-users phishing-resistant
  verdict exists.
- **User consent.** `microsoft-user-default-recommended` and `-low` no longer read `restricted`: the verdict is
  `limited` and the new rule `consent_policy.user_consent_limited` fails CIS `5.1.5.1` and SCuBA
  `MS.AAD.5.2v1`. The companion policy `microsoft-user-default-allow-consent-apps` is recognised as Microsoft
  managed (it read `custom`); an unrecognised `microsoft-` policy reads `unknown` with
  `built_in_permission_grant_policy_not_evaluated`.
- **Cyber Essentials.** `ca.mfa_not_enforced` and the four stale-account rules are `partial` confidence (the
  verdict never reads per-user MFA; the inactivity threshold is Auditex's, not the applicant's), and the
  `ce.uac.mfa_cloud_services` limits say so. A new confidence, `supporting`, lists a rule in a row without letting it
  decide the row: `identity.global_admin_sprawl`, `identity.global_admin_disabled`,
  `identity.guest_with_privileged_role`, `google.super_admin_sprawl`, `google.suspended_admin` (Cyber Essentials
  sets no administrator count, and a disabled account has its privileges disabled) and `intune.device_noncompliant`
  (a compliance state does not say which setting failed) no longer fail `ce.uac.special_access_privileges` or
  `ce.sum.vulnerability_fixes_14_days`. A failing row gains `confidence`; a row whose rules were not evaluated says
  `rules_not_evaluated` with `not_assessed_reasons`. The Markdown report and the explorer show the title, reason,
  confidence and evidence limits of each Cyber Essentials row (the explorer no longer says "no collector in this run
  evidences this control" for a collector that ran).
- **Google Workspace bundles.** The Cyber Essentials section lists only Google rules for a Google bundle (and
  only Microsoft rules for a Microsoft one), and a Google rule that ran clean appears as evaluated.
- **Licence-gated reads.** An identity collector that is partial only because `userSignInActivity` was refused
  (`license_required`, no Microsoft Entra ID P1) no longer makes every identity rule `not_assessed`: the
  administrator rules are evaluated, and the sign-in rules (`identity.stale_enabled_account`,
  `identity.privileged_stale_account`, `identity.stale_guest`) read `not_assessed` with
  `signin_activity_unavailable`; the first two used to pass with no sign-in data at all. An
  `identity_governance` collector that is partial only because the PIM schedules were refused no longer blocks
  `identity.privileged_mfa_not_registered`.
- **Emergency access check.** A role-targeted policy is judged only when an account holds the role (and is
  never `high` unless it covers Global Administrator); a policy for a user action or an authentication context is
  not judged; an excluded group counts when the run read its members (role-assignable groups).
- **Administrator set.** Partner Tier1 Support, Partner Tier2 Support and Directory Writers count as
  administrator roles (matched by template id).
- **Handed over from the coverage and integrity work.** `intune_depth.update_ring_not_assigned` is quiet and reads
  `not_assessed` (with the `update_profiles_gap` reason: `update_profiles_blocked`, `update_profiles_truncated`,
  `profile_assignments_blocked`, `profile_assignments_truncated`, `profile_assignments_absent` or
  `profile_assignments_unknown`) when the beta update-profile lists were refused or cut and no ring is assigned: "no
  profile" was not established. `exchange.mailbox_forwarding_configured` also fires for forwarding to a mail contact
  (`ForwardingAddress`), not only to an SMTP address. `intune.device_noncompliant` reads `not_assessed` while any
  device's compliance was never evaluated (`unknown`, no value, `configManager`) or is in its grace period
  (`inGracePeriod`), where it used to pass; `device_posture_summary` gains `compliance_unknown` and
  `compliance_in_grace_period`. Baseline alignment reads a `closed` or `resolved` finding as closed only when a
  matching waiver stands behind it, as the gate does; without one it stays open (a bare `accepted_risk` is still
  accepted in the baseline rows, where the gate counts it open: the engine writes that status only with its waiver).
- **Demo.** The remediated demo tenant turns user consent off (it limited it, which no longer reads
  restricted), and its emergency-group exclusions read "with exclusions" because the demo lists no
  `--break-glass-accounts`.
- **Emergency-access list is read against the full lists (third CE+ review).** The MFA and legacy-authentication
  verdicts resolved `--break-glass-accounts` against the 20-row inline sample while the Conditional Access graph
  read the chunk files, so on a tenant with more than 20 users an account listed by user principal name, display
  name or group name was ignored and the verdicts read `enforced_with_exclusions` or `not_enforced` (a false high
  `ca.admin_mfa_not_enforced`). The accounts are now resolved once, against the full user and group lists, and
  both the break-glass check and every verdict use that resolution. An entry matches an object ID, user principal
  name, mail or display name; a display name that two accounts share is `ambiguous_display_name`. An entry that
  matches nothing is recorded as unresolved, never dropped: `break_glass_assessment` gains
  `unresolved_account_details` and `unverified_accounts` (object IDs not in the directory read, still honoured), the
  verdict records gain `unresolved_operator_accounts`, and `ca.mfa_not_enforced`, `ca.admin_mfa_not_enforced`,
  `ca.legacy_auth_not_blocked` and `ca.break_glass_exclusion_missing` name them.
- **Security defaults and the benchmark controls.** Security defaults still read `enforced` and `blocked` (Cyber
  Essentials, Zero Trust and Secure Score keep treating them as enforcement), but CIS `5.2.2.1` to `5.2.2.3` and
  SCuBA `MS.AAD.3.2v1` and `MS.AAD.1.1v1` audit a Conditional Access policy and passed on security defaults alone.
  Baseline alignment now reads them `not_assessed` with `conditional_access_policy_required:basis_security_defaults`
  until a qualifying policy backs the verdict (`_verdict_basis_requirements` in `configs/control-mappings.json`).
- **A country block is not the legacy-authentication block.** A policy now counts only when it names both legacy
  client app types (`exchangeActiveSync` and `other`, as ScubaGear and the CIS audit require) and no location
  condition limits it. A block of every client type that exempts the trusted countries (`all`, locations excluded)
  read `blocked` and passed CIS `5.2.2.3`, SCuBA `MS.AAD.1.1v1` and `BlockLegacyAuthentication`; it is now a near miss
  (`legacy_client_app_types_not_targeted`, `excludes_locations`, `narrowed_by_location`). A legacy block that exempts
  a network is a near miss too.
- **Administrator MFA is judged per administrator, across every enabled policy.** An all-users policy that excludes
  the Global Administrator role, plus a policy that includes it, read `not_enforced` (a false high finding and a
  failing Cyber Essentials row) whenever the second policy did not reach every administrator. A role policy that
  reaches only some roles now covers the administrators it reaches (`supplementary_policies`), role policies that
  each reach some administrators cover them together, and when only a policy that cannot be verified could cover an
  excluded administrator the verdict is `unknown` (`authentication_strength_unverified`,
  `administrator_exclusion_unresolved`) instead of `not_enforced`.
- **Exclusions are compared by person.** A user excluded by id from one qualifying policy, through a
  role-assignable group the run read from a second and through an administrator role they hold from a third was
  outside every policy and still read `enforced`. The three verdicts now add such principals to
  `excluded_principals` as `user` rows with the route each policy takes (`via`), so CIS `5.2.2.1`/`5.2.2.2`/`5.2.2.3`
  and SCuBA `MS.AAD.3.2v1`/`MS.AAD.1.1v1` no longer pass on them.
- **Administrator MFA must cover the benchmark role lists.** A policy for the roles held today, or an all-users policy
  that excludes a role nobody holds, passed CIS `5.2.2.1` and SCuBA `MS.AAD.3.6v1`. `administrator_mfa` gains
  `role_catalog_verdict` (the CIS 5.2.2.1 list: 15 roles by template id) and
  `phishing_resistant_role_catalog_verdict` (ScubaGear's 8 default privileged roles) with the uncovered roles; the
  verdict itself, which Cyber Essentials and Secure Score `AdminMFAV2` read, still reads the roles held today. New
  rule `ca.admin_mfa_role_set_incomplete` (medium; CIS `5.2.2.1`) fails the first, and
  `ca.admin_phishing_resistant_mfa_not_enforced` is also raised for the second.
- **Administrator scope reads the full role definitions.** The scope was built from the 20-row inline sample of raw
  role definitions, so only Global Administrator and three template-id roles were privileged and an excluded held
  role such as Security Administrator read `enforced_with_exclusions` (medium) when the administrator set was
  unknown. It is built from the normalized definitions read in full, and the collector now selects `directoryScopeId`
  on role assignments, which the Bundle fields entry above already claimed.
- **Sign-in reason.** A licence-limited identity run now reads the three sign-in rules `not_assessed` with
  `signin_activity_unavailable`, as documented; they stopped at `collector_not_complete:identity`.
- **Verdict logic follow-ups (focused verify).** An excluded group whose members were not read now counts as possibly
  containing a principal another policy excludes by id: the MFA and legacy verdicts read `*_with_exclusions` (a
  `possible` row) and the administrator verdict reads `unknown` (`administrator_exclusion_unresolved`) unless another
  policy covers the administrator. `effective_mfa` credits a role-targeted MFA policy toward an administrator role an
  all-users policy excludes (`covered_by_policy_ids`, `supplementary_policies`), so Cyber Essentials
  `ce.uac.mfa_cloud_services` no longer fails when everyone is covered; `single_policy_verdict` keeps the CIS 5.2.2.2 and
  SCuBA `MS.AAD.3.2v1` reading and the new rule `ca.mfa_split_across_policies` (low) fails those two controls. With the
  administrator set incomplete, an excluded privileged role nobody is known to hold reads `unknown`
  (`administrator_set_unknown`), not a high `not_enforced`, and a covering role policy's user exclusion is doubted
  (`administrator_exclusion_unresolved`). Security defaults beside a Conditional Access policy with gaps list only
  `security_defaults` in `basis`, so the Conditional Access benchmark controls stay `not_assessed`. Two block policies that
  each name one legacy client type keep the verdict `not_blocked` with the reason `legacy_block_split_across_policies`
  and `ca.legacy_auth_not_blocked` is medium.
- **New rule.** `identity.service_principal_privileged_role` (high): a service principal that holds Global
  Administrator or Privileged Role Administrator, directly, PIM-eligible or through a role-assignable group. It maps
  to MCSB `PA-1`/`PA-7` and Zero Trust `identities`, lists `ce.uac.special_access_privileges` as supporting
  evidence, and reads `not_assessed` while the administrator set is `unknown`.

### Google Workspace

Upgrade notes (all in `auditex google`):

- **New scope and API.** The `core-security` and `identity` presets add the `google_policies` collector, which
  reads the 2-step verification policy through the Cloud Identity Policy API. Enable the Cloud Identity API
  and add `https://www.googleapis.com/auth/cloud-identity.policies.readonly` to the delegation entry.
  The scope is requested on its own token, so a tenant that has not added it yet loses only that read
  (the run is partial and the policy is reported as unknown); the other collectors are unaffected.
- **OAuth token caches must be re-consented.** The new scope is part of the OAuth consent set, so an existing
  `--token-cache` does not hold it: the policy read fails until the browser flow is run again (delete the cache
  or let it refresh). Domain-wide delegation needs no re-consent, only the delegation entry.
- **DNS posture checks every verified domain.** It used to assess the `--domain` label only; it now reads the
  Directory domains list, so secondary domains raise their own `google.dns_*` findings. The label stands in
  only when the list cannot be read.
- **`--domain` is a label.** Users and groups are listed for the whole customer (`customer=my_customer`),
  so secondary and alias domains are no longer left out. The internal domain set comes from the Directory
  domains list; without it, or when the list was cut short, the external-principal rules report
  `google.internal_domains_unknown` (status `unknown`, `label_only` or `partial`) instead of returning nothing.
- **Gmail settings are read per user** under domain-wide delegation, on a token narrowed to the two Gmail
  settings scopes (bounded: 500 mailboxes without `--top`, the cut recorded as a coverage gap). With OAuth
  only the signed-in mailbox is read, and the run says so. Drive and Calendar evidence is the delegated admin's view and is labelled `subject_scoped: admin` on its
  coverage rows, capability rows and findings.
- **One `google.collector_issue` per surface** with the object count, replacing one per user, group or
  calendar. Finding ids for per-object failures change to `google.collector_issue:<collector>:<surface>`.
- **Device lists use the `FULL` projection with a field mask**, and `google.mobile_device_compromised` reads
  the API's `deviceCompromisedStatus` (the old `compromisedStatus` key never appeared in real responses).
  The Directory API lists no values for the field, so a value is classified `compromised`, `not_compromised` or
  `unknown` (record field `compromised_state`); an absent or unrecognised value is never a pass or a failure and
  is counted in one `google.evidence_unknown:mobile_compromised_status` finding. The previous substring match
  that treated any text containing "compromise" as compromised is gone.
- **`--stale-device-days`** (default 90, was fixed) sets the sync age for `google.mobile_device_stale_sync` and
  `google.chromeos_device_stale_sync`.

### Collection coverage, run integrity and transport

Contract notes. These are additive to `2026-10-22`, which is unreleased, so the contract version is unchanged:
the validation codes `unwaived_accepted_status` (error) and `unknown_finding_status` (warning), the manifest key
`rule_parameters` (with the emergency-access list `break_glass_accounts`), the manifest key `replay_source`, the gate
codes `bundle_integrity_mismatch`, `bundle_integrity_invalid`, `bundle_integrity_absent`,
`expected_manifest_sha256_mismatch` and `expected_manifest_sha256_invalid`, the truncation reason `pagination_not_followed`, the rule input reason
`bounded_sample:<collector>.<list>`, the normalized section `bounded_samples`, the `update_management_summary`
fields `update_profiles_gap` and `profiles_with_unknown_assignments`, the `forwarding_address` field of mailbox
forwarding records, `graph.redirects` and `graph.redirects_refused` in the observed ledger, coverage rows of an
offline replay, and the `verify-pack` issue codes and options listed below. Changed behaviour a pipeline may
notice: a bundle finalized under `2026-10-22` and found without `bundle-hashes.json` is `invalid` (handoff
`unusable`, no pack), an accepted or closed status on an expired waiver counts as open, a report written into a run
makes the handoff `ready_with_limitations`, an offline replay no longer says its flags were observed in a transport
log, and `source-artifacts/run-manifest.json` in a pack has local paths made pack-relative; the legacy cut-off for unresolved references is the fixed version `2026-10-22` and not the current
`CONTRACT_VERSION`; an operator `--top` below the list length now also cuts `secureScoreControlProfiles`,
`secureScores`, `subscribedSkus` and `domains` (below about 250 it makes `defender` partial); a DNS resolver failure
makes the `dns_posture` collector and the run partial; the mailbox forwarding command text and the eDiscovery
command spellings in `configs/collector-definitions.json` changed; packs use pack-relative paths.

- **Fixed: a resumed run read `ok` over earlier gaps.** `--resume-from` turned a `partial` collector into `skipped`
  (`not_applicable` in the ledger), so the run read `ok`, exited 0 and passed the gate. A finished collector now keeps
  the status it finished with; a `partial` or `failed` collector, a collector the preflight skipped as blocked and an
  `ok` collector whose raw payload is gone are run again and replace their earlier summary and coverage rows; a
  checkpointed collector outside the resumed session that did not finish keeps the run `partial`.
- **Fixed: `gate` and `gate-drift` did not check the hash manifest and compared only finding ids.** Both verify
  `bundle-hashes.json` (a mismatch, an invalid manifest, or a missing one in a bundle finalized under `2026-10-22`
  blocks), compare each finding's status, severity and rule between the findings file and the report pack, and count
  an accepted or closed status only when a matching waiver stands behind it. `gate-drift` and `compare` record and
  compare the rule windows the runs were judged with (`rule_parameters`: `stale_sync_days`, `stale_guest_days`,
  `stale_account_days`, `stale_user_days`, `stale_device_days`), so a laxer later window, or one nobody recorded, is
  `not_reassessed` and not `resolved`. `compare` verifies each run's hash manifest and recorded contract.
- **Fixed: Google Workspace findings read `resolved` when their inputs went unknown.** Reassessment now checks the
  `google_directory` and `google_policies` collectors and the 2-step policy and internal-domain status.
- **Fixed: offline replay ignored error and truncation markers.** A sample section that records a blocked read or a
  cut list replays as a partial collector with a coverage row and blocker (Microsoft 365 and Google Workspace), so
  blocked MFA evidence no longer reads `pass` in a valid bundle.
- **Fixed: unpaged list reads dropped `@odata.nextLink`.** `secureScoreControlProfiles` was cut at 200 rows with
  `collection_truncated: false`. Every list is paged, an unpaged response that carries a next link is a gap
  (`pagination_not_followed`), and a test fails the build when a collector reads a list with a direct `get_json`.
- **Fixed: bounded sign-in and audit samples let `security.*` rules read `pass`.** `security.risky_signin` and
  `security.privilege_change_event` read `not_assessed` (`bounded_sample:security.signIns`,
  `bounded_sample:security.directoryAudits`) when no finding was raised and the newest-500 log was cut.
- **Fixed: mailbox forwarding read the first 50 mailboxes and recorded no gap.** It reads the mailboxes that forward,
  server-side, with a 500-row bound recorded as a `fanout_limit` gap.
- **Fixed: a DNS resolver failure raised high SPF, DMARC and DKIM "missing" findings.** A resolver failure is
  unknown: the record flags are `null`, no such finding is raised (Microsoft 365 and Google Workspace), and it no
  longer mutes `exchange.dkim_signing_disabled`.
- **Fixed: a blocked beta update-profile list could read as "no update ring".** The update summary now says why
  (`update_profiles_gap`); the rule and baseline checks that read it belong to the findings change (see the report).
- **Fixed: the API ledger collapsed long resource names into `{id}`.** Only identifiers are templated, so
  `deviceCompliancePolicies` and its siblings stay distinct and an undeclared one is listed. Content-read detection
  also covers `calendarView`, calendars by id, group threads, conversations and posts, `getAllMessages`, list items
  and To Do tasks, an `$expand` of content, and a query left inside a next-page or `$batch` inner URL. The four
  eDiscovery `purview ... list` commands seen "outside the declared set" are declared (`command_variants` on every
  eDiscovery row), the m365 CLI adapter logs `command.completed` after classifying the output, and resource-token
  requests emit `graph.token.requested`.
- **Fixed: unlisted and symlinked files were read by handoff and copied into the customer pack while integrity read
  `verified`.** A symbolic link anywhere in a run, and an unlisted file where the product reads (except named
  post-finalization outputs), is an integrity mismatch; the pack copies only regular files the hash manifest lists.
- **Fixed: `verify-pack` ignored the copied `bundle-hashes.json`.** It checks the digest against
  `integrity.manifest_sha256` and every copied source artifact against its row, reports unexpected files and symbolic
  links, prints `digests`, and takes `--expect-manifest-sha256` and `--expect-checksums-sha256` (also on the MCP
  tool). Packs carry pack-relative paths and no absolute path of the operator's machine, and a non-empty output
  directory with no earlier pack is refused.
- **Fixed: `verify-pack` skipped its source-artifact check when the pack claimed the run was not verified.** A pack
  whose copied `reports/report-pack.json` was rewritten, with its manifest and `handoff.json` edited to say the run's
  integrity was `absent`, passed with the genuine `--expect-manifest-sha256`. The copied `bundle-hashes.json` is now
  checked whenever the pack carries it, over every listed file under `source-artifacts/` found by where it sits
  (`source_integrity_status_inconsistent` when the pack claims anything but `verified`), and a current-contract pack
  with no copy is `missing_bundle_hashes`.
- **Fixed: a planted SQLite sidecar was excluded from hashing but replayed by every consumer.** A `-wal` file beside
  `index/evidence.sqlite` changed the run id, dates and section counts that `compare`, the gates and the handoff read
  (and could reverse a comparison) while integrity read `verified`. A sidecar beside the hashed index is now an
  `unexpected` file (mismatch); the index is read with SQLite `mode=ro&immutable=1`, which neither replays nor creates
  a sidecar and opens on read-only media; read-only validation copies the hashed file alone. `excluded[].reason`
  `sqlite_sidecar` is no longer written. A bundle no hash manifest covers is read as before.
- **Fixed: the emergency-access list was an unrecorded rule input.** Listing the excluded staff group in a later run
  made the MFA findings `resolved`. `rule_parameters.break_glass_accounts` records the list, and a vanished finding of
  a Conditional Access rule (`ca.*`) is `not_reassessed` (`rule_parameters_changed:break_glass_accounts`, or `..._unrecorded:...`)
  unless both runs used the same list.
- **Fixed: an offline replay claimed "Read-only: True (observed in the transport audit log)".** A replay has no tenant
  traffic. Handoff, pack and `api-calls` say `replayed from <file>, no tenant contact`, the basis is `offline_replay`
  (`api-inventory.json` `safety.observation_basis`, `observed_ledger.basis`), and `run-manifest.json` records
  `replay_source` (file name and SHA-256). Older replay bundles read the same way from `mode: offline`.
- **Fixed: a current-contract bundle stripped of `bundle-hashes.json` was "from before the manifest existed" to the
  handoff.** It is `invalid` (`manifest_missing`), the handoff is `unusable` and `customer-pack` refuses it; only a
  bundle finalized under an older contract is `absent`. The gates keep the code `bundle_integrity_absent`.
- **Fixed: an expired waiver left a `closed` or `resolved` finding closed.** `accepted_risk` on the same waiver failed
  the gate; `closed` passed silently. An expired waiver now reopens every accepted or closed status in `gate` and
  `gate-drift` (`expired_waiver_status_count`; `reason` `stale_accepted_risk` or `expired_waiver`), reported once.
- **Added: `--expect-manifest-sha256` on `gate`, `gate-drift` and `compare`.** The absent-manifest block rests on the
  contract version in the bundle, which can be rewritten with the manifest; the SHA-256 of `bundle-hashes.json`
  received separately cannot. A run with another digest, or none, is blocked first (`expected_manifest_sha256_mismatch`;
  `compare` reads `run_unverified:...` and resolves nothing). `gate-drift` and `compare` take `<run-dir>=<digest>` per
  run. See the output contract, "Expected manifest digest". The MCP compare tool does not take it yet.
- **Fixed: a pack carried the operator's absolute path in `source-artifacts/run-manifest.json`.** The copy has `run_dir`
  set to the run folder name, paths below the run run-relative and other absolute paths reduced to
  `<local-path>/<name>`. Its pack-manifest row has `transformed: "pack_relative_paths"` and `source_sha256` (the digest
  the run's `bundle-hashes.json` lists); `verify-pack` accepts it on that basis, and only `checksums.sha256` binds the copy.
- **Fixed: reports written into a run after it was finalized were unhashed and raised no limitation.** The explorer
  page, `rendered-report.*` and `reports/handoff.md` are readable by an assessor. They stay out of
  `bundle-hashes.json` (adding them would change the digest after it was handed over); the handoff lists them as the
  limitation `unhashed_outputs` and never copies them into a pack.
- **Fixed: handoff, report and pack presented the declared call rows as "Observed calls" and an unqualified
  "Read-only: True".** They render the transport ledger ("Observed calls (transport ledger)"), label the declared
  figure "Declared calls", print the observation basis next to Read-only and No content reads, and never claim
  "stayed read-only" without an observed ledger. Handoff counts gain `declared_calls`, `observed_graph_requests`,
  `observed_commands` and `observed_outside_declared`. Drive readonly is classified `content_capable`.
- **Fixed: packs, rendered reports, the explorer and `--output` payloads took the caller's umask.** They are `0600` in
  `0700` directories through one private writer, including `reports/explorer.html` inside the bundle.
- **Fixed: the legacy cut-off followed `CONTRACT_VERSION`.** It is now the fixed version `2026-10-22`, so a later
  contract bump never labels an edited citation "not a sign of editing".
- **Fixed: fan-out totals and OneDrive sites came from the 20-row inline sample.** Gap rows state the real total, the
  OneDrive finding counts every site read, and the `app_consent` fan-out row carries `rows_collected`.
- **Changed: transport hygiene.** `GraphClient` no longer lets the HTTP library follow redirects: it follows them by
  hand, keeps the bearer token only for a hop on Graph, fetches a Microsoft download host over HTTPS without the
  token, refuses anything else, and logs each hop as host and path only. Command-output samples are redacted before
  they are cut, and JSON-keyed secrets (`"client_secret": "..."`) are redacted. Inbox-rule keyword lists and Gmail
  filter `query`, `negatedQuery` and `subject` are kept as counts and lengths. The guided Exchange module install no
  longer marks PSGallery as trusted.

### Third CE+ product review, coverage lens (2026-10-23)

Contract notes. Additive to `2026-10-22`, which is unreleased, so the contract version is unchanged:
`coverage_gaps[].section_gaps` and `surface_coverage[].section_gap_collectors` in `run-manifest.json` and
`summary.json`, section-scoped records (`section_scoped`, `status`, `error_classes`) in
`normalized/collection_gaps.json`, the validation warnings `section_gap_not_recorded` and
`observed_call_outside_declared`, `observed_ledger.log.empty`, the replay row error class `section_absent`, the
per-collector `since` and `until` of a checkpoint, `normalized/bounded_samples.json` on Google Workspace, the
`casMailboxSmtpAuth` section of `exchange_policy_objects` (a new read-only command, `Get-CASMailbox`, an aggregate
count), and the rule input reasons `registration_report_incomplete:<n>`, `tenant_domains_unknown` and
`risk_detail_hidden`. Changed behaviour a pipeline may notice: an empty or partial MFA registration report, a
SharePoint external-principal check with no domain list and a sign-in sample that hides every risk level now read
`not_assessed` where they read `pass`; a run with section-scoped gaps stays `ok` (exit 0) but its handoff reads
`ready_with_limitations` and the gate warns; a resume now reports on every finished collector of the run folder.

- **Fixed: the MFA registration rules passed on an empty report (high).** `identity.user_mfa_not_registered`,
  `identity.privileged_mfa_not_registered`, `identity.global_admin_mfa_not_registered` and
  `attack_path.no_mfa_to_tier0` judged only the rows the registration report returned, so an enabled user or counted
  administrator with no row was never judged: an empty report passed CIS `5.2.3.4`, the Cyber Essentials MFA rows,
  MCSB IM-6 and PA-1 and Zero Trust identities, live and in an offline replay of `auth_methods` as `{}`, `null` or `[]`.
  The rules now read `not_assessed` with `registration_report_incomplete:<n>`.
- **Fixed: section-scoped gaps were invisible to the run.** A Defender state read for 100 of 150 devices, refused
  beta update profile lists, a refused compliance assignment read, `windowsProtectionState` refused on every device
  and 111 compliance policies cut at 100 left `coverage_gaps` empty, the gate passing and the handoff clean. They are
  now section gaps in the manifest, `collection_gaps.json`, the handoff limitations and a gate warning, without making
  the collector or the run `partial`. A cut or failed beta update profile page no longer leaves a bundle that fails
  validation (`truncated_list_reported_ok`) while the run reads `ok`: `list_truncations` leaves section-scoped rows out.
  The 10-profile assignment fan-out of `intune_depth` is section-scoped, so a tenant with more than ten profiles keeps
  its update ring rules.
- **Fixed: the attack-path rules passed with their graph inputs partial.** `attack_path.app_owner_to_tier0` and
  `attack_path.privilege_escalation` now need `identity`, `app_consent`, `directory_relationships` and
  `identity_governance` (not applicable is tolerated).
- **Fixed: `sharepoint.external_principal` passed with no domain list.** It is gated on `domains_hybrid` and reads
  `tenant_domains_unknown` without a verified domain record; comparison no longer calls a finding resolved when the
  later domain read failed. The tenant name alone is no longer a domain list.
- **Fixed: the mail protection rules judged only the tenant defaults.** `exchange.malware_filter_weakened` judges every
  anti-malware policy, and `exchange.smtp_auth_enabled_tenant_wide` counts mailboxes that switch SMTP AUTH back on
  (`Get-CASMailbox`, a count and no address) and is `not_assessed` until that count was read.
- **Fixed: `security.risky_signin` passed when every sampled sign-in hid its risk.** It reads `not_assessed` with
  `risk_detail_hidden`.
- **Fixed: an offline replay treated a collector that held nothing as complete.** A collector the sample holds as
  `{}`, `null` or a list is `partial` with a failed `section_absent` row for every section of its live run; a domain
  record with a `resolver_error` is a failed `dns_resolver_error` row; a Google Workspace replay is labelled
  `complete_offline_sample`, never `complete_exact_scope`. A collector that holds any key is not second-guessed
  section by section, because minimal fixtures omit sections on purpose.
- **Fixed: a resume that narrowed the collector set reported on half a bundle.** Every finished collector of the run
  folder is carried and judged whether or not it is selected; diagnostics, blockers and findings are rewritten (and
  removed when empty), so a collector that succeeds on resume drops its old blocker; stale `normalized/` sections are
  removed; a checkpointed collector that cannot be carried keeps the run `partial`.
- **Fixed (low): resume coverage and windows.** The writer seeds coverage from `index/coverage.jsonl` as well as
  `coverage.json`, so an interrupted session keeps its rows, and a carried collector with no summary row is added.
  A checkpoint records `since` and `until`; `security` and `defender` are re-run when the resumed session's window differs.
- **Fixed (low): a preflight-blocked collector read `not_applicable`.** It is `blocked_permission` in the ledger, raises a
  blocker with the cause (a 403 is `insufficient_permissions`) and is named by the `--allow-partial` gate warning.
- **Fixed (low): DNS edge cases.** A DoH answer with no `Status` or with `TC` is unknown, not absent; a revoked DKIM key
  (empty `p=`) is an absent selector; an MTA-STS policy fetch that did not answer fails its row.
- **Fixed (low): Google Drive 500-file crawl.** `google.drive_anyone_with_link` and `google.drive_public_discoverable`
  are sample-judged rules (`bounded_sample:google_drive_posture.driveFiles`).
- **Fixed (low): paging leftovers.** `riskyUsers` and the Power Platform environment and DLP policy lists follow their
  next link; a failed page or a list past 50 pages is a marked cut.
- **Fixed (low): API ledger.** An empty audit log next to declared calls is not `read_only`; the PowerShell adapter
  logs the outcome and the command words (`command.completed` `status` and `error_class`, `command.failed` words);
  a call outside the declared set is a validation warning and a gate warning.

### Added

- Google Workspace rules `google.user_2sv_not_enforced`, `google.org_2sv_policy_not_enforced` (high when no
  policy enforces, medium when only some organisational units or groups do), `google.stale_user` (`--stale-user-days`, default 90), `google.never_logged_in_user`,
  `google.chromeos_device_past_aue` and `google.mobile_device_encryption_off`, with the diagnostics
  `google.internal_domains_unknown` and `google.evidence_unknown` (an absent field is unknown, never a pass).
  Delegated admins now get the admin rules (`is_privileged`). Mobile and ChromeOS posture fields (encryption,
  lock, patch level, auto-update expiration) are normalized.
- `auditex google run --waiver-file`, with the Microsoft 365 waiver semantics; an invalid file stops the run
  before any API call. `make contract-smoke` also runs and validates the Google offline sample.
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

[Unreleased]: https://github.com/magrathean-uk/auditex/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/magrathean-uk/auditex/compare/v1.2.4...v1.3.0
[1.2.4]: https://github.com/magrathean-uk/auditex/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/magrathean-uk/auditex/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/magrathean-uk/auditex/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/magrathean-uk/auditex/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/magrathean-uk/auditex/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/magrathean-uk/auditex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/magrathean-uk/auditex/releases/tag/v1.0.0
