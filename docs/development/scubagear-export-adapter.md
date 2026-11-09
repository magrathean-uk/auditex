# Internal ScubaGear export adapter

This adapter is internal and experimental. Run `scripts/assess-scubagear-export.py` against a local ScubaGear `ProviderSettingsExport.json`, or a `ScubaResults_*.json` containing that export under `Raw`. It is absent from the public `auditex` CLI, MCP, shipped content and customer documentation. It does not sign in, collect tenant evidence or modify a tenant. Its output directory contains a local rule-only assessment plus `scubagear_adapter_report.json`; it is not a validated run bundle, and `auditex validate` does not apply. Assessment is rules only and nothing is sent anywhere; the model layer is removed. All 102 catalogue policies have registered value rules, but available evidence, the adapter and permissions determine whether a policy can be assessed; a policy without a rule would report `rule_not_implemented`.

The adapter uses the unchanged `scuba_projection` shape gate. That gate admits 410 digests for 16 of the catalogue's 58 sections. The other 42 sections are withheld. Historical model-view measurements yielded 44 eligible policy rows out of 102 for the clean synthetic fixture and 43 for the real-format construction because its `org_config` had no validated `Identity`. These figures describe eligibility for the retired model projection, not current rule coverage. These are fixture plumbing figures with the gate unedited, not coverage claims. Both constructions include the seven `privileged_roles` readers and ten Conditional Access readers. A full real PIM rule set cannot pass the gate: every validated role rule element shape carries `NotificationRecipients`, whereas real expiration, enablement, approval and authentication-context rules do not. A real export's yield is unmeasured. The source-reading estimate has a floor of 0, and 16 to 27 only if ledgers are healthy, enum values are in domain, `scuba_config` is default and each section has at most 40 items. Above 27 requires `conditional_access_policies` to project, which is improbable on a real export because an enabled policy with a populated restriction or authentication strength is withheld. The real-export upper bound is 36, not 43; EXO.13.1 is certain to stay withheld. No shape digest is added here.

For historical model-view measurements, the gate admitted compliant configurations preferentially. For example `authorization_policies` projects only when `AllowInvitesFrom` is `adminsAndGuestInviters`, the passing value for MS.AAD.8.2. Any measured yield or model score on the assessed set therefore skews towards passes. The report's `ceiling` is a statement about this validated gate and the synthetic fixtures, not about actual tenant coverage.

## In-memory rule view

`project_export` also captures `Projection.rule_sections` and per-policy
`rule_views` after repair and command-ledger checks, canonicalisation and
qualifier checks, before proof pruning, the unchanged shape gate, the model
budget and redaction. Digest-less sections and lists over the projection's 40-item
budget can therefore reach deterministic value rules while the projection still
shows the not-collected marker. The capture is kept in memory; the
assessment envelope and the sidecar serialise only the model projection and
safe diagnostics. An unprojected `scuba_config` policy view is not collected
for both rules and the model, even when the shared base config was projected.
Capture reuses validated section objects except for `privileged_users`, which
model redaction edits in place, and keeps the raw section alive for as long as
the projection lives (about 100 MiB held for a 33 MiB file once the loader is
released). Serving deep-copies the sections each rule reads once per policy, to
stop a rule from changing a later policy's input, so the copy cost multiplies by
the number of rules that read a section. The file cap of 64 MiB bounds the
input. Measured on synthetic 200,000-row sections: a section no rule reads cost
nothing extra (27.4 s against 27.2 s for the full assessment), while
`powerbi_tenant_settings`, which eight rules read, raised the peak from 247.7 to
262.2 MiB and the assessment from 25.5 s to 70.0 s, under a machine load of
about 26. These are single local measurements on synthetic input, not a
performance promise or a production figure.
One failed Security Suite command still withholds all sections tied to that
ledger; this is a coverage limit of the current adapter. The validated
`securitysuite_unsuccessful_commands` list itself is also available in the
private rule view, including when non-empty. Missing, repaired or malformed
ledgers remain not collected; failed provider sections remain withheld. The
ledger is outside the frozen projection catalogue.
The sidecar persists only unsuccessful-command counts per provider; it never
copies command strings from a ledger.

The existing export capture retains `defender_license` and
`defender_dlp_license` without coercion, so false, null and absent remain
distinct. It also retains ATP preset rules (`atp_policy_rules`) for SS 2.1-2.3
and 7.1-7.3: `Identity`, `State`, `SentTo`, `SentToMemberOf`,
`RecipientDomainIs`, `ExceptIfSentTo`, `ExceptIfSentToMemberOf` and
`ExceptIfRecipientDomainIs`. Recipient emails reach rules only in memory;
these digest-less sections remain withheld from the projection; redaction is
unconditional. The stage-3 rule catalogue must add
`defender_license` to SS 1.3 and 7.1-7.3, `defender_dlp_license` to SS 3.1,
3.3 and 3.4, and `atp_policy_rules` to SS 2.1-2.3 and 7.1-7.3. The model
catalogue is unchanged. No complete source or adapter for these Defender
sections or the provider ledger exists on the run-bundle path; that path
continues to supply not-collected evidence for them.

DNS `log` survives privately on both paths, when saved by the source. The
run adapter removes it from the model view after capture; the export adapter
already captures it before proof pruning. This does not add a DNS collector
read or reconstruct records that the collector did not save. Preserving the
log does not itself implement the successful-empty-answer rule (spec Q12).

Both paths already preserve `GrantControls.Operator` and distinguish a null
role-assignment date from an absent key. The M6 collector correction now also
preserves Graph's explicit null `scheduleInfo.startDateTime` upstream of the
run projection. Source semantics: the output contract's privileged-role
section identifies `roleAssignmentSchedules`, including its known scope and
instance limitations; v3.9 spec section 3.5 and Q26 treat null start/end as
non-PIM/permanent signals and absent keys as unusable evidence. The change
preserves source values; it does not establish live Graph behaviour or change
which schedules are read.

`scuba_config.M365Environment` reaches AAD 9.1 and the three environment-bound
Teams private rule views on both paths. Private export rule views accept the exact
values `commercial`, `gcc`, `gcchigh` and `dod`; malformed or unknown values
withhold those views. The export projection views retain their existing behaviour:
only `commercial` projects, and `gcc`, `gcchigh` and `dod` remain withheld until
a projection environment gate lands. An omitted environment retains the existing
commercial default. The export synthesis diagnostic describes the projection views
and keeps its existing `assumed_default` basis vocabulary for these configuration
assumptions; it does not assert a
detected tenant cloud. Run bundles retain their discovery/SKU/default evidence
and ambiguity handling. The rule-view expansion leaves the export projection
and prechecks unchanged; the frozen shape gate is unchanged. Break-glass and
Security Suite operator-input withholding remain
in force.

## Evidence boundaries and privacy

The projection reads catalogue section keys, provider command ledgers and four relevant `scuba_config` keys. Baseline comparison reads `Results` control IDs and result labels, or the corresponding TestResults fields. The parser reads `MetaData.ToolVersion` and `MetaData.ReportUUID`, or the provider export's `module_version` and `report_uuid`; only validated forms reach output. `tenant_details.TenantId` is consulted only to detect a conflict with `tenant_id`. Other export keys, including connectors, `cap_table_data`, licence detail, arbitrary `tenant_details` fields and credential-shaped configuration fields, are not put into assessment cases, the envelope or the sidecar. The provider export, `Raw` when wrapped, is canonicalised in memory for the redaction salt; its content is not emitted. The parser accepts equal top-level `accepted_domains` copies, withholds that section when the copies differ and refuses every other duplicate; it rejects non-finite JSON and lone surrogates, and caps a file at 64 MiB. Its one ScubaGear repair turns a missing JSON value after a key into `[]`; the enclosing section or provider ledger is withheld because repaired data is not evidence. A repair pattern inside a string is refused. The sidecar lists only fixed known section or ledger names, capped at 64, and counts all other repaired key names without emitting them.

Default redaction pseudonymises `privileged_users` display names and immutable IDs. It rewrites an e-mail local part to `***@domain` anywhere in projected evidence. Domain names remain unmasked, including in `accepted_domains`, SPF, DKIM, DMARC and similar sections. A projected `tenant_id` remains an unmasked UUID. Redaction is unconditional: `--no-redaction`, `--endpoint`, `--model`, `--dry-run` and `--shadow-model-on-precheck` are not parsed, so the script rejects each with a usage error (exit 2). Nothing is sent to a model endpoint. The canonicaliser drops GUID keys and each entry's `id` before projection, whatever the redaction setting.

The canonicaliser converts a non-empty GUID-keyed `privileged_users` object only when **every** key is a canonical hyphenated GUID, unique after lower-casing, and every entry has exactly `id`, `DisplayName`, `OnPremisesImmutableId` and `roles` with the specified types. The entry `id` must match the key exactly. It drops `id`, sorts each roles list and orders entries by a hash keyed by the redaction salt before numbering them `User1` onwards. It retains identical entries with different valid GUIDs. Any mismatch leaves the original value for the unchanged shape gate to reject; there is no partial conversion. An administrative-unit-scoped role cannot be distinguished in this export; ScubaGear lists such users in `privileged_users` anyway.

The redaction salt is SHA-256 over a purpose string, sorted canonicalised entries, sorted lower-case object IDs and a digest of the whole parsed provider export. The digest canonicalises object keys and array order, is held in memory and is never persisted; `input.sha256` remains a hash of file bytes. The schema's `run-salted-sha256-v1` strategy label means, for this adapter, **salted SHA-256 with an export-specific salt that is never persisted**. It is not the manifest digest used for the bundle path in `docs/reference/output-contract.md`. Pseudonyms reproduce for the same provider export, whether bare or under `Raw`, independent of roles or JSON key order. Changing any export section can change the salt; pseudonyms are deliberately not stable across exports. Accordingly, the cross-export equality clauses of criteria 16(d) and 22(a) are dropped under O18 revised; policies unaffected by changed evidence or pseudonyms retain equal assessment cases in the two fixtures. The dictionary-attack regression shows that a known salt input permits name recovery while the output alone does not. This is pseudonymisation, not anonymisation. When ReportUUID is unavailable, the `run_id` suffix uses the first 16 hex digits of the already reported file-byte `input.sha256`.

Projected Conditional Access `Conditions.Users.IncludeUsers` and `ExcludeUsers` arrays retain object IDs, including on real exports. The fixtures also expose `privileged_roles.Assignments[].PrincipalId` where that section projects. If all privileged-user IDs are visible, an attacker can reconstruct the ID part of a weaker salt; a synthetic two-user probe recovered both names from a 300-name dictionary in about 49,413 guesses when the IDs were known. The whole-export digest now adds data unavailable from the output, but a recipient who also knows the complete export can confirm candidate names. The product stream's O18 decision accepted this residual; it was not a decision by G. There is no run-random salt, so the output remains pseudonymised rather than anonymised.

## Proof-gated pruning and qualifier checks

The checked-in `src/auditex/scubagear_prune_proof.py` is generated by `scripts/derive-scubagear-prune-table.py` from ScubaGear revision `2446ad723b7f55031cc02c8aca244d731d468cba`, its twelve hashed Rego files and the unchanged validated shape descriptors. Its 13 rows hold `rego_read`, `validated`, `verdict`, `reason`, `evidence` and `adjudicated`. The generator is built on OPA's parser (the pinned OPA 1.20.2) and uses its AST to follow section aliases, imports, element binders, helper parameters and literal keys. It is an **advisory first guard, not the proof**: it withholds the patterns it recognises as unsafe, and it is known not to be an exhaustive allow-list (a later review invented constructs that read a field in an unusual way, none present in the pinned Rego, that it classifies as prunable). The proof for the **shipped** table is (a) independent hand re-derivation of all 13 sections from the pinned Rego in four review rounds, (b) byte-for-byte regeneration, and (c) the OPA vocabulary differential (622 runs, 4,266 rows, truthy and falsy values, with mutations M1 to M4 and FirstOrg caught). It treats explicit AST patterns as safe field reads, direct report values, null checks, scalar-array cardinality or object emptiness. An object emptiness check also withholds if an admitted shape has an empty object there. Any human resolution of an unresolved use belongs in the generator's `ADJUDICATIONS` table; a stale entry fails generation. A table for a **new** ScubaGear revision still needs human review of **every verdict**, including all prunable rows, not just regeneration. Do not hand-edit the module.

For a prunable row, `prune_section` removes only object keys outside the validated path set. It preserves every kept value, array and element order, then passes the result to the unchanged digest and enum gate. It refuses a hand-edited `prunable` flag when `verdict_of` recomputes a different decision. Removed **names only** may appear as `ignored_fields` on a projected section; each unrecognised path segment is masked as `unrecognisedField`, and OData annotations are omitted. Removed values never enter that field or the sidecar. The sidecar records only removed counts and fixed verdict and outcome tokens.

Two sections need a qualifier check before any pruning. For an enabled Conditional Access policy, a populated restriction such as locations, platforms, devices, groups, guests, service principals or session controls withholds the section. Disabled and report-only policies are inert to the pinned Rego; their extra fields can be pruned. For `privileged_roles`, populated scope, assignment and PIM-rule qualifiers withhold; an unknown rule-ID prefix also withholds. These checks mirror the bundle path and have drift tests against its private `_ca` and `_roles` rules. The Conditional Access post-check reads the pre-prune raw list whenever the section was healthy but not projected, so a withheld restriction cannot appear as a false `evaluated, 0` projection summary. Its raw-row pre-check is stricter than the bundle path; malformed rows yield `not_evaluated/incomplete_shape`, which fails safe.

## Local validation

`tests/test_scubagear_export.py` verifies the proof table against the shape fixture without a ScubaGear checkout and regenerates it byte for byte when `AUDITEX_TEST_OPA` points at pinned OPA 1.20.2 and `AUDITEX_TEST_SCUBAGEAR` points at the pinned checkout. `tests/test_scubagear_differential.py` requires the same tools. It evaluates each product's `tests` set on full and pruned synthetic inputs and compares only pass, fail or not-evaluated verdicts. It includes clean and real-format fixtures, a descriptor sweep, canonicalised users, a deliberately failing Teams negative control, and vocabulary injection at every object level. The vocabulary is derived from the Rego directory under test, so a newly added field name is included in that local test. The current batch makes 622 OPA runs over 4,266 policy rows, including 2,558 reachable rows. This differential sees presence-sensitive and truthy or falsy reads, but cannot see a check for one specific enum or string value unless that value is injected. Equality on these inputs does not prove the static table for every possible input or the qualifier checks. Both tests skip with a named reason when their pinned tools are absent or mismatched.

An optional local mutation probe copies the Rego directory into session scratch, inserts one verdict-relevant unvalidated read in that copy and calls `run_vocabulary_case` on the copy. A non-empty difference list shows that the harness can detect that chosen missed read. The pinned checkout is never edited. Independent review must re-derive Conditional Access and privileged-role helper chains by hand as well as with the generator, and review the canonicaliser, salt, qualifier checks, pruning and leakage tests.

## Measured fixture milestone (4 November 2026)

These are fixture figures with the gate unedited, plumbing figures, not coverage claims. The real-format column is a construction, not a real export. The ScubaResults fixture uses each product's actual list of groups; its five controls that are in the assessed set give 1 pass, 2 fail and 2 not assessed. An empty, malformed or repaired baseline is labelled `empty`, `unreadable_layout`, `unreadable_file` or `unreadable_repaired` in the sidecar, never silently presented as a readable baseline. A single TestResults object is accepted as one row. `accepted_domains` needs both EXO and Security Suite ledgers, which can reduce yield on an EXO-only export.

| Product | Clean fixture assessed/total | Real-format construction assessed/total |
| --- | ---: | ---: |
| AAD | 22/31 | 22/31 |
| EXO | 8/12 | 7/12 |
| SECURITYSUITE | 0/21 | 0/21 |
| TEAMS | 6/14 | 6/14 |
| SHAREPOINT | 8/8 | 8/8 |
| POWERPLATFORM | 0/8 | 0/8 |
| POWERBI | 0/8 | 0/8 |
| overall | 44/102 | 43/102 |

### Withheld policies: Clean fixture

| Policy | Withholding section: reason/detail kind or configuration outcome |
| --- | --- |
| MS.AAD.3.3v2 | authentication_method: missing_artifact/- |
| MS.AAD.3.4v1 | authentication_method: missing_artifact/- |
| MS.AAD.3.5v2 | authentication_method: missing_artifact/- |
| MS.AAD.5.2v1 | risky_delegated_permission_classifications: missing_artifact/- |
| MS.AAD.5.3v1 | directory_settings: incomplete_shape/unseen_shape |
| MS.AAD.5.5v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.5.6v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.5.7v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.6.1v1 | domain_settings: missing_artifact/- |
| MS.EXO.1.1v2 | remote_domains: missing_artifact/- |
| MS.EXO.6.1v1 | sharing_policy: incomplete_shape/unseen_shape |
| MS.EXO.6.2v1 | sharing_policy: incomplete_shape/unseen_shape |
| MS.EXO.7.1v1 | transport_rule: missing_artifact/- |
| MS.POWERBI.1.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.2.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.3.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.4.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.4.2v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.5.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.6.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.7.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERPLATFORM.1.1v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.1.2v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.2.1v1 | dlp_policies: missing_artifact/- |
| MS.POWERPLATFORM.2.2v1 | dlp_policies: missing_artifact/-; environment_list: missing_artifact/- |
| MS.POWERPLATFORM.2.3v1 | dlp_policies: missing_artifact/- |
| MS.POWERPLATFORM.3.1v1 | tenant_isolation: missing_artifact/- |
| MS.POWERPLATFORM.5.1v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.6.1v1 | environment_creation: missing_artifact/- |
| MS.SECURITYSUITE.1.1v1 | anti_malware_policies: missing_artifact/-; anti_malware_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.2v1 | anti_malware_policies: missing_artifact/-; anti_malware_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.3v1 | atp_policy_rules: missing_artifact/-; built_in_protection_rules: missing_artifact/-; safe_attachment_policies: missing_artifact/-; safe_attachment_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.4v1 | atp_policy_for_o365: missing_artifact/- |
| MS.SECURITYSUITE.2.1v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.2.2v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.2.3v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.2.4v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.1v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.2v1 | defender_dlp_license: missing_artifact/-; dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.3.3v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.4v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.4.1v1 | protection_alerts: missing_artifact/- |
| MS.SECURITYSUITE.5.1v1 | admin_audit_log_config: missing_artifact/- |
| MS.SECURITYSUITE.6.1v1 | hosted_content_filter_policies: missing_artifact/-; hosted_content_filter_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.6.2v1 | hosted_content_filter_policies: missing_artifact/-; hosted_content_filter_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.1v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.2v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.3v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.8.1v1 | conn_filter: missing_artifact/- |
| MS.SECURITYSUITE.8.2v1 | conn_filter: missing_artifact/- |
| MS.TEAMS.1.7v2 | broadcast_policies: missing_artifact/- |
| MS.TEAMS.2.1v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.2.2v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.2.3v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.4.1v1 | client_configuration: missing_artifact/- |
| MS.TEAMS.5.1v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |
| MS.TEAMS.5.2v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |
| MS.TEAMS.5.3v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |

### Withheld policies: Real-format construction

| Policy | Withholding section: reason/detail kind or configuration outcome |
| --- | --- |
| MS.AAD.3.3v2 | authentication_method: missing_artifact/- |
| MS.AAD.3.4v1 | authentication_method: missing_artifact/- |
| MS.AAD.3.5v2 | authentication_method: missing_artifact/- |
| MS.AAD.5.2v1 | risky_delegated_permission_classifications: missing_artifact/- |
| MS.AAD.5.3v1 | directory_settings: incomplete_shape/unseen_shape |
| MS.AAD.5.5v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.5.6v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.5.7v1 | app_management_policies: missing_artifact/-; default_app_management_policy: missing_artifact/- |
| MS.AAD.6.1v1 | domain_settings: missing_artifact/- |
| MS.EXO.1.1v2 | remote_domains: missing_artifact/- |
| MS.EXO.13.1v1 | org_config: incomplete_shape/unseen_shape |
| MS.EXO.6.1v1 | sharing_policy: incomplete_shape/unseen_shape |
| MS.EXO.6.2v1 | sharing_policy: incomplete_shape/unseen_shape |
| MS.EXO.7.1v1 | transport_rule: missing_artifact/- |
| MS.POWERBI.1.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.2.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.3.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.4.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.4.2v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.5.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.6.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERBI.7.1v1 | powerbi_access_denied_reason: missing_artifact/-; powerbi_license_found: missing_artifact/-; powerbi_tenant_settings: missing_artifact/- |
| MS.POWERPLATFORM.1.1v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.1.2v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.2.1v1 | dlp_policies: missing_artifact/- |
| MS.POWERPLATFORM.2.2v1 | dlp_policies: missing_artifact/-; environment_list: missing_artifact/- |
| MS.POWERPLATFORM.2.3v1 | dlp_policies: missing_artifact/- |
| MS.POWERPLATFORM.3.1v1 | tenant_isolation: missing_artifact/- |
| MS.POWERPLATFORM.5.1v1 | environment_creation: missing_artifact/- |
| MS.POWERPLATFORM.6.1v1 | environment_creation: missing_artifact/- |
| MS.SECURITYSUITE.1.1v1 | anti_malware_policies: missing_artifact/-; anti_malware_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.2v1 | anti_malware_policies: missing_artifact/-; anti_malware_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.3v1 | atp_policy_rules: missing_artifact/-; built_in_protection_rules: missing_artifact/-; safe_attachment_policies: missing_artifact/-; safe_attachment_rules: missing_artifact/- |
| MS.SECURITYSUITE.1.4v1 | atp_policy_for_o365: missing_artifact/- |
| MS.SECURITYSUITE.2.1v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.2.2v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.2.3v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.2.4v1 | anti_phish_policies: missing_artifact/-; anti_phish_rules: missing_artifact/-; defender_license: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.1v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.2v1 | defender_dlp_license: missing_artifact/-; dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/-; scuba_config: operator_input_required |
| MS.SECURITYSUITE.3.3v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.3.4v1 | dlp_compliance_policies: missing_artifact/-; dlp_compliance_rules: missing_artifact/- |
| MS.SECURITYSUITE.4.1v1 | protection_alerts: missing_artifact/- |
| MS.SECURITYSUITE.5.1v1 | admin_audit_log_config: missing_artifact/- |
| MS.SECURITYSUITE.6.1v1 | hosted_content_filter_policies: missing_artifact/-; hosted_content_filter_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.6.2v1 | hosted_content_filter_policies: missing_artifact/-; hosted_content_filter_rules: missing_artifact/-; protection_policy_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.1v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.2v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.7.3v1 | protection_policy_rules: missing_artifact/-; safe_links_policies: incomplete_shape/unseen_shape; safe_links_rules: missing_artifact/- |
| MS.SECURITYSUITE.8.1v1 | conn_filter: missing_artifact/- |
| MS.SECURITYSUITE.8.2v1 | conn_filter: missing_artifact/- |
| MS.TEAMS.1.7v2 | broadcast_policies: missing_artifact/- |
| MS.TEAMS.2.1v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.2.2v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.2.3v2 | federation_configuration: missing_artifact/- |
| MS.TEAMS.4.1v1 | client_configuration: missing_artifact/- |
| MS.TEAMS.5.1v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |
| MS.TEAMS.5.2v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |
| MS.TEAMS.5.3v2 | app_policies: missing_artifact/-; tenant_app_settings: missing_artifact/- |

### Proof-table pruning outcomes

| Section | Proof verdict | Clean keys/outcome | Real-format keys/outcome | Qualifier withheld in either fixture |
| --- | --- | ---: | ---: | --- |
| SPO_tenant | prunable | 0/projected | 3/projected | False |
| accepted_domains | prunable | 0/projected | 2/projected | False |
| authorization_policies | prunable | 0/projected | 4/projected | False |
| conditional_access_policies | prunable | 0/projected | 25/projected | False |
| dkim_config | prunable | 0/projected | 2/projected | False |
| dkim_records | prunable | 0/projected | 6/projected | False |
| dmarc_records | prunable | 0/projected | 6/projected | False |
| meeting_policies | prunable | 0/projected | 2/projected | False |
| org_config | prunable | 0/projected | 12/withheld | False |
| privileged_roles | prunable | 0/projected | 18/projected | False |
| service_plans | prunable | 0/projected | 2/projected | False |
| spf_records | prunable | 0/projected | 3/projected | False |
| transport_config | prunable | 0/projected | 2/projected | False |

Clean pruning total: 0 sections, 0 keys. Real-format pruning total: 13 sections, 87 keys. All 13 proof rows are prunable on the pinned Rego. The real-format `org_config` row remains withheld after 12 keys are removed because the validated `Identity` field is absent.
