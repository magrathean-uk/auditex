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

[1.1.0]: https://github.com/magrathean-uk/auditex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/magrathean-uk/auditex/releases/tag/v1.0.0
