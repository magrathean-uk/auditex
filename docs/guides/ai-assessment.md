# AI assessment

`auditex assess <run-dir>` writes an optional rule-only CISA SCuBA assessment from a finished
Microsoft 365 run's local evidence. It writes private `model_assessment.json` (the file name is kept for
compatibility) without changing findings, scores, reports, exports or customer packs. Nothing is sent anywhere:
the assessment is computed locally from the run bundle.

## What decides each answer

All 102 catalogue policies have value rules across Entra ID, Exchange Online, Power BI, Power Platform,
Defender, SharePoint and Teams. Rule availability does not guarantee a verdict: available evidence, the adapter
and permissions determine whether a policy can be assessed. A catalogue policy without a rule reports not assessed with
`reason: "rule_not_implemented"` and the constant text:

> Not assessed: Auditex has no rule for this policy yet.

On such a row both claims are unknown, with null values and empty evidence IDs. Limitations and recommendations are
empty; attempts and latency are zero; prompt and response hashes are null; thinking flags are false.
IDs outside the catalogue are skipped as `policy_not_in_catalogue`.

For covered policies, a closed applicability gate wins, then missing sections, then the value predicate.
Rules read a private in-memory view captured before the projection's frozen shape gate, budgets and
redaction. Source, ledger, collector-error, qualifier and scan checks still apply. A rule's met, not met,
not assessed or not applicable result carries its cell, reason code and constant text. Missing evidence
uses `section_not_collected`; collected but unusable evidence uses `evidence_unusable` and the relevant
reason. Optional Power BI or Power Platform collection not enabled retains
`optional_collection_not_enabled`. A rule fault reports `rule_evaluation_failed` (a shared reason with a null cell, not a catalogue cell) with
`report_product_fault`. Teams 2.2v2, 2.3v2 and 4.1v1 record a closed applicability gate as class
`value_rule`, cell `closed_gate`. The scope envelope is still collected for review. Row-level scope marking has been removed;
`totals.scope_narrowed` stays zero. Historical model-row metadata remains readable.
See the [output contract](../reference/output-contract.md) for exact fields and policy coverage.

For SS 2.1, supply `--sensitive-users <file>` during collection (or set
`AUDITEX_SENSITIVE_USERS_FILE`). Assessment verifies the saved private list,
count and HMAC before passing bare lower-case addresses to that rule in memory.
With the other required evidence, SS 2.1 can now decide; an absent or unusable
list retains the existing not-assessed outcome. A copied bundle replays the
same way. Addresses never enter assessment outputs.
SS 2.3 uses the separate `--partner-domains <file>` input (or
`AUDITEX_PARTNER_DOMAINS_FILE`); its verified snapshot reaches only that rule's
private in-memory view, independently of SensitiveUsers.
The ScubaGear export configuration path is unchanged.

Collection replaces the transient `TargetedUsersToProtect` list with a bound
`TargetedUsersCoverage` summary before saving evidence or diagnostics. SS 2.1
can establish met from usable membership and the remaining policy conditions.
Invalid, absent or mismatched summaries never fall back to literal targets;
explicit non-compliant flags or actions can still establish not met.
Missing verified private input reports `section_not_collected`.
`config_list_empty` applies only to a direct ScubaGear configuration with no
usable SensitiveUsers entries. A supplied list alone does not establish
compliance. The summary, binding and operator count/HMAC stay out of assessment
outputs, shareable exports and customer packs. See
[TargetedUsersCoverage v1](../reference/output-contract.md#targeteduserscoverage-v1)
for limits, replay and resume behaviour.

## Run and read the result

```sh
auditex assess <run-dir>
auditex assess <run-dir> --policies MS.AAD.3.4v1,MS.POWERBI.1.1v1
```

Assessment needs no endpoint, model name or network access. `--policies` takes a comma-separated list of
policy IDs; the `--projection-max-items`, `--projection-max-chars` and `--projection-scan-*` options set the
projection budgets and scan bounds (`auditex assess --help` lists the defaults). The file is private (0600) and
outside the original bundle seal; a sealed output cannot be replaced. Treat it as confidential evidence.

`auditex assess` has no dry-run, endpoint, model or redaction options, and no `AUDITEX_MODEL_*` or
`AUDITEX_DISABLE_VALUE_RULES` setting is read. The old `model` command is removed: it
exits 2 as an unknown command, and so does any of the removed options (`--endpoint`, `--model`, `--dry-run`, `--no-redaction`,
`--shadow-model-on-precheck`). Redaction is always on.

The envelope keeps historical field names: `endpoint_host` is `none`, `model_name` is `rules-only`, and
there is no `serving` object. `totals.rule_answered` counts rule rows including abstentions;
`totals.unknown` includes all not-assessed rows, including any `rule_not_implemented` row. Confirmed rule
verdicts can agree or disagree with baseline pass/fail statuses; not-assessed rows compare as `not_assessed`.

## Rule pre-checks

A value rule uses the shared closed gate first (the rule's `closed_gate` cell, rendered by
`value_rules/gates.py`), then its own ordered section list, then its kind. The rule engine and catalogue follow
spec v3.9.1 with addenda A1 and A2 (the catalogue's `spec_version` is `v3.9.1`); the cell inventory and reason
codes are checked by the `2026-11-05` assessment validator. The [output contract](../reference/output-contract.md)
lists the policy ids each rule covers. A rule that raises answers the catalogued `rule_evaluation_failed` reason
with the `report_product_fault` recommendation, and logs only the rule id and the exception class.

`configs/scuba-rule-precheck.json` is the shared authority for the gate, field and list rules. For a policy with a
value rule, `precheck_policy` (`scuba_precheck.py`) calls `value_rules.assess` first, and that result is the answer.
`assess` applies, in order:

1. The shared closed gate (`value_rules/gates.py`, which calls `check_gate`): a present, usable gate section and
   field whose typed value is closed. The row is not applicable: requirement `inferred` true, limitations exactly
   `["policy_not_applicable"]`, no recommendations. It wins even when another dependent section is missing or
   marked `not_collected`.
2. The rule's own section list: a missing or `not_collected` section gives an unknown answer naming the
   unavailable sections. A `not_collected` marker is unusable, including a gate section marker.
3. The rule kind, which always answers (a kind with no implementation raises, and the row then answers
   `rule_evaluation_failed`).

The `absent_field` and `empty_required_list` classes (`check_fields`, `check_lists`, the `field_rules` and
`list_rules` entries) and the stand-alone `absent_section` check are compatibility shims. They run only when no
value rule answered, that is for a policy without a catalogue row or when `value_rules` is off, and they still
render the historical `rule_precheck` classes (`closed_gate`, `absent_section`, `absent_field`,
`empty_required_list`) in `model_assessment.json`. With every catalogue policy ruled they do not decide a current
product row. Their behaviour:

- `absent_field`: a field the policy's Rego reads is missing inside a collected section and a registered
  `field_rules` entry covers it (a missing key in the single tenant object, an empty singleton list, or no entry
  whose `settingName` equals the policy's Power BI setting). The answer is unknown, citing the one section.
- `empty_required_list`: a registered `list_rules` entry whose collected list is exactly `[]` for a policy that
  passes only when some entry satisfies it (Conditional Access policies for ten Entra ID policies). The answer is
  confirmed not met, with the one recommendation `review_policy_against_baseline_text`. A list with entries,
  null, an object or a marker is left to the earlier classes. Some entries carry an `unless` condition (for
  example MS.AAD.9.1v1 in the `gcchigh` and `dod` clouds) that leaves the row to the value rule.

| Policies | Decisive field | Closed values |
| --- | --- | --- |
| MS.SHAREPOINT.3.1v1, 3.2v1 | `SPO_tenant.SharingCapability` | `0`, `1`, `3` |
| MS.SHAREPOINT.3.3v2 | `SPO_tenant.SharingCapability` | `0` |
| MS.SHAREPOINT.1.3v1 | `SPO_tenant.SharingCapability` | `0`; doc-sourced |
| MS.TEAMS.2.2v2, 2.3v2, 4.1v1 | `scuba_config.M365Environment` (synthesised; see below) | `gcc`, `gcchigh`, `dod` |
| MS.AAD.3.3v2 | `authentication_method.authentication_method_feature_settings[Id=MicrosoftAuthenticator].State` | `disabled` |

Sharing values mean `0` organisation only, `1` new and existing guests, `2` anyone, `3` existing guests. Real
integers and integral floats are accepted; booleans, numeric strings, fractional and out-of-range values cannot
close a gate. String gates use exact exported values. Singleton object arrays and objects are supported;
empty or ambiguous objects and missing, null or invalid gate fields give unknown. Policies without a registered
value rule report `rule_not_implemented`.

`scuba_config` is ScubaGear's operator configuration, not tenant evidence, so assessment synthesises it (output
contract, `scuba_config` row): ScubaGear's default configuration, the tenant's cloud and the run's
`--break-glass-accounts` list, per policy family. Its projection report entry says so (`synthesis.source`
`synthesised:default-config`, with the cloud and its evidence, the emergency-access counts and each reading
policy's outcome). The cloud comes from the `dns_posture` OpenID discovery when the run has it, else from US
Government licence SKUs, else it is taken as `commercial`.

**DNS evidence for EXO 2.2, 3.1 and 4.1 to 4.4.** The opt-in `dns_posture` collector saves `spf_records`,
`dkim_records` and `dmarc_records` for tenant Exchange accepted domains (coexistence excluded) when complete
same-run `acceptedDomains` evidence is available; otherwise it uses Graph-verified domains with the Email service
(a missing or non-list `supportedServices` field is kept). Records include resolver logs, which the private rule
view keeps and the projection drops before its shape and budget checks. Failed or truncated reads withhold the
dependent sections. `dns_posture` remains outside default collector sets; its public lookups and OpenID discovery
are described in the [privacy model](../reference/security-privacy.md).

The value-rule test vectors live in `tests/fixtures/value-rules/` (constructed rows with vector ids and origins;
see [provenance](../provenance/provenance.md)). `AUDITEX_TEST_VALUE_RULE_VECTORS_V391=<kit vectors.jsonl>`
replays a full source file, and `AUDITEX_TEST_OPA` with `AUDITEX_TEST_SCUBAGEAR` enable pinned offline Rego
replay.

## The retired model layer

The parked verdict model and its tooling were removed (see the [retirement note](model-development.md) and the
changelog). No product answer ever came from a model. A deterministic template explainer ships and is wired
into reports; it describes rule results and never changes a verdict.
