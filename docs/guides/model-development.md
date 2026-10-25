# Auditex model development

Prepare reviewed knowledge for **one base model and one LoRA adapter**. OpenAdmin
and M365 Expert can supply comparison answers for review; their different model
architectures do not make their weights compatible for merging. Collection,
findings and evidence references remain deterministic Auditex responsibilities.

This workflow assembles review materials and supports local GGUF benchmarks.
Training and JUPITER runtime qualification remain separate steps.

## Available materials

Run `auditex model sources` to inspect the pinned source inventory. The prepared
external materials live under `/Volumes/4TB/dev/auditex-data/`:

- Two downloaded, checksum-verified Q4_K_M GGUF comparison models: OpenAdmin 8B
  and M365 Expert v3, approximately 10.2 GB combined. These are inference
  artifacts, not the BF16 training base or compatible adapter weights.
- OpenAdmin's public SFT release contains **499 unique conversations**, rather
  than the full training corpus behind its released 8B model. Its repository
  also contains overlapping assembled runs and separate evaluation material.
- A matching public corpus for M365 Expert's claimed 40,962 examples was not
  established. Do not represent that corpus as acquired.
- The proposed Qwen base revision is pinned in the source catalogue; its
  training weights and the GH200 runtime still need staging and qualification.

`examples/model_development/` supplies 48 synthetic, **unreviewed** Auditex cases
with 32 train, eight validation and eight test cases in separate families.
Recorded response fixtures test file handling; they are not model outputs or
benchmark results. Proposed expected labels are not approved gold labels.
The synthetic generator supplies the same candidate limitation and
recommendation vocabulary to every case, including irrelevant choices. Earlier
v1 prompts supplied the expected selections directly. The current v3 also asks
direct factual questions where earlier proof/meta-questions ambiguously expected
`unknown`. An explicitly unperformed detection exercise now correctly yields
`confirmed: false` for whether validation occurred; attack occurrence remains
unknown. Case IDs and split families are retained; prompt and target hashes
change. Exported examples remain unreviewed proposals.

## Prepare and inspect locally

From the repository root, select the prepared kit directory. Use new output
paths; commands refuse to replace existing results.

```sh
source ~/dev/machine/env.zsh
export AUDITEX_MODEL_ROOT=/Volumes/4TB/dev/auditex-data
export AUDITEX_KIT=/absolute/path/to/the/prepared/development-kit

clean-development run --session session-only -- .venv/bin/auditex model sources
clean-development run --session session-only -- .venv/bin/auditex model stage \
  --manifest "$AUDITEX_KIT/public-source-manifest.json" \
  --output-dir "$AUDITEX_KIT/staged-public-corpus-new"

clean-development run --session session-only -- .venv/bin/auditex model evaluate \
  --cases examples/model_development/cases.jsonl \
  --responses examples/model_development/fixture-model-a.jsonl \
  --output "$AUDITEX_KIT/review/fixture-evaluation-new.json"

clean-development run --session session-only -- .venv/bin/auditex model combine \
  --cases examples/model_development/cases.jsonl \
  --responses examples/model_development/fixture-model-a.jsonl \
  --responses examples/model_development/fixture-model-b.jsonl \
  --output "$AUDITEX_KIT/review/fixture-combined-new.json"

clean-development run --session session-only -- .venv/bin/auditex model prepare \
  --cases examples/model_development/cases.jsonl \
  --output-dir "$AUDITEX_KIT/training-pack-new" \
  --base-model Qwen/Qwen3.8-27B \
  --revision 1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0
```

The assembled public stage contains 4,225 unreviewed candidate conversations;
conflicting prompt variants are quarantined. Its 448 source evaluation YAML
files remain separate and opaque; semantic non-overlap has not been established.
Staging does not turn public conversations into reviewed Auditex examples. Preparation exports
approved prompt/completion records to `train.jsonl` and `validation.jsonl`,
keeps `test.jsonl` separate and places unreviewed cases in `quarantine.jsonl`.
The starter pack therefore has `job_ready: false` and no training rows.

## Case and answer contract

Each JSONL case has `id`, `family`, `split`, `provenance`, `messages` and
`expected`. Provenance records `source`, a boolean `synthetic`,
`review_status` (`unreviewed` or `approved`) and a `reviewer` required for approved
cases (optional for unreviewed proposals). Two optional curation keys are accepted:
`template`, a reasoning-template label, and `distinct_prompt_sha256`, the SHA-256 of the
case-id-masked normalized prompt, so id-only duplicates can be found without a full comparison.
Oracle-labelled cases may also record `evidence_view` (`rego_ast` or `widened`) and `oracle_outcome`
(`met`, `not_met`, `fail_closed_missing_input`, `not_applicable` or `not_collected`) as optional fields; other values
are rejected and `source` stays free text. `auditex.model_training.oracle_provenance(case)` returns both fields and
falls back to the `evidence_view=` and `oracle_outcome=` pairs in `source` when the fields are absent, so scripts can
read either form (a fallback value is not enum-checked). Two further optional provenance keys exist: `consensus_weight`
(`scubagear_only`: a consensus-approved row whose second oracle gives a constant verdict across the fixture family, so
the agreement corroborates nothing) and `adjudication` (`{source, ruling}`: a disagreement-queue row kept after review).
Messages contain string `role`/`content` fields and finish with an assistant
response. Approval describes an actual review; scripts never grant it.

Expected answers contain `claims`, `limitations`, `recommendations` and the
case-local `allowed_evidence_ids`. Each claim has an `id`, a status of
`confirmed`, `inferred` or `unknown`, `evidence_ids`, and an optional typed
JSON `value`. Limitations and recommendations are stable IDs, not free prose.
Recorded answer rows are `{case_id, model_id, response}`; `response` contains
the same three answer fields without the evidence allowlist.

The loader rejects duplicate IDs, family or normalized-prompt leakage across
splits, conflicting prompt labels and approved answers that disagree with their
rubric. Evaluation checks exact claim status, typed values, evidence sets and
gap/recommendation IDs. It does not prove prose entailment or source truth.
Combination requires every supplied model to pass the reviewed rubric; voting
does not establish truth. Only approved **train** cases become candidates.
Export reviewed `training_candidates` as cases JSONL and supply independently
reviewed validation/test cases in separate files using repeated `--cases`.
Public staging records and recorded-response JSONL are not training-case inputs.

## Cases from a directory lab

After collecting a finalized audit of explicitly prefixed synthetic directory
fixtures, export configuration-reasoning proposals locally:

```sh
clean-development run --session session-only -- .venv/bin/python scripts/build-lab-model-cases.py \
  --run-dir /absolute/path/to/finalized-lab-audit \
  --fixture-prefix auditex-lab-example \
  --output-dir /absolute/path/to/new-lab-cases
```

The exporter revalidates the bundle, selects only matching user, group and
application records, and copies a small configuration-field allowlist. It omits
principal names, tenant domains, object GUIDs and timestamps from case content;
fixture label suffixes remain untrusted evidence text. Provenance records source
artifact hashes and record pointers. Missing fields produce unknown targets.
Tenant grouping uses the observed organization UUID when the run manifest lacks
one, and rejects conflicting identities.
Exports cover the matching normalized records only. Paged collectors retain a
20-row inline sample, but current normalization reads all collected chunk rows.
Check `normalization_complete`, endpoint coverage and collection/fan-out limits
before assuming all fixtures appear. Older runs may still contain sample-only
normalization. A valid bundle alone does not establish complete collection.

These are live observations of synthetic fixtures, with unreviewed proposed
answers. Every exported case stays in one tenant-specific **train** family,
including later runs from that tenant. Build independent validation/test
scenarios separately. Exporting cases neither approves targets nor runs a model.

## Oracle-labelled cases

Cases whose labels come from running CISA ScubaGear's Rego policies, a deterministic open-source
engine, offline over fictional tenant configurations. No tenant is contacted. Needs a ScubaGear
checkout (`PowerShell/ScubaGear`, pinned commit in `configs/assessment-sources.json`) and OPA 1.20.2,
the version ScubaGear pins; OPA 1.21 rejects a helper in `Rego/Utils/TestAssertions.rego`. The
tests in `tests/test_oracle_cases.py` that parse and evaluate Rego run when `AUDITEX_TEST_OPA` is
exported, and the end-to-end ones when `AUDITEX_TEST_SCUBAGEAR` is exported as well (optionally
`AUDITEX_TEST_ORACLE_REFERENCE` for a label comparison, `AUDITEX_TEST_ORACLE_V4_AAD` for a byte comparison of the `combined` AAD run with a stored v4 `cases-aad.jsonl`); otherwise they are skipped.

```sh
clean-development run --session session-only -- .venv/bin/python scripts/build-oracle-cases.py \
  --scuba /absolute/path/to/ScubaGear/PowerShell/ScubaGear --opa /absolute/path/to/opa-1.20.2 \
  --output-dir /absolute/path/to/new-oracle-cases [--products PowerPlatform ...] [--not-collected-every 4] \
  [--evidence-view rego_ast|widened] [--no-expression-patches] [--ca-bases single-purpose|combined]
# --ca-bases single-purpose (default) drops Conditional Access `met` cases mined from ScubaGear's combined unit-test
# base policy and generates per-item single-purpose bases (ids salted conv3-sp); `combined` reproduces the pre-25 Oct output.
clean-development run --session session-only -- .venv/bin/python scripts/split-oracle-cases.py \
  --cases /absolute/path/to/new-oracle-cases/cases.jsonl \
  --output /absolute/path/to/new-oracle-split/cases.jsonl --approve-as-oracle
```

`build-oracle-cases.py` loads each product's base fixture, builds for every unit test CISA wrote against it
the tenant that test describes (one test = one tenant variant), evaluates the variants, and writes one case per
distinct (policy, evidence view): `requirement_met` confirmed true or false (or one of the engine outcomes below),
plus a share of the cases (`--not-collected-every`, default one in four) with one section marked
`not_collected` and an `unknown` answer. The output directory is new (`cases.jsonl`,
`cases-<product>.jsonl`, `summary.json`, `variants-<product>/`); an existing one is refused. Every case
carries the commit, policy id, test name, OPA version, input hash and CISA's ReportDetails in
`provenance.source`; `provenance.evidence_view` (`rego_ast` or `widened`, per policy) and
`provenance.oracle_outcome` (`met`, `not_met`, `fail_closed_missing_input`, `not_applicable` or
`not_collected`) as first-class fields, as the contract above defines them (`source` carries no
`evidence_view=` or `oracle_outcome=` pairs; `oracle_provenance` still reads them from older output); a
`provenance.template` of `<product>/<policy id>/<mutation family>` (which fields of its evidence the
variant changes; `not_collected:<section>` for gap cases) and `provenance.distinct_prompt_sha256`. Cases are
written `unreviewed` in `train`.

Case ids. The id is the policy and a hash of the evidence view salted with the labelling convention
(`conv3`, recorded as `labelling_convention` in `summary.json`), so an id never names two different cases
across packs. The ids of the 20261019 kit were unsalted: an earlier revision of this miner reused 464 of them
(every SharePoint id) for cases whose content differed, 14 with a different label; salted, no id is shared. The id
still hashes the view, so a different view or method gives a different id. To join two packs on the same variant use the policy id and `variant=` in the source.

Labelling conventions. A convention fixes what the labels cite, which codes the system prompt asks for and how absence
is rendered. It is salted into every id (`<convention>:<view>`), so the same policy and variant has one id per
convention, and it is recorded once per pack in `summary.json`.

| | conv2 | conv3 (current) |
| --- | --- | --- |
| `requirement_met` met, not met, not applicable | the data sections of the view | `e0`, then the data sections of the view |
| `requirement_met` unknown (section not collected, field missing, setting unreadable) | the section that is hidden, lacks the field or could not be read | `e0`, then that section, and any section shown as not collected |
| `policy_criticality` | `e0` | `e0` |
| A field the policy reads that an object of a section lacks, engine evaluated | absent | explicit `null` in every object (`null_fields` in `summary.json` lists the paths per policy) |
| The same, engine failed closed on a missing input | absent | absent, so that the unknown label stays readable |
| Top-level key the variant removed from the base input, engine failed closed | `null` | the not-collected marker, cited by the label |
| Section hidden in a not-collected case | hash of the conv2 id | the same (`MASK_ID_SALT`, fixed) |
| System prompt | no rule on citations or on which codes a verdict carries | cite `e0` on every claim about the requirement and every section the policy depends on (an unknown verdict: only the sections not collected, lacking the field or unreadable); states the limitation and recommendation codes of a not-met, unknown and not-applicable verdict; a field shown as null means the export holds no value and the policy's default applies |
| Id | `conv2:<view>` | `conv3:<view>` |

`e0` is the policy item (`policy_id`, `criticality`, `baseline_text` and, where the policy has a gate,
`applicability`). conv3 puts it in the label because the baseline text and the gate sentence a verdict rests on
live there: in the blind review of the v3 holdout (`reviews/20261022-heldout-blind-review-v3`) reviewers agreed
with the label on 293 of 300 claims but strictly on 96 of 300, and of 197 evidence mismatches 140 cited `e0` on
`requirement_met` where the conv2 label cited the data sections only, and 50 left out a dependency section the
label includes (a section that does not change the answer for that tenant is still a dependency); reviewers also
omitted `review_policy_against_baseline_text` on 35 not-met verdicts because the conv2 prompt never said it is
expected. The adjudication of the seven remaining disagreements found five caused by rendering: a field the policy
reads (MS.AAD.9.1v1 reads agent-identity and agent-risk fields that conditional access policies of reused fixtures
never carry) was simply missing, so a reader could not reach the engine's not-met, and a key the variant removed
(Power BI `LicenseVariableMissing`, `PowerBITenantSettings_Missing`) read as null while the label was unknown.

How fields are found. `rego_ast_field_reads` walks the parsed Rego like the dependency scan, and follows data as well as
rules: a variable bound by `some x in input.<section>`, `x := input.<section>[_]`, `every`, a comprehension or a rule value,
and the arguments of a function call into the function's parameters, so `policy.Conditions.AgentIdRiskLevels` in a helper
called with an item of `conditional_access_policies` is the read `conditional_access_policies.*.Conditions.AgentIdRiskLevels`
(`*` is any item). The message fields of the head are skipped as for views. A field is shown as null at the first level an
object lacks it (`Conditions.ClientApplications` when the whole `ClientApplications` object is missing). Only the `rego_ast`
method does this; the earlier `widened` method does not parse Rego for fields. Fields of `scuba_config`, a configuration
document rather than an export, are rendered the same way (623 of the changed cases differ in `scuba_config` alone).

Conv2 and conv3 packs of the same harvest hold the same cases: at the pinned commit 4,248 each, no id in common, joined one
to one on policy id and `variant=`, with every verdict, limitation, recommendation and outcome unchanged and the same
section hidden in every not-collected case. The evidence differs in 1,665 of the 4,248 (1,641 with a field shown as null, 24
with a removed key shown as not collected; AAD 1,436 cases carry a field rendered null, Security suite 143, Teams 14, Power BI 48);
the `requirement_met` citation differs beyond `e0` in 8 (the Power BI `NoLicense_TakesPrecedence_OverMissingTenantSettings`
variants cite the removed settings as well as the licence flag). Eight Power BI cases whose removed settings now read exactly
like a not-collected case merge with it, so the splitter keeps 3,970 cases and a 435-row test split, against 3,978 and 436
under conv2.

Do not mix conventions. A pack, a training set and an evaluation set must come from one convention: a model
trained on conv2 labels learns not to cite `e0` and fails strict evidence matching on every conv3 requirement claim, and
the prompts differ, so one case would carry two different answers. Rebuild instead of editing ids or citations in an
existing pack, split the pack of one convention only, and compare packs by the policy and `variant=` join, never by id.

Evidence views (`--evidence-view`, recorded in `summary.json`). The default, `rego_ast`, cites only
the sections the policy reads: `opa parse --format json` gives the AST of the product's policy file and
of every `Rego/Utils` package, and every `input.<section>` or `object.get(input, "<section>", ...)`
reachable from the policy's `tests contains` rules through helper rules and functions (body references,
imported Utils packages, `else` branches; transitively) is a dependency. References reached only through
a rule's `ReportDetails` or `ErrorDetails` field are not evidence, because that text does not decide
`RequirementMet` (without this, `module_version` would sit in the views of several SharePoint, Teams and
Defender-suite policies, and the Power BI views would carry the licence-reason text). The view is then
checked against the variants: if two variants share a view but carry a different verdict or engine outcome
(a not-applicable pass is not an evaluated pass), or the policy reads no input, the view is widened one
section at a time and the policy is recorded as `evidence_view: widened` (in `summary.json` under
`evidence_views`, with the dependencies, the sections added and the reason `verdict_conflict` or
`no_dependency`); otherwise as `rego_ast`. At the pinned commit none of the 102 policies needed the
fallback. `widened` is the earlier method: the sections named in each rule head, widened the same way, which
ended in whole-tenant views for most policies. **Packs built with the two methods must not be mixed**: the
same policy and variant carries different evidence under a different id, and a smaller view merges variants
that differ only in unread sections, so there are fewer cases (4,248 against 5,850 with the same harvest and
label rules at the pinned commit).

The tenant of a test. With `--expression-patches` (the default) the input of each unit test is the one OPA
builds for it: the statements before its `Output := <package>.tests` line become a throwaway rule next to the
fixture and helpers, whose value is `input` under the test's own `with` clauses, evaluated against the base
input. Whatever expression builds a value (a `sprintf` path through a helper, a variable, a function call, a
string such as `with input.tenant_id as "Test Id"`, a nested `with input.scuba_config.Aad[...].CapExclusions...`
path) therefore means what it means to CISA. The Python replay of `json.patch` and `with input... as` is the
fallback for a test OPA cannot evaluate and the whole harvest under `--no-expression-patches`; it reads string
literals, `Name[0]` and nested lists too, and a literal defined inside a test shadows one of the same name in the
file. `harvest_resolved` in `summary.json` counts the variants OPA supplied (`opa_probe`,
`opa_probe_identical_to_base`), the tests the replay could not follow (`replay_could_not`) and those where it
built a different input (`replay_differed`). At the pinned commit OPA builds the input of 834 variants and 55
more tests evaluate to the base input (`identical_to_base`); the replay could not follow 88 of these tests (Power BI 39,
AAD 25, Defender suite 12, Exchange 10, Power Platform 2) and built a different input for 118 (AAD 107, Exchange 7,
Defender suite 3, Power Platform 1), mostly by ignoring a nested `scuba_config` path or a `with` value it could not
read. Two kinds of test describe no tenant and are skipped under their own reason: `empty_tenant_input`, an input
that holds none of the product's input keys (CISA's `NotImplemented` tests run `with input as {}`: AAD 3, Defender
suite 3, Power Platform 2), and `non_object_input`, an input that is not an object (the 8 SharePoint
`*_SharepointSettings_Missing` tests run `with input as []`). Nothing else is skipped. Against CISA's own
expectations (the last argument of each test's `TestResult(...)`, rows the engine answers as not applicable or
fail-closed left out) the earlier harvest disagreed on 47 of 553 comparisons and this one on 5 of 634 (two in AAD
and three in the Defender suite, where CISA's sparse test input meets a full tenant); the dropped `tenant_id`
string had flipped variants of MS.POWERPLATFORM.2.1v1 and 2.3v1.

A section the fixture does not define stays absent. The base input holds only the objects the fixture maps onto
`input.<key>`; nothing is invented for the others. An invented `[]` or `{}` is evidence nobody collected, and for a
key read with `object.get` it changes the verdict (an empty `powerbi_access_denied_reason` list reads as "access
denied", so the earlier Power BI set had no case labelled met; 17 of its 19 sections per case were invented).
`absent_keys` in `summary.json` lists the sections missing from each product's base input (Teams
`tenant_app_settings`, the Defender suite's `hosted_content_filter_*`, AAD `app_management_policies` and
`domain_settings`; the list also holds keys only another product's Utils read, such as `defender_license`), and some of
them appear in the variants whose test sets them.
A policy whose section is absent has no result for that variant, so it produces no case there. Measured against
inventing them: 849 variants, every one with a different input; the evaluated results change for 687 of them and
for 5,338 of 20,502 (variant, policy) results, which include the ReportDetails text (AAD 2,354 of 12,598, Defender
suite 1,050 of 3,558, Power BI 1,520 of 1,616, SharePoint 234 of 733, Power Platform 108 of 310, Teams 72 of 1,051,
Exchange 0 of 636).

Engine outcomes that are not plain verdicts:

- A false whose ReportDetails says an input is "... missing from input JSON", or that a Power BI tenant could not
  be read ("Unable to evaluate tenant setting": no licence found, or the Admin API refused with 401 or 403), is
  the engine failing closed, not a finding. The case labels `requirement_met` `unknown` (null), cites the section
  that lacks the field (for an unreadable tenant the licence flag, or the access-denied reason), with
  `required_evidence_section_not_collected` and `collect_missing_evidence_section`
  (`oracle_outcome: fail_closed_missing_input`; SharePoint 31, Power BI 96, of which 48 unreadable tenants).
- A pass because the policy does not apply ("only applicable if the external sharing slider ... is set to
  Anyone", the Teams GCC, GCC High and DoD skips, the Authenticator gate of MS.AAD.3.3v2) is `requirement_met`
  `inferred` true with the limitation `policy_not_applicable` (`oracle_outcome: not_applicable`; SharePoint 116,
  AAD 85, Teams 23). The applicability sentence is quoted as `applicability` in the policy evidence of every case
  of that policy, so the gate is visible whatever the label. The sentence is the engine's, checked against its Rego:
  SharePoint 1.3, 3.1, 3.2 and 3.3 apply or not by the slider value, Teams 2.2, 2.3 and 4.1 by
  `scuba_config.M365Environment`, and MS.AAD.3.3v2 is also not applicable whenever a conditional access policy
  already enforces phishing-resistant MFA, which the engine's sentence omits, so `APPLICABILITY_NOTES` names both
  conditions. `policy_not_applicable` is in every case's candidate limitations and the system prompt states the
  rules.
- Precedence: a missing field does not make a case unknown when the applicability condition is visibly unmet. The
  gate is learned from the engine's own answers: a field named in the policy's missing-input message whose values
  in evaluated results never occur in not-applicable ones (SharePoint's `SharingCapability`: `{0}` for 1.3 and 3.3,
  `{0, 1, 3}` for 3.1 and 3.2, found automatically, `gates` in `summary.json`). A missing-input result whose evidence
  shows such a value is not applicable (7 SharePoint cases, formerly fail-closed); one that lacks the gate field
  itself, or has the gate met and the setting missing, stays unknown.
- Rows that are not verdicts are dropped: the `Shall/Not-Implemented` skip row of a policy that also has verdicts
  (MS.AAD.9.1v1 in GCC High and DoD answered a false) and non-boolean results, counted as `not_a_verdict`. A policy
  whose rows are all Not-Implemented has no view, and its rows count as `policy_skipped`.
- A verdict needs something observed. A section of a case's view can be null: that means the export holds no object
  for it and the policy's default applies, which the system prompt says in one sentence and keeps apart from a section
  marked not collected. Every one of the 258 confirmed labels that cite a null section (Power BI 187,
  Defender suite 24, AAD 23, Teams 15, Power Platform 8, Exchange 1; 187 of them `powerbi_access_denied_reason`) is on
  an input that lacks the key, so the label is what the Rego gives for an absent key. A verdict whose view sections
  are all absent is no case (`empty_tenant_input` in the case stats; none remain), and a policy whose only section
  is absent is labelled unknown like a missing input (`absent_dependency`: MS.AAD.6.1v1 on the base fixture, which
  has no `domain_settings`).
- A not-collected variant (`oracle_outcome: not_collected`) hides one section the policy reads that holds data in
  that variant, chosen by a hash of the view id (salted with `MASK_ID_SALT`, fixed, not with the convention) among such sections, and never an engine outcome above. A policy whose
  view is a single section never gets one (it would leave nothing to read). One gap case is owed for every N cases and
  issued at the next eligible case, so a skipped position only delays it: the share is one in N where eligible cases
  exist (AAD 25%, Defender suite 25%, Teams 25%, Power Platform 20%, Power BI 25%, Exchange 10% because 93 of its cases have
  one section) and
  SharePoint has none, all its views being the single section `SPO_tenant`.

Output of a full run at the pinned commit (default options), cases by product: AAD 2,552, Exchange 118,
Defender suite 448, SharePoint 464, Teams 226, Power Platform 64, Power BI 376; 4,248 cases, 3,970 with distinct
prompts (conv2, same harvest: 3,978; the earlier packs: 4,247 and 3,780). Evidence sections per case (median and maximum) in the earlier packs
against now: AAD 2 and 25 against 2 and 3, Exchange 1 and 3 against 1 and 3, Defender suite 3 and 25 against 4 and
6, SharePoint 16 and 16 against 1 and 1, Teams 21 and 21 against 1 and 2, Power Platform 20 and 20 against 2 and 2,
Power BI 19 and 19 against 3 and 3.

`split-oracle-cases.py` first keeps the first case of each `distinct_prompt_sha256`, then splits by
whole policy group and whole template, so no family or template appears in two splits. Per product
the last group becomes test, the one before it validation, the rest train; products with fewer than
three groups stay in train. `split-report.json` (beside the output) records counts, families,
distinct counts and a leakage check per split, and `test_sha256`, the hash of the test split as
written, which freezes the holdout. The hash changes if approval is toggled; `test_ids_sha256` does
not. Both files are new: created exclusively with mode 0600 (new parent directories 0700), and an
existing file, a symlink, the same path for output and report, or a location inside a finalized audit
run is refused.

Deduplication matters for the holdout. At the pinned commit the deduplicated test split of the earlier (`widened`) packs has 280 rows.
`auditex model prepare` removes id-only duplicates from train and validation only and writes
`test.jsonl` as given, so a pack prepared from an approved file that was not deduplicated carries
more test rows (371 in the first oracle training pack, prepared from the un-deduplicated prototype file).
Benchmarks run on that 371-row test split are not on the frozen holdout; identify the holdout by
`test_sha256` or `test_ids_sha256` from `split-report.json`.

Approval convention (provisional, pending G's confirmation): `--approve-as-oracle` sets
`review_status: approved` and `reviewer: oracle:cisa-scubagear@<commit>/opa-<version>; deterministic
policy evaluation, no human review`, so `auditex model prepare` accepts the rows. `<commit>` is the
12-character short commit the miner records in every case's `provenance.source` (`summary.json`
holds the full 40-character commit under `oracle.commit`). Approval is strict: only unreviewed,
`synthetic: true` cases that name no reviewer and whose source matches the miner's
`oracle:cisa-scubagear@<hex commit> ...; opa=<x.y.z>; ...` form are approved; anything else is an
error, and already-approved cases are left untouched. It is a labelling convention, not a human
review; the scripts never grant any other approval.

Caveats:

- Labels are deterministic engine output, not human judgement, and inherit any gap between ScubaGear's
  policy logic and its baseline text. Fixtures are fictional; the mutations are CISA's, so coverage
  follows what CISA tests, not what tenants do.
- A `rego_ast` view is the policy's dependency set, which is the least that can decide its verdict, not
  what an auditor would cite: a policy reads `scuba_config` or a licence flag that the auditor would not
  quote, and a section a policy reads only on a branch the variants never take is still a dependency.
  The widening check only proves the view is sufficient for the variants mined. A local variable that
  shares a rule's name is treated as that rule, which can only widen a view.
- Outcomes are classified from ReportDetails wording ("missing from input JSON", "Unable to evaluate tenant
  setting", "only applicable" and "not applicable"), so a new engine message outside those patterns would be
  labelled as an ordinary verdict. Two such messages existed at the pinned commit and were first labelled as
  ordinary verdicts: Power BI's "Unable to evaluate tenant setting" and the GCC High and DoD skip row of
  MS.AAD.9.1v1; both are handled now. The learned gate needs both an evaluated and a not-applicable answer for
  the policy in the variants mined, and a gate field that never varies is not found.
- A variant is a full tenant: the base fixture under a test's own overrides, where CISA's unit test evaluates a
  sparse input. The engine's verdict on such a tenant can differ from the test's expectation (MS.AAD.3.3v2 is not
  applicable once the base tenant's phishing-resistant MFA policy is in place; five rows disagree outright).
- Earlier packs and reviews (the 20261019 kit, 4,247 cases) were built with `--evidence-view widened`, without
  expression patches, with invented empty sections, unsalted ids and the earlier label rules; they stay valid
  as built but must not be mixed with a current pack.
- The `policy` evidence quotes baseline text, partly adapted from Microsoft documentation under
  CC BY 4.0. Attribute Microsoft and CISA when redistributing, or strip `baseline_text`. ScubaGear is
  CC0 1.0 and is not vendored; CISA does not endorse Auditex or models trained on this data. See
  [Source provenance](../provenance/provenance.md#oracle-labelled-cases).

### Second oracle: Prowler consensus

A second deterministic engine, the Microsoft 365 provider of Prowler, checks the same fictional tenants so that each
ScubaGear label can be confirmed by consensus. `scripts/build-prowler-cases.py` rebuilds, for every variant in
`variants-<product>/`, the Prowler service objects the mapped checks read (Prowler's own pydantic models, imported from a
checkout; nothing is copied), runs each mapped check's `execute()` against a stub client that has no Graph, PowerShell or
network access, and compares the verdict with each case's `requirement_met` label. `configs/oracle-policy-map.json` pairs
52 ScubaGear policies (AAD 22, EXO 8, SecuritySuite 11, SharePoint 2, Teams 9) with 49 Prowler checks in 54 rows, 13 `exact`
and 41 `partial`, and lists 100 further Prowler checks as Prowler-only. Rows were paired by reading both rule sets and the
check code. `exact` means both engines test the same setting with the same pass condition; `partial` means overlapping but
different conditions (another threshold, a subset of the settings, another scope, another evidence source), so a
disagreement there is expected and is not by itself a wrong label. Rows that share a ScubaGear policy are conjunctive parts
(MS.AAD.3.5v2 needs both authentication-method checks). The map has no alternative or sufficient-condition rows, so a Prowler
check that only sufficiently implies a ScubaGear policy stays Prowler-only: `defender_strict_preset_security_policy_enabled`
does not test recipient coverage, so it does not imply the preset branches of the ScubaGear Defender policies.

Policies with no Prowler counterpart (so every case is `policy_not_mapped`): AAD 3.1, 3.4, 7.2, 7.4, 7.5, 7.7 to 7.9 and 9.1;
EXO 2.2, 4.3, 4.4 and 6.1; SecuritySuite 1.2, 2.1 to 2.3, 3.1 to 3.4, 4.1 and 6.1; SharePoint 1.2, 2.1, 2.2 and 3.1 to 3.3;
Teams 1.4, 1.7 and 5.1 to 5.3; every Power Platform and Power BI policy.

Setup, once per session. The reference checkout `~/dev/opensource/auditex-references/prowler` is pinned at commit
`f45173997b8331e6cba3deac78bc2e1043b9281d` and sparse to `mcp_server`, `prowler` and `tests/providers/m365` (69 MB; its
`sparse_paths` in `sources.json`), so it goes straight into `--prowler-root` and nothing is cloned for a run. Prowler's
classifiers list Python 3.10 to 3.13 and its models use `pydantic.v1`, which pydantic does not support on 3.14, so use 3.12.
Prowler has no m365 extra; the environment installs only what the Microsoft 365 provider imports, held to the versions
Prowler's own `pyproject.toml` pins (its `dependencies` and `[tool.uv] constraint-dependencies`, written to a constraints
file). It is about 190 MB under `$CLEAN_DEV_BUILDS`.

```sh
P=~/dev/opensource/auditex-references/prowler; B="$CLEAN_DEV_BUILDS/prowler-m365"; mkdir -p "$B"
uv venv --python 3.12 "$B/venv"
"$B/venv/bin/python" - "$P/pyproject.toml" "$B/constraints.txt" <<'EOF'
import sys, tomllib
doc = tomllib.load(open(sys.argv[1], "rb"))
open(sys.argv[2], "w").write("\n".join(doc["project"]["dependencies"] + doc["tool"]["uv"]["constraint-dependencies"]) + "\n")
EOF
uv pip install --python "$B/venv/bin/python" -c "$B/constraints.txt" pydantic msgraph-sdk microsoft-kiota-abstractions \
  azure-identity msal colorama dnspython python-dateutil pyyaml jsonschema pytest

"$B/venv/bin/python" scripts/build-prowler-cases.py --kit-dir /absolute/path/to/20261019-oracle-cases --prowler-root "$P" \
  --output-dir /absolute/path/to/new-prowler-consensus --products AAD EXO SecuritySuite Sharepoint Teams PowerPlatform PowerBI
AUDITEX_TEST_PROWLER_ROOT="$P" PYTHONPATH=src "$B/venv/bin/python" -m pytest tests/test_prowler_cases.py
```

The project `.venv` lacks Prowler's dependencies, so `tests/test_prowler_cases.py` skips the Prowler-backed tests there
(the map, evidence-helper, consensus and parsing tests still run); in the 3.12 environment all of them run, including one
offline real-check test per product (Entra, Exchange, Defender with Purview, SharePoint, Teams) with `socket.connect`,
`sendto` and `getaddrinfo` blocked, and a consensus-count test on a tiny synthetic kit. The test that checks every mapped
policy against the miner's policy list reads `AUDITEX_TEST_ORACLE_KIT` (default: the 20261019 kit under
`~/dev/machine/work/auditex-data/development-kit`) and skips when it is absent. The output directory is new; an existing
one is refused. `--products` defaults to AAD. It holds:

- `verdicts.jsonl`: one row per (variant file, policy, check): `variant`, `scubagear_policy`, `prowler_check`, `status`
  (`PASS`, `FAIL`, `MANUAL`) and `status_extended`, plus `confidence`, `assumptions` and `input_sha256`. `status` is
  `UNMAPPED` with a `reason` when the evidence cannot be expressed as Prowler's models (`evidence_missing:<section>.<key>`,
  `shape:<detail>`), ScubaGear never exports the setting the check reads (`not_exported:<what>`), the check found nothing
  to report (`no_finding`), ScubaGear skips the policy in a US Government region (`scubagear_not_applicable:us_government_region`,
  with Prowler's own verdict kept in `prowler_status`), or no builder exists (`no_builder`; none at present).
- `consensus.jsonl`: one row per ScubaGear case with both verdicts and `consensus`: `agree`, `disagree` or `unmapped`
  (reasons: `policy_not_mapped`, `scubagear_label_unknown` for the deliberate collection-gap cases, `prowler_manual`, or an
  unmapped verdict reason). A `FAIL` part decides a conjunctive policy, otherwise any unmapped part leaves it unmapped.
- `unmapped-evidence.json` (rows by reason and check, with example variants) and `summary.json` (counts per product and
  policy, the commits, `checks_executed` and `checks_not_evaluated` per product).

How a variant becomes Prowler evidence. A setting the check reads and the variant carries is passed through unchanged. A
setting the check reads and the variant lacks is either central, so the row is UNMAPPED (`evidence_missing`), or peripheral,
meaning ScubaGear never exports it: it is then assumed compliant, so the verdict can fail only on exported evidence, and the
assumption is written on every row it touched. The assumptions are:

- Safe Links `AllowClickThrough` and `DisableUrlRewrite` off; Safe Attachments `Enable` on and `QuarantineTag` admin-only;
  Safe Documents on with click-through blocked; anti-phishing spoof intelligence, DMARC honouring and the quarantine actions
  at Quarantine; the SharePoint allowed or blocked domain list non-empty when its mode is selected.
- The default anti-malware policy is the one whose identity is `Default` (ScubaGear does not export `IsDefault`). Prowler's
  own recommended file-type list has 53 entries and every fixture blocks exactly `exe`, `cmd` and `vbe`, so the run sets Prowler's
  `recommended_blocked_file_types` audit config to those three; without that the check fails every fixture.
- A DMARC domain with no TXT data is read as a confirmed absence, because ScubaGear does not distinguish a failed lookup. The
  TXT data is fed through Prowler's own record parsing by an offline stand-in for its DNS resolver, so nothing is looked up.
- Prowler reads only the Global entry of the Teams meeting, federation and client configurations; other entries (ScubaGear
  reads all of them) are recorded as not read, and a variant without a Global entry is UNMAPPED.
- Rule priorities (which Prowler only prints) are reported as 0 where ScubaGear omits them.

Three mapped Exchange checks have no evidence in the kit and are reported as `not_exported` for every case, not guessed:
`defender_antispam_outbound_policy_forwarding_disabled` (Prowler reads outbound spam policies, the kit has remote domains),
`exchange_external_email_tagging_enabled` (native external tagging against transport rules) and
`admincenter_external_calendar_sharing_disabled` (the sharing policy's Enabled flag against its shared domains). The Admin
Center password check (MS.AAD.6.1v1) is `evidence_missing:domain_settings`: that section is empty in every variant.

Prowler checks that ran, per product (a check that ran on at least one variant):

| Product | Checks |
|---|---|
| AAD (20) | `entra_legacy_authentication_blocked`, `entra_identity_protection_user_risk_enabled`, `entra_conditional_access_policy_block_high_medium_sign_in_risk`, `entra_users_mfa_enabled`, `entra_admin_users_phishing_resistant_mfa_enabled`, `entra_managed_device_required_for_authentication`, `entra_managed_device_required_for_mfa_registration`, `entra_conditional_access_policy_device_code_flow_blocked`, `entra_authentication_method_authenticator_show_context`, `entra_authentication_method_sms_voice_disabled`, `entra_authentication_method_email_otp_disabled`, `entra_thirdparty_integrated_apps_not_allowed`, `entra_policy_restricts_user_consent_for_apps`, `entra_policy_guest_users_access_restrictions`, `entra_policy_guest_invite_only_for_admin_roles`, `entra_admin_consent_workflow_enabled`, `entra_default_app_management_policy_enabled`, `entra_admin_users_cloud_only`, `entra_pim_global_administrator_approval_required`, `admincenter_users_between_two_and_four_global_admins` |
| EXO (4) | `exchange_transport_config_smtp_auth_disabled`, `exchange_organization_mailbox_auditing_enabled`, `defender_domain_dkim_enabled`, `defender_domain_dmarc_records_published` |
| SecuritySuite (10) | `defender_malware_policy_comprehensive_attachments_filter_applied`, `defender_malware_policy_common_attachments_filter_enabled`, `defender_safe_attachments_policy_enabled`, `defender_atp_safe_attachments_and_docs_configured`, `defender_antiphishing_policy_configured`, `defender_antispam_policy_inbound_no_allowed_domains`, `defender_antispam_connection_filter_policy_empty_ip_allowlist`, `defender_antispam_connection_filter_policy_safe_list_off`, `defender_safelinks_policy_enabled`, `purview_audit_log_search_enabled` |
| SharePoint (2) | `sharepoint_external_sharing_restricted`, `sharepoint_external_sharing_managed` |
| Teams (9) | `teams_meeting_external_control_disabled`, `teams_meeting_anonymous_user_start_disabled`, `teams_meeting_external_lobby_bypass_disabled`, `teams_meeting_dial_in_lobby_bypass_disabled`, `teams_meeting_recording_disabled`, `teams_external_domains_restricted`, `teams_external_users_cannot_start_conversations`, `teams_unmanaged_communication_disabled`, `teams_email_sending_to_channel_disabled` |
| PowerPlatform, PowerBI | none; Prowler has no Power Platform or Power BI checks |

Result on the 20261019 kit (ScubaGear `2446ad7`, Prowler `f451739`, all variant files of the seven products). Of 4,247
cases, 1,872 have a mapped policy, a confirmed label and a Prowler verdict: 1,653 agree and 219 disagree; 2,375 are unmapped.
By confidence, `exact` rows 466 agree and 34 disagree (all 34 in AAD, see below), `partial` rows 1,187 agree and 185 disagree.

| Product | Cases | Agree | Disagree | Unmapped | label unknown | policy not mapped | not exported | not applicable | other |
|---|---|---|---|---|---|---|---|---|---|
| AAD | 2,294 | 1,224 | 121 | 949 | 476 | 390 | 0 | 0 | 83 |
| EXO | 81 | 27 | 2 | 52 | 12 | 26 | 14 | 0 | 0 |
| SecuritySuite | 654 | 147 | 49 | 458 | 96 | 322 | 0 | 0 | 40 |
| SharePoint | 464 | 79 | 8 | 377 | 18 | 348 | 0 | 0 | 11 |
| Teams | 482 | 176 | 39 | 267 | 83 | 152 | 0 | 18 | 14 |
| PowerPlatform | 152 | 0 | 0 | 152 | 0 | 152 | 0 | 0 | 0 |
| PowerBI | 120 | 0 | 0 | 120 | 0 | 120 | 0 | 0 | 0 |
| Total | 4,247 | 1,653 | 219 | 2,375 | 685 | 1,510 | 14 | 18 | 148 |

`other` is, for AAD, 57 `shape` (a few unit tests put empty strings in enumerations such as `BuiltInControls`, a non-GUID
`GuestUserRoleId`, or two authorization policies, none of which Prowler's models can hold), 20 `no_finding`
(MS.AAD.7.6v1: the variant has no Global Administrator approval rule, so Prowler reports nothing), 5 `prowler_manual` (custom
authentication strengths) and 1 `evidence_missing` (MS.AAD.6.1v1); for SecuritySuite 35 `no_finding` (an empty policy list,
or only presets beside a rule for an absent custom policy, so Prowler judges nothing) and 5 `evidence_missing`
(anti-phishing policies without the safety-tip settings); for SharePoint 11 `evidence_missing` (a tenant
export without `SharingCapability` or `SharingDomainRestrictionMode`, or empty); for Teams 14 `evidence_missing` (no Global
meeting policy). The `label unknown` cases are the deliberate collection-gap variants, which are never compared.

AAD per policy:

| ScubaGear policy | Confidence | Agree | Disagree |
|---|---|---|---|
| MS.AAD.1.1v1 | exact | 49 | 30 |
| MS.AAD.2.1v1 | partial | 71 | 8 |
| MS.AAD.2.3v1 | partial | 68 | 8 |
| MS.AAD.3.2v2 | partial | 65 | 12 |
| MS.AAD.3.3v2 | partial | 94 | 9 |
| MS.AAD.3.5v2 | partial | 138 | 0 |
| MS.AAD.3.6v1 | partial | 31 | 37 |
| MS.AAD.3.7v1 | partial | 80 | 0 |
| MS.AAD.3.8v1 | partial | 74 | 4 |
| MS.AAD.3.9v1 | exact | 66 | 4 |
| MS.AAD.5.1v1 | exact | 5 | 0 |
| MS.AAD.5.2v1 | partial | 5 | 0 |
| MS.AAD.5.3v1 | partial | 159 | 0 |
| MS.AAD.5.5v1 | partial | 6 | 2 |
| MS.AAD.5.6v1 | partial | 5 | 2 |
| MS.AAD.5.7v1 | partial | 3 | 5 |
| MS.AAD.7.1v1 | partial | 5 | 0 |
| MS.AAD.7.3v1 | exact | 5 | 0 |
| MS.AAD.7.6v1 | partial | 3 | 0 |
| MS.AAD.8.1v1 | exact | 158 | 0 |
| MS.AAD.8.2v1 | partial | 134 | 0 |

Reading the AAD disagreements:

- 71 of the 121 disagreements, including all 34 `exact` ones, are tenants whose policy has exclusions (MS.AAD.1.1v1 30,
  MS.AAD.3.9v1 4, MS.AAD.3.2v2 9, MS.AAD.3.6v1 28). ScubaGear counts a policy with exclusions that are not exempted in
  `scuba_config` as a near miss, which is not met; Prowler ignores exclusions. That is an engine difference, not evidence
  that a label is wrong; agreement on exclusion-free variants is the stronger signal.
- The rest follow the notes in the map. MS.AAD.3.6v1: Prowler treats a phishing-resistant policy with no included roles as
  an administrator policy and fails fixtures whose role ids are placeholders rather than Entra role GUIDs. MS.AAD.2.1v1 and
  2.3v1: Prowler's different grant or risk conditions. MS.AAD.3.2v2: Prowler ignores authentication strengths.
  MS.AAD.3.3v2: ScubaGear treats enforced phishing-resistant MFA as making it not applicable. MS.AAD.3.8v1: Prowler also
  needs the mfa grant control. MS.AAD.5.5v1 to 5.7v1: one Prowler check stands in for three narrower ScubaGear policies.
- Evidence the variants do not carry is assumed and recorded per row in `assumptions`: session controls, the default app
  management policy's enabled flag, PIM approvers (assumed configured) and admin consent reviewer settings. A consensus
  that rests on such an assumption is weaker than one that does not.

EXO, SecuritySuite, SharePoint and Teams per policy (policies with a Prowler counterpart; `unmapped` is mostly `label unknown`
and the reasons above):

| ScubaGear policy | Confidence | Agree | Disagree | Unmapped (not label unknown) |
|---|---|---|---|---|
| MS.EXO.1.1v2 | partial | 0 | 0 | 5 not exported |
| MS.EXO.3.1v1 | partial | 12 | 2 | 0 |
| MS.EXO.4.1v1 | partial | 7 | 0 | 0 |
| MS.EXO.4.2v1 | partial | 5 | 0 | 0 |
| MS.EXO.5.1v1 | exact | 1 | 0 | 0 |
| MS.EXO.6.2v1 | partial | 0 | 0 | 2 not exported |
| MS.EXO.7.1v1 | partial | 0 | 0 | 7 not exported |
| MS.EXO.13.1v1 | exact | 2 | 0 | 0 |
| MS.SECURITYSUITE.1.1v1 | partial | 18 | 0 | 0 |
| MS.SECURITYSUITE.1.3v1 | partial | 2 | 5 | 1 no finding |
| MS.SECURITYSUITE.1.4v1 | partial | 1 | 0 | 0 |
| MS.SECURITYSUITE.2.4v1 | partial | 2 | 0 | 5 evidence missing, 3 no finding |
| MS.SECURITYSUITE.5.1v1 | exact | 87 | 0 | 0 |
| MS.SECURITYSUITE.6.2v1 | partial | 16 | 8 | 13 no finding |
| MS.SECURITYSUITE.7.1v1 | partial | 8 | 11 | 6 no finding |
| MS.SECURITYSUITE.7.2v1 | partial | 6 | 12 | 6 no finding |
| MS.SECURITYSUITE.7.3v1 | partial | 3 | 13 | 6 no finding |
| MS.SECURITYSUITE.8.1v1 | exact | 4 | 0 | 0 |
| MS.SECURITYSUITE.8.2v1 | exact | 0 | 0 | 0 |
| MS.SHAREPOINT.1.1v1 | partial | 44 | 8 | 5 evidence missing |
| MS.SHAREPOINT.1.3v1 | partial | 35 | 0 | 6 evidence missing |
| MS.TEAMS.1.1v1 | partial | 5 | 0 | 5 evidence missing |
| MS.TEAMS.1.2v2 | partial | 13 | 0 | 5 evidence missing |
| MS.TEAMS.1.3v1 | partial | 5 | 37 | 0 |
| MS.TEAMS.1.5v1 | partial | 44 | 1 | 4 evidence missing |
| MS.TEAMS.1.6v1 | exact | 39 | 0 | 0 |
| MS.TEAMS.2.1v2 | partial | 11 | 0 | 0 |
| MS.TEAMS.2.2v2 | partial | 9 | 1 | 8 not applicable |
| MS.TEAMS.2.3v2 | exact | 11 | 0 | 6 not applicable |
| MS.TEAMS.4.1v1 | exact | 39 | 0 | 4 not applicable |

Reading the disagreements of the other products. Every `exact` row outside AAD agrees on every case it compared (EXO 3,
SecuritySuite 91, Teams 89).

- EXO (2 of 29 compared): both are MS.EXO.3.1v1 variants where ScubaGear fails the published DKIM DNS record (`Rdata_Incorrect`)
  while DKIM signing is enabled, which is all Prowler reads. Only four of the eight mapped EXO policies produce a verdict;
  MS.EXO.1.1v2, 6.2v1 and 7.1v1 are `not_exported` (14 cases).
- SecuritySuite (49 of 196): MS.SECURITYSUITE.7.1v1 to 7.3v1 account for 36. In every one ScubaGear is `met` and Prowler fails,
  because Prowler judges every custom Safe Links policy that has a rule in full, including the fixtures' always-misconfigured
  "Non-Compliant Custom Policy" at a lower priority that never applies; in 12 of them the applied policy also lacks a setting
  Prowler requires that the ScubaGear policy under test does not examine (the mutated setting belongs to a sibling policy).
  MS.SECURITYSUITE.6.2v1 (8): Prowler skips preset policies and has no precedence cascade. Of the 6 `met` cases that fail in
  Prowler, 4 are a compliant preset shielding a default or custom policy that carries allowed domains, and 2 are a custom
  policy with a disabled rule, which ScubaGear ignores and Prowler counts as non-compliant; the 2 `not_met` cases that pass
  are an active preset carrying allowed domains, which Prowler never sees. MS.SECURITYSUITE.1.3v1 (5): ScubaGear accepts
  DynamicDelivery and lets a compliant preset win (4 `met` cases fail in Prowler on a DynamicDelivery custom policy), and one
  `not_met` case where no policy covers all recipients passes in Prowler, which passes the built-in policy unconditionally.
  Agreement is complete on the malware filter (18, with the three-extension override), the audit log (87) and the connection
  filter (4); MS.SECURITYSUITE.2.4v1 compares only 2 cases because most variants carry no safety-tip settings.
- SharePoint (8 of 87): all MS.SHAREPOINT.1.1v1 variants whose `SharingCapability` is "New and existing guests" (1), which Prowler
  accepts and ScubaGear does not. MS.SHAREPOINT.1.3v1 agrees on all 35, including the not-applicable case where sharing is
  off; its allow-list passes rest on the assumed non-empty domain list.
- Teams (39 of 215): MS.TEAMS.1.3v1 accounts for 37, all because the fixtures set `AutoAdmittedUsers` to `EveryoneInCompany`
  (guests included), which ScubaGear 1.3 accepts and Prowler fails. MS.TEAMS.1.5v1 (1): a non-Global meeting policy lets
  dial-in users bypass the lobby, which only ScubaGear reads. MS.TEAMS.2.2v2 (1): `AllowTeamsConsumerInbound` on with
  `AllowTeamsConsumer` off, which ScubaGear accepts and Prowler's inbound-only check fails. 18 cases are not compared because
  ScubaGear counts MS.TEAMS.2.2v2, 2.3v2 and 4.1v1 as met without testing them in `gcc`, `gcchigh` and `dod` variants.

The 20261020 run is saved under `~/dev/machine/work/auditex-data/reviews/20261020-prowler-consensus/`
(`manifest.json` holds the commits, the checksums of the script and the map, and the counts).

Treat `agree` as corroboration and `disagree` as a review queue, not as an automatic relabel: the two engines read the same
baseline differently, and every label stays an engine output rather than human judgement.

Licence and provenance: Prowler is Apache-2.0 (`prowler-cloud/prowler`, commit `f45173997b8331e6cba3deac78bc2e1043b9281d`,
the commit pinned in the reference `sources.json`). The script imports Prowler from a local checkout at run time; no Prowler
code, metadata text or check message is vendored or shipped, and the map holds check ids with Auditex's own wording. The
`status_extended` strings in `verdicts.jsonl` and `consensus.jsonl` are Prowler output text, so keep those files with the
other oracle outputs outside the distributable tree, or attribute Prowler and include its Apache-2.0 licence if you share
them. See [Source provenance](../provenance/provenance.md#oracle-labelled-cases).

## Local GGUF benchmarks

`scripts/run-model-benchmark.py` launches one owned localhost `llama-server`,
runs explicitly reviewed cases sequentially, and stops only that subprocess.
Supply an existing native runtime, a local GGUF, a model hash and a new output
directory:

```sh
clean-development run --session session-only -- .venv/bin/python scripts/run-model-benchmark.py \
  --server /absolute/path/to/llama-server --check-runtime
clean-development run --session session-only -- .venv/bin/python scripts/run-model-benchmark.py \
  --server /absolute/path/to/llama-server --model /absolute/path/to/model.gguf \
  --model-id reviewed-model-label --model-sha256 EXPECTED_SHA256 \
  --cases /absolute/path/to/reviewed-cases.jsonl --output-dir /absolute/path/to/new-results \
  --response-format json-object --disable-thinking --ctx-size 8192 \
  --max-tokens 2048 --threads 6 --gpu-layers 99 --seed 42
```

Only `messages[:-1]` enters inference. The final assistant target and expected
rubric stay evaluation-only. The manifest records model/runtime hashes, the
embedded template, exact protocol settings, prompt fingerprints and usage.
Generic JSON-object constraints and thinking settings are explicit. Malformed,
truncated or failed responses retain raw traces; no response repair is performed.
Case approval is attributed provenance, not proof of independent human review.
Report agent-reviewed reference results as such, and separate same-tenant live
calibration from held-out synthetic results. Exact ID matching is a mechanical
protocol check, not a standalone measure of natural-language factual accuracy.

Thinking is a recorded protocol choice. `--disable-thinking` (`enable_thinking`
false) is the adapter's serving protocol and the setting for every adapter
result. `--enable-thinking` is a control arm only, for scoring an untuned base
with reasoning on: it sets `enable_thinking` true and starts the server with
`--reasoning-format deepseek`, so the think block is returned in
`reasoning_content` and only `content` is scored as the answer. With neither flag
the template default applies and the manifest says so (`thinking.mode`). The two
flags are mutually exclusive. `--max-tokens` bounds the whole completion
including reasoning (there is no separate reasoning budget), so a case that
spends it thinking ends with `finish_reason=length` and fails. Each record
carries `reasoning_present`, `reasoning_chars` and `reasoning_tokens` (the
server's count if exposed, else a best-effort `/tokenize` estimate of
`reasoning_content` taken after the answer is judged, so a failed count leaves
`reasoning_tokens` null and never changes the case result); the reasoning text
is retained in `records.jsonl`, never sent to the evaluator, and the answer is
not extracted or repaired.

## Claude execution handoff

Before execution, review labels and evidence, preserve family-level splits,
freeze a representative independent holdout and inspect source/artifact hashes.
Compare deterministic templates, retrieval and untuned models before deciding
whether an adapter improves a recurring error. Model agreement alone does not
approve data or justify promotion.

The pack contains `training-config.json`, `train_lora.py`, a guarded
`jupiter-auditex.sbatch` and a checksum manifest. `job_ready` means approved
train/validation/test data and an immutable base revision exist; runtime
qualification remains a separate pending requirement. Unreviewed data cannot
pass the launch guard. Train and validation rows carry
`chat_template_kwargs: {"enable_thinking": false}` so TRL renders exactly the
thinking-off inference prefix (empty think block, no reasoning-effort preamble)
and the completion-only loss starts at the JSON answer; evaluate adapters with
thinking disabled. Id-only duplicates (same prompt and answer apart from the
case id) are exported once and listed under `deduplicated_ids`. Pass
`--training-overrides overrides.json` with reviewed `{"sft": {...}, "peft": {...}}`
values (allow-listed keys only; the offline completion-only guards cannot be
overridden) and the manifest records them. The default **100 optimizer steps is a pilot limit**, not
a GPU-hour estimate; preparation leaves token counts and runtime unknown.

Claude must stage the exact base checkpoint in the project Hugging Face cache,
qualify the pinned candidate dependencies on Arm64/GH200, verify the explicit
Qwen text-backbone loader and LoRA targets, then inspect a four-GPU pilot. No
dependency installation, model download or hosted-service fallback occurs in
the recipe. It refuses overlength examples instead of silently truncating them.
The candidate PyTorch 2.14.1 release has Linux Arm64 wheels, but its
[PyPI dependencies](https://pypi.org/pypi/torch/2.14.1/json) request CUDA 13
components. Check the allocated node's driver and qualified environment against
that stack; wheel availability does not qualify the cluster runtime.

For JUPITER, the template requires a qualified environment file, absolute
project cache/scratch paths, the pack path, a separate durable output directory
and an explicitly supplied Slurm account. Submit only after qualification and
pass `--runtime-qualified` explicitly. Resume uses a checkpoint beneath the
same output directory and checks base revision and pack identity in both the
run directory and the selected checkpoint. The recipe writes that identity on
each checkpoint save; checkpoints without it cannot resume through this guard.
Retain checkpoint, dataset and environment records; evaluate the exported adapter on
untouched held-out cases and its intended deployment machine before promotion.

Implementation references: [Transformers Qwen text and vision model classes](https://huggingface.co/docs/transformers/model_doc/qwen3_5),
[TRL supervised fine-tuning](https://huggingface.co/docs/trl/en/sft_trainer).

### Checkpoint selection by generation (G3)

Eval loss is next-token fit to the teacher-forced answer; it does not say whether a checkpoint's own generated JSON
passes the reviewed rubric. `scripts/score-adapter-checkpoints.py` chooses the checkpoint by generated answers on
held-out cases and never by eval loss. It loads the text-only base once (the loader `train_lora` uses, offline,
`local_files_only`), attaches each checkpoint's adapter with PEFT, renders every prompt from the same
prompt/`chat_template_kwargs` record the trainer reads (`enable_thinking` false, generation prompt appended, the
assistant target never included), generates greedily (`do_sample` false) until the chat turn end or
`--max-new-tokens`, and parses the raw text as strict JSON. A fenced, prefixed, suffixed, duplicate-key or truncated
answer is kept as raw text and fails the evaluator as a `response_schema_error`; nothing is repaired. The adapter is
unloaded (checked for leftover LoRA layers) and memory freed before the next checkpoint. Only approved cases in the
requested splits are generated for (default `validation` and `test`, never `train`); `--splits validation` is
the recommended selection run, keeping `test` for one final report of the winner.

The rule is recorded in `selection.json`: highest strict pass rate; ties go to the lowest overconfidence (claims
expected `unknown` answered `confirmed`), then the lowest over-abstention (expected `confirmed` or `inferred`
answered `unknown`), then the earliest step. A tie on the first three keys is listed under `tied_with` and in
`warnings`, as is a zero pass rate or a `--limit` smoke. Each checkpoint also records schema errors, strict-JSON
failures, token-limit hits, issue counts, adapter hashes and `seconds_per_case`.

The output directory must be new and holds `responses.jsonl` (rows `{case_id, model_id, response}` with
`model_id` `<base>@<revision>+<checkpoint name>`, exactly what `auditex model evaluate` reads),
`generations.jsonl` (raw text, parse error, token counts, finish reason), `scored-cases.jsonl`, `evaluation.json`
(the evaluator's output over all checkpoints) and `selection.json`. Checkpoints with an
`auditex-training-input.json` must match `--base-model` and `--revision`; without one a warning is logged.

On JUPITER, after training, run it as a separate single-GPU job against the run's output directory (a 27B base in
bf16 is loaded to one device; pick it with `CUDA_VISIBLE_DEVICES`). Trainer `save_total_limit` is 2 by default, which
keeps only the newest and the best-by-loss checkpoint, so prepare the pack with
`--training-overrides` `{"sft": {"save_total_limit": 8}}` (or more) to leave several candidates. Use the repository
checkout or payload that keeps `scripts/` beside `src/`, and the qualified environment file for `PYTHON_BIN` and the
cache variables:

```sh
source "$JUPITER_ENV_SETUP"
"$PYTHON_BIN" scripts/score-adapter-checkpoints.py \
  --base-model Qwen/Qwen3.8-27B --revision 1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0 \
  --checkpoints-root "$AUDITEX_TRAIN_OUTPUT" \
  --cases "$AUDITEX_PACK_DIR/approved-cases.jsonl" --splits validation \
  --output-dir /absolute/path/to/new-g3-scores \
  --device cuda --max-new-tokens 512 --batch-size 8
```

Run it first with `--limit 8` to read `seconds_per_case`. Add `--checkpoint "$AUDITEX_TRAIN_OUTPUT/adapter"` to
include the trainer's final (best-by-loss) adapter as a comparator. Batching can shift bf16 numerics slightly; it is
held constant across checkpoints and recorded, and `--batch-size 1` removes the effect. Then score the selected
`selected_path` once on `--splits test` and report that as the held-out result.

On the Mac, smoke the pipeline with the 0.8B base from the offline travel copy of the cache, using the second
virtual environment (the repository one has no torch). `--device mps` works; `cpu` is slower. The qualification
run's checkpoints are not kept, so use any PEFT adapter saved from the text-only 0.8B model, such as a few-step
local training run's `checkpoint-N`. An untrained adapter behaves like the untuned base and mostly fails strict
parsing, which is the expected smoke outcome; it validates the plumbing, not quality. Linear-attention layers fall
back to reference PyTorch kernels without `flash-linear-attention`, roughly 20 s per case at 160 new tokens on the
Mac, so keep `--limit` small:

```sh
HF_HOME=$HOME/dev/machine/work/auditex-data/hf-home clean-development run --session session-only -- \
  $HOME/dev/machine/work/auditex-data/venv-model-qual/bin/python scripts/score-adapter-checkpoints.py \
  --base-model Qwen/Qwen3.5-0.8B --revision 2fc06364715b967f1860aea9cf38778875588b17 \
  --checkpoints-root /absolute/path/to/smoke-run \
  --cases /absolute/path/to/approved-cases.jsonl --splits validation --limit 4 \
  --device mps --batch-size 2 --max-new-tokens 160 --output-dir /absolute/path/to/new-g3-smoke
```

The scoring and selection logic is covered by `tests/test_score_adapter_checkpoints.py` with a stub generator; only
the prompt-equality test uses the staged tokenizer and is skipped when it or `transformers` is absent.
