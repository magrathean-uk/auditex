# Auditex Output Contract

Contract version: `2026-11-11` (1.5.0). It keeps everything `2026-10-22` made traceable and adds, additively, the items listed under "Contract history", and it removes the text-derived Google Workspace fields listed there. Consumers that ignore unknown keys are unaffected by the additions; a consumer that read a removed field must stop. `REFS_MUST_RESOLVE_SINCE` stays `2026-10-22`, so the legacy-bundle cut-off does not move.

## Local sensitive-user operator input (additive)

Microsoft 365 runs, including offline replay and guided audit flows, accept
`--sensitive-users FILE` or `AUDITEX_SENSITIVE_USERS_FILE` (the flag wins).
An empty environment variable is treated as unset; demos never load this input.
The regular local UTF-8 file is opened once read-only before collection, capped
at 256 KiB and 10,000 entries, and rejected as a usage error if empty or invalid.
Entries are e-mail strings in a JSON array or one per plain-text line;
`name;email` is accepted. Addresses are trimmed, lower-cased, de-duplicated and
sorted. Blank plain-text lines are ignored. Parser errors show a fixed message;
direct validation can give a physical line number. Neither quotes the input.

`run-manifest.json` adds `operator_inputs.sensitive_users`:

```json
{"supplied": true, "count": 2, "hmac_sha256": "<64 lower-case hexadecimal characters>"}
```

`supplied` is a boolean. When true, `count` is an integer of at least 1 giving
the number of unique normalised addresses; `hmac_sha256` is HMAC-SHA256
of their UTF-8 newline-joined list, sorted, **without** a trailing newline,
using a per-run key from `secrets.token_bytes(32)`. When absent,
the entry is `{"supplied": false}`; older bundles may omit it altogether.
No addresses, display names or source path are recorded in that entry.

The sole list copy is `operator-inputs/sensitive-users.txt`, mode 0600 inside
a 0700 directory: bare normalised addresses, one per line, with a final newline.
The key is stored as exactly 32 **raw bytes**, without encoding or a trailing
newline, only in `operator-inputs/sensitive-users.key`, also mode 0600.
Both appear in `artifacts` and `redacted_artifacts` in the run manifest and are
listed as `redacted_operator_input` in `bundle-hashes.json`, without a file
checksum or byte length. The writer places a `.gitignore` containing `*` in
`operator-inputs/`, including in custom output directories; it receives the same
integrity exclusion. **REDACTED** means this local personal
data and the key must not be disclosed: their contents are excluded from the evidence index,
AI context, logs, reports, built-in exports and customer packs. Customer packs
may carry their relative paths and exclusion reasons, but never the files or
their checksums or byte lengths. Shareable, customer-pack and explainer derivatives
retain at most the boolean `supplied`; the operator count and HMAC stay local.
The key never leaves
the private area, including through run-copy helpers. The source path
is redacted from recorded command arguments. No list is uploaded.

The copy is loaded only into the in-memory rule view of `MS.SECURITYSUITE.2.1v1`,
under `SecuritySuite["MS.SECURITYSUITE.2.1v1"].SensitiveUsers`. A supplied,
verified list allows that rule to decide when the remaining evidence is usable.
The Exchange collector selects `TargetedUsersToProtect` transiently and replaces
it with the bound `TargetedUsersCoverage` summary described below before any
payload or diagnostic leaves the adapter. A valid summary can establish target
membership; flags, actions, policy scope, licensing and precedence still have to
satisfy the existing rule. Literal target strings are never saved in the run.
`MS.SECURITYSUITE.2.3v1` receives the separate verified PartnerDomains input
in its own private rule view; neither input enables the other policy.
Offline assessment of a copied bundle uses the same checks and rule view.
ScubaGear export assessment retains its existing provider-config path.

The projection requires `supplied: true`, a positive integer count and a
64-character lower-case HMAC, regular non-symlink list/key files within the
non-symlink `operator-inputs` directory, collect's 256 KiB / 10,000-entry bounds,
canonical list bytes validated by collect's parser, and a matching count and
HMAC over the captured list, key and manifest. Verification does not reopen
those files. The existing closed synthesis outcome `operator_input_required` means
that a verified required input is unavailable, including absent, false, malformed,
unreadable or tampered inputs; `oversize` identifies a list byte or entry bound.
The rule still reports `section_not_collected` in those cases.
`config_list_empty` applies only when a direct ScubaGear rule configuration has
no usable SensitiveUsers entries, including absent, null, empty, blank-only or
non-string-only lists. It does not describe a missing verified private input
in a run bundle. Additional files
in `operator-inputs` are never loaded by projection and retain their normal bundle
integrity accounting; they do not invalidate an otherwise verified list.

Addresses bypass the model shape gate and projection budgets only in the private
rule view. They never enter projection views, assessment cases, assessment records, sidecars,
AI context, logs, reports, exports or packs; rule reasons remain constant text.
The synthesis outcome `projected` for SS 2.1 describes its private rule view;
its model view remains `not_collected`. The copy must never become a persisted
rule-view section. On resume the current invocation
replaces it, or removes it and records `supplied: false` if no input is supplied.
Resume retains the same key when replacing a supplied list and recomputes its
HMAC; clearing the list removes the key too. A missing or invalid key for an
existing HMAC is an error, never a silent key rotation. Supplying a list after
clearing it generates a fresh key.
Support can call `azure_tenant_audit.sensitive_users.verify_sensitive_users(run_dir)`
to recompute the HMAC from the private files and compare with
`hmac.compare_digest`. It returns false for missing, malformed or inconsistent
inputs. This proves consistency, not authenticity against an operator who can
rewrite the manifest and both private files.

The definition is `properties.operator_inputs.properties.sensitive_users` in `schemas/run_manifest.schema.json`.

### TargetedUsersCoverage v1

Each usable anti-phish policy row in `raw/exchange_policy.json` carries a
`TargetedUsersCoverage` object instead of `TargetedUsersToProtect`. Known
membership has exactly these fields:

```json
{"version": 1, "state": "known", "input_hmac_sha256": "<64 lower-case hexadecimal characters>", "input_count": 2, "protected_nonempty": true, "missing_count": 0}
```

The input count and HMAC refer to the run's verified private SensitiveUsers
list, not the policy's protected-user list. `protected_nonempty` records whether
the literal comparison found any non-empty protected value; `missing_count`
counts configured addresses absent from that set. Membership is true only for
a non-empty protected set with no missing configured address. The private rule
view validates the closed shape, exact types, count invariants and matching
count/HMAC against the same captured private snapshot used for configuration.
Invalid or unbound summaries supply unknown membership, without a literal-list
fallback. An explicit false protection flag or action remains decisive.

Other states are exactly `{"version": 1, "state": "unusable"}`,
`{"version": 1, "state": "not_collected"}` or
`{"version": 1, "state": "over_limit"}`, without counts or HMAC.
The runtime validator and `schemas/targeted_users_coverage.schema.json` define
the shape; Python also checks cross-field and input-binding invariants.

Collection counts all raw list entries before filtering or de-duplication and
permits at most 10,000. The compact JSON list, including brackets, separators
and escapes, must occupy at most 262,144 strict UTF-8 bytes. The adapter reads
stdout in bounded chunks and terminates and reaps a child that exceeds 64 MiB
before decoding. Limits produce `over_limit`; below-limit invalid fields
produce `unusable`. These are Auditex bounds. Unexpected live wire shapes
remain unverified and are treated as unusable evidence.

For this sensitive operation, events and error results omit stdout, stderr
and sample text on every path, including successful warnings and helper
exceptions. Only controlled outcomes and numeric command metadata remain.
Other selected policy settings stay available to SS 2.2-2.4. Unknown row fields
are discarded, and no target list reaches raw samples, logs or returned rows.

The validated summary is retained locally in normalised anti-phish records and
the evidence index. Its private binding is used only in SS 2.1's rule view.
Every shareable, customer-pack and explainer boundary drops the entire
`TargetedUsersCoverage` and `TargetedUsersCoverageBinding` subtree, including
embedded JSON. Sensitive-user manifest derivatives retain at most boolean
`supplied`; malformed private metadata is withheld. Other counts are retained.
Local evidence is unchanged. Customer-pack derivative hashes and seals cover
the transformed bytes; a customer pack is not a privately reassessable bundle.

Offline replay sanitises the sample before saving it or running collectors.
Fresh literals are summarised against the new run's binding; an imported
summary without fresh literals cannot be rebound to that run. Resume reuses a
known summary only when its shape, count and HMAC match the current verified
input and retained key. A changed or cleared list invalidates Exchange reuse;
the collector reruns when available, otherwise no usable membership proof is
carried forward. It never replaces an old summary's HMAC to make it match.
Reassessment of an unchanged original bundle uses that bundle's own verified
private files. The independent ScubaGear export path keeps literal comparison
and ignores reserved run-summary fields.

## Local partner-domain operator input (additive)

Microsoft 365 runs (`auditex run`, `azure-tenant-audit`), offline replay and
`auditex guided-run` accept `--partner-domains FILE` or
`AUDITEX_PARTNER_DOMAINS_FILE`; the flag wins and an empty environment value
means unset. Demos never read the operator's file. These domains are not personal
data, but they are customer-confidential. The file is opened once with `O_RDONLY`,
`O_NOFOLLOW` where available and `fstat` to require a regular file; special files
and links are rejected. The limits are 256 KiB and 10,000 entries before
uniquing. UTF-8 with an optional initial BOM is accepted; NUL, invalid UTF-8,
empty lists and invalid entries stop the run. Parser errors show a fixed message;
direct validation can name a physical line. Neither exposes source content or its
path.

Use one bare domain per line or a JSON array of domain strings. Blank text lines
are ignored; `#` comment lines and `name;domain` entries are rejected. Normalisation
trims whitespace, lower-cases, strips one trailing dot, then sorts unique entries.
A domain must have at least one dot, at most 253 characters after normalisation,
and labels of 1-63 ASCII letters, digits or hyphens, without leading or trailing
hyphens; the final label cannot consist entirely of digits or match `0x` followed
by hexadecimal digits. Non-ASCII domains are
rejected with a sanitised error; supply an ASCII DNS name (punycode is accepted).
E-mail addresses, leading `@`, URLs and wildcards
are rejected. An explicit subdomain is a literal domain, without expansion.
This follows v3.9.1 SS 2.3's `PartnerDomains` shape and exact trimmed, lower-case
set comparison; it defines no IDNA conversion or wildcard semantics.

`run-manifest.json` records `operator_inputs.partner_domains` as
`{"supplied": false}` when absent, otherwise:

```json
{"supplied": true, "count": 2, "hmac_sha256": "<64 lower-case hexadecimal characters>"}
```

Only the unique count and HMAC are recorded, never the domains or source path.
The HMAC covers the normalised UTF-8 newline-joined list **without** a final
newline. Each run uses a random 32-byte key from `secrets.token_bytes(32)`,
**separate from the sensitive-users key**. The private copy is
`<run-dir>/operator-inputs/partner-domains.txt`: bare sorted normalised domains,
one per line with a final newline. Its raw key is exactly 32 bytes at
`<run-dir>/operator-inputs/partner-domains.key`. Both files are 0600 in a 0700
directory and appear in the manifest's `artifacts` and `redacted_artifacts`.
The shared `operator-inputs/.gitignore` contains `*` and stays while either
operator input is supplied.

Both exact paths and `.gitignore` are excluded from bundle hashes with
`redacted_operator_input`, without file checksum or byte length. Other files
planted under `operator-inputs/` are hashed at finalisation or reported as unlisted
afterwards. The domains and key never enter evidence, its index, AI context,
logs, reports, built-in exports or customer packs; the flag's path is redacted
in command lines, including command-runner, response and Google redactors.
Packs may carry relative exclusion paths and manifest metadata, never the private
files. No list is uploaded. Rule views containing these domains must stay in
memory. Assessment consumes only the verified private snapshot for SS 2.3.

Resume replaces the list using the same private key and recomputes the HMAC.
No supplied input clears only this channel's list, key and metadata; the other
channel remains intact. A missing, short, linked or otherwise invalid key for
an existing HMAC is an error, never silent rotation. Supplying again after
clearing generates a new key. Support can call
`azure_tenant_audit.partner_domains.verify_partner_domains(run_dir)` to compare
manifest count and HMAC against the private files using `hmac.compare_digest`.
It returns false for absent, malformed or inconsistent inputs. This establishes
consistency, not authenticity against someone able to rewrite all three files.

`schemas/run_manifest.schema.json` defines
`properties.operator_inputs.properties.partner_domains`, identical to `sensitive_users` (boolean
`supplied`; when true require positive integer `count` and a lower-case 64-hex
`hmac_sha256`; when false forbid both; reject other properties). Assessment loads
the verified snapshot only into `SecuritySuite["MS.SECURITYSUITE.2.3v1"].PartnerDomains`
in that policy's private rule view. SensitiveUsers is loaded independently; ordinary
absence of either input leaves only its own policy unconfigured. Unsafe or
inconsistent private material still refuses run admission. Neither list enters
projection views, the shape gate, assessment cases or assessment/report output.

## Private pseudonym key (additive)

Every run sealed by 1.5.0 on storage with locking holds a private pseudonym key,
`operator-inputs/pseudonym.key`: 32 random bytes, the file 0600 in a 0700
`operator-inputs/` folder, beside `operator-inputs/.gitignore` holding `*`.
Collection creates it when it seals the run, after every digested artefact and
just before `bundle-hashes.json`, which names it under `excluded` with reason
`redacted_operator_input` and no checksum or byte length. The key is in no other
artefact: not in `run-manifest.json`, `summary.json`, `validation.json`,
`ai_context.json`, the evidence index, a report, preview, customer pack, export,
notification, MCP output, log or error message. A customer pack never copies
`operator-inputs/`. A re-finalised or resumed run keeps its key, and nothing in
Auditex removes, shortens or replaces a published key.

Pseudonyms (D5 person-name masking, privileged-user display names and immutable
ids in projections) are `HMAC-SHA256(key, text)` cut to 16 lower-case hex digits,
keeping their prefixes (`User `, `Id `, `Guid `, `user-`); the strategy label is
`keyed-hmac-sha256-v1`. Without the key, knowing the run folder, its manifest or
any other run metadata reproduces no pseudonym. The key protects people who hold
outputs; anyone who can run Auditex against the run folder can still mask a name
of their choosing with the run's key, and that caller can already read the
evidence beside it. A person keeps one pseudonym in every output derived from the
run, across re-renders and after the run folder moves; a copy with
`operator-inputs/` shares the key. Outputs built from several runs (MCP
`auditex_diff_runs` and `auditex_compare_runs`, and every other comparison, diff
or drift output that masks names) use the first-listed run's key for every run's
names, so they line up with that run's own reports; listing the runs in the
other order uses the other key. Output with no run uses a fresh random key for
that output only.

A keyless run is one made by 1.4.0 or earlier, one copied without
operator-inputs/, or one sealed on storage without locking. Auditex never writes
into it while reading: reports, previews, customer packs, notifications, `assess`
and every MCP tool mask it with a temporary key held in memory, one per run (its
folder and the `run_id` its manifest records) per process, so the files of one
customer pack and the calls of one MCP server session agree, and another command
or a restarted server gives different pseudonyms. A run whose manifest records
no usable `run_id` (missing, null, not a string or empty) gets a key for one
command or tool call only, so no other run ever shares it. Such output says so in one
fixed line (`pseudonym_notice` at the top level of JSON reports, results and
customer-pack files, `pack-manifest.json` and the redacted copies under
`source-artifacts/` included, and of MCP run-tool results, a closing line in
Markdown and HTML reports, customer-pack Markdown (`README.md` included) and
notification text, a closing CSV row whose `id` is `pseudonym_notice`, the SARIF
run property `auditex.pseudonym_notice` and the OSCAL metadata `remarks`; the
pack's `checksums.sha256` and its byte-for-byte copy of `bundle-hashes.json`,
which hold no pseudonym, carry none): its pseudonyms are not stable across
sessions until
`auditex report prepare-key RUN_DIR` is run once. That command creates the key,
prints `created` (or `present` when the run already has one) and exits 0; it is
the only command besides collection that writes a key and is not offered over
MCP. A key that appears later is used from the next command or tool call on;
one command or tool call keeps the key it resolved first for each run.

The key is created only under an exclusive lock on the run folder, through a
temporary file (`.pseudonym.key.<24 hex>.tmp`, registered as private before its
bytes are written and named in `bundle-hashes.json` like the key if a crash
leaves one) that is flushed and then renamed into place. Storage without locking
(every lock error except would-block, try-again and interrupted; Linux network
storage answers this way, because NFS emulates the lock with one that needs a
file open for writing) never gets a key: collection seals the run keyless and
logs `pseudonym_key.unavailable` with reason `nolock` in `audit-log.jsonl`, and
`prepare-key` refuses there until the run is copied to local storage. Between
machines on network storage, locks depend on the server's lock service. The run
folder is flushed after `operator-inputs/` is created and `operator-inputs/`
after the key is published, where the storage supports it. Where a folder cannot
be flushed (storage that cannot flush a folder, a flush that fails after the
key was published, the moment between publication and the flush, and macOS,
where a flush does not empty the disk's own cache), a power loss soon after
creation can lose the key's folder entry; outputs made before the loss then do
not match the key created next.

A key that is not exactly 32 bytes (`damaged`), or a key or folder with any group
or other permission bit (`permissions`), refuses every derivation of that run,
local reports with policy explanations included, until the operator restores,
restricts (0600 and 0700) or removes it; Auditex never repairs or widens it, and
removing it starts a new pseudonym series. A link, FIFO, folder, hard link or
file of another owner at the key's name is refused like any private input. The
guard refuses the key, by name, case alias, link, standard input or output
destination, wherever an ordinary input is admitted. CLI refusals exit 2 with a
fixed message that names `operator-inputs/pseudonym.key` and never a path or
key bytes.

Pseudonyms in outputs rendered by 1.4.0 or earlier came from the run path and do
not match those of 1.5.0; re-render and re-share where that matters. 1.4.0 reads
a 1.5.0 run (the key is outside the folders it reads) but rejects its
`model_assessment.json`, so a 1.4.0 render of a 1.5.0 run omits policy
explanations.

## Contract history

The optional `operator_inputs.sensitive_users`, `operator_inputs.partner_domains`
and `redacted_artifacts` manifest keys and the private-input integrity exclusions
above are additive under this version.

Version `2026-11-11` (1.5.0). Pseudonyms come from a private per-run key: the run key `operator-inputs/pseudonym.key`, made at collection, excluded from the hash manifest and never copied (see "Private pseudonym key"); keyless runs (made by 1.4.0 or earlier, copied without operator-inputs/, or sealed on storage without locking) use a temporary key held in memory, say so in their output, and get a key from the new `auditex report prepare-key`. The projection label is `keyed-hmac-sha256-v1`; `schemas/model_assessment.schema.json` accepts it and `run-salted-sha256-v1` in place (its `schema_version` stays `2026-11-05`), and writers emit only the new label. `schemas/bundle_hashes.schema.json` lists `redacted_operator_input` among the `excluded` reasons, which writers of `2026-10-22` already wrote. Pseudonyms made by 1.4.0 or earlier do not match; 1.4.0 rejects a 1.5.0 assessment.

Version `2026-11-08` (1.3.0). Removed, from the Gmail settings, Alert Center and group-settings text exclusions (live output only; offline fixtures follow): the length and presence fields derived from text the collector no longer requests, for example the vacation message and signature lengths. Presence stays only where a non-text field reports it, and no value rule read a removed field. Added since 1.2.4 (new in this version): the skip reasons `teams_token_unavailable` and `teams_powershell_not_supported` on section gaps with `status: skipped`, and the preservation of `status: skipped` on the coverage rows of an offline replay (added in 3e8c1bd); and, from the PIM role policy reads of `identity_governance` (see "PIM role policy reads"), the normalized artefact `normalized/privileged_roles.json`, the `governance_objects` record kinds `role_management_policy_assignment` and `role_management_policy_rule`, the coverage rows `roleManagementPolicyAssignments`, `roleManagementPolicyRules` and `roleManagementPolicyRulesFanout`, and the `collection_gaps` reasons `endpoint_unavailable` and `artefact_withheld` (with its `reasons` field).

Documented here for the first time but already present in 1.2.4 code or docs, so not changes of this version: the validation codes `unwaived_accepted_status` and `unknown_finding_status` (see "Finding status"), the manifest keys `rule_parameters` (see "Rule parameters and reassessment") and `replay_source`, the rule parameter `break_glass_accounts`, the coverage rows of an offline replay, the ledger's `graph.redirects`, the gate codes `bundle_integrity_mismatch`, `bundle_integrity_invalid`, `bundle_integrity_absent`, `expected_manifest_sha256_mismatch` and `expected_manifest_sha256_invalid`, `coverage_gaps[].section_gaps` and `surface_coverage[].section_gap_collectors` (see "Collection limits and coverage gaps"), the warnings `section_gap_not_recorded` and `observed_call_outside_declared`, `observed_ledger.log.empty`, the replay row error class `section_absent`, the per-collector `since` and `until` of a checkpoint, the `casMailboxSmtpAuth` section of `exchange_policy_objects` and the reasons of "Rules that need the whole input".

Version `2026-10-22` (released in 1.2.4). This version makes evidence traceable. The validator resolves every evidence reference against the bundle; references carry `collected_at`, `content_hash` and `resolved`; a proof row is `supported` only when its reference resolved and a finding's `confidence` follows from how many resolved; finalization writes `bundle-hashes.json`, which handoff, the explorer and customer-pack creation recompute; and the OSCAL export is OSCAL 1.1.2 Assessment Results that validates against the official schema, with the run manifest's `created_utc` as its collection time. It adds the validation codes `unresolved_evidence_ref`, `evidence_ref_hash_mismatch`, `unresolved_report_proof_table_ref`, `unresolved_report_evidence_ref` and `legacy_unresolved_ref` (see "Evidence references and traceability"). Bundles written under earlier versions stay readable, but the validator now reports any of their references that do not resolve, and handoff, the explorer and the gates recompute validation, so an older bundle with such references reads as invalid; its files are not rewritten.

Version `2026-10-20` records every list that was cut short as a coverage gap (see "Collection limits and coverage gaps") and adds the `truncated_list_reported_ok` and `collection_gap_not_recorded` validation codes. Bundles written under `2026-04-21` stay valid: a coverage row is checked only when it carries a `truncation_reason`, and older rows that flag `collection_truncated` on an `ok` row carry none.

Auditex treats completed run directories as product contracts, not incidental implementation output. Public `run` and `probe` flows must finish through the shared bundle finalizer so the same required artifacts and validation semantics are applied.

## Required root artifacts

Every successful bundle must contain:

- `run-manifest.json`
- `summary.json`
- `reports/report-pack.json`
- `index/evidence.sqlite`
- `ai_context.json`
- `validation.json`

Finalization also writes `bundle-hashes.json`, the SHA-256 of each non-excluded artifact (see "Bundle hash manifest"). It is not a required artifact, so bundles finalized before it existed stay valid.

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

`model_assessment.json` is an optional root artefact written by `auditex assess`.
Assessment is rules only: the model layer is removed and nothing is called. Current outputs use
`endpoint_host: "none"`, `model_name: "rules-only"` and omit `serving`.
Its schema is `schemas/model_assessment.schema.json` (version `2026-11-05`), listed
by the schema manifest and checked when present by bundle validation. The known
older versions `2026-10-27`, `2026-10-27.1`, `2026-10-28` and `2026-10-29` use their
byte-preserved, date-named schema files; `2026-10-29` is the most recent of these.
Malformed or unknown-version optional assessments produce warnings and never change
the deterministic gate result. It contains
`generated_at`, `run_id`, `endpoint_host`, `model_name`, prompt convention
`named-enums-v1`, the pinned `system_prompt_sha256`, totals and policy rows.
Historical model records remain valid, including serving and shadow provenance.
The following attempt/hash descriptions apply to those historical records; current rule rows make no requests.
Each row records claims, limitations, recommendations, `validation_status`, reason,
`latency_ms`, HTTP POST `attempts` (including format, thinking and `cache_prompt` negotiation; at most 5),
`thinking_disabled`, `thinking_stripped`, prompt and response
hashes, and a comparison against mapped `cisa_scuba` baseline alignment in the report
pack (`agree`, `disagree` or `not_assessed`), with `baseline_match` (`exact`,
`version_mismatch` or `none`). Prompt hashes cover the canonical JSON
system/user message array (UTF-8, sorted keys, compact separators, no newline).
Response hashes cover the final attempt's assistant text used for JSON parsing,
after removal of a leading thinking block. They are null when the final attempt
failed at transport level or supplied no assistant text. Skips have no
prompt or response hash. No raw invalid answer or API key is retained.

Within `2026-10-29` (since superseded by `2026-11-05`), two additive changes (older files still validate; the schema version is unchanged): model
rows (and `model_shadow`) may carry `finish_reason`, the final reply's token (`stop`, `length`, ...) or null when
no reply arrived or the server sent none or a non-token value; it is absent from rule and skipped rows, and the
validator rejects it there. A row whose reply was lost in transit twice (connection error, timeout, cut-short,
empty or non-JSON body, no chat-completion choice or no assistant text) is `unknown` with reason and sole
limitation `model_transport_failed` and no response hash; `model_endpoint_unavailable` now means an HTTP error
status or an oversized reply, not retried. Earlier `2026-10-29` files recorded such transport losses as
`model_response_invalid` or `model_endpoint_unavailable`. A third additive change: the envelope may carry
`serving`, the request settings the client sent after negotiation: `cache_prompt` is `disabled` (`cache_prompt:
false` sent, as benchmarked) or `server_default` (the server rejected the field, so llama-server may reuse a
cached prompt prefix and greedy answers can depend on the previous request), and `response_format` is
`json_object` or `not_sent`. `server_default` departs from both the production request and the benchmark protocol
(which sent `cache_prompt: false`); `not_sent` departs from the production request only, since the benchmark never sent a
response format. Assistant text that is not valid Unicode (a lone surrogate sent as a JSON `\ud800` escape) is
`model_response_invalid` and retried like any invalid answer; its response hash covers the text encoded as UTF-8
with `surrogatepass`, which equals plain UTF-8 for valid text.

The four verdict totals are disjoint: `answered` counts validated known requirement verdicts, `unknown`
counts validated abstentions, endpoint failures and transport losses, `invalid` counts exhausted answer
validation retries (whose claims are unknown), and `skipped` counts policy IDs absent
from the catalogue (`policy_not_in_catalogue`). All 102 shipped policy items preserve
their training text, including the intentionally empty Power Platform excerpt.

A catalogue policy without a registered value rule (none today: all 102 have one) uses
`reason: "rule_not_implemented"` and exact
`reason_text: "Not assessed: Auditex has no rule for this policy yet."`. Its status is `unknown`,
both claims are unknown with null values and empty evidence IDs, limitations and recommendations
are empty, latency and attempts are zero, hashes are null and thinking flags are false. No
`finish_reason`, `rule_precheck`, `model_shadow` or `post_check` is permitted. A rules-only file is
marked by `endpoint_host: "none"`, by `model_name: "rules-only"` or by any such row; any one marker
requires the whole file to have both envelope values, no `serving` and no model-answered or shadow rows.
Mixed files fail validation. Preserved legacy schemas reject this reason and keep their earlier envelope
checks; the unreleased `2026-11-05` schema is extended in place.

**Customer term and internal values.** Customer-facing text says met, not met, not assessed and not applicable.
The contract keeps the internal values and does not rename them. A row's `requirement_met` claim carries the
`status` (`confirmed`, `inferred` or `unknown`) and `value` (`true`, `false` or null); `comparison.model_status`
is `pass`, `fail` or null. The value-rule inventory (`configs/scuba-value-rules.json`) uses the cell outcomes
`met`, `not_met` and `not_assessed` (its loader also accepts `not_applicable`). Mapping for rule rows, as the code writes it (the `requirement_met` and `comparison.model_status` columns hold for every row; a model row can carry other limitations and recommendations):

| Customer term | `requirement_met` claim | `comparison.model_status` | Other fields |
| --- | --- | --- | --- |
| met | `confirmed`, `true` | `pass` | no limitation |
| not met | `confirmed`, `false` | `fail` | recommendation `review_policy_against_baseline_text` |
| not assessed | `unknown`, null | null | missing sections: `required_evidence_section_not_collected`, `collect_missing_evidence_section`; collected but unusable evidence: `evidence_unusable` and the reason-specific recommendation below |
| not assessed | `unknown`, null | null | `rule_not_implemented`, constant `reason_text`, empty limitations and recommendations |
| not applicable | `inferred`, `true` | null | limitation `policy_not_applicable` |

A model row that abstains (`unknown`), fails to answer (`invalid`) or is skipped has no customer verdict and reads
as not assessed; the comparison `result` is `not_assessed` whenever the row has no `pass` or `fail` status or the
baseline has none. That `result` value and the baseline's `not_assessed` status are the same customer term. The
four verdict totals (`answered`, `unknown`, `invalid`, `skipped`) are internal counters and keep their names.
Rules decide all product answers; every catalogue policy has a value rule, so no current row reports
`rule_not_implemented`.
No model answers a product policy; the shipped deterministic template explainer describes value-rule answers and never changes them.

Version `2026-10-28` adds deterministic pre-checks from the shipped
`configs/scuba-rule-precheck.json`, resolved through the engine resource resolver.
For a policy with a value rule the value-rule result is returned first, in this order: the shared closed
gate, then the rule's missing or `not_collected` sections, then the rule kind. The remaining classes below are
compatibility shims in `azure_tenant_audit/scuba_precheck.py`; they run only when no value rule answered (a policy
without a catalogue row), and they keep the historical `rule_precheck` class names:

1. A present, usable gate section and field with a typed value in the closed set
   produces `closed_gate`: requirement `inferred` true, limitations exactly
   `["policy_not_applicable"]` and no recommendations. This takes priority even
   when another dependent section is absent or marked `not_collected`.
2. Otherwise, a missing or unusable gate section/field for a gated policy, or any
   missing dependent section for any policy, produces `absent_section`: requirement
   `unknown` with null value, with limitations naming unavailable sections or fields.
   A `not_collected` marker is unavailable, including a gate section marker.
3. Otherwise a registered field rule whose field is missing inside a collected section
   produces `absent_field` (unknown, as above).
4. Otherwise a registered list rule whose section was collected as exactly `[]` produces
   `empty_required_list`: requirement `confirmed` false (the ten AAD policies that need a
   matching Conditional Access policy; see [AI assessment](../guides/ai-assessment.md#rule-pre-checks)).
5. A policy with no registered value rule is `rule_not_implemented`; no model decides.

Explicit null sections keep their default semantics outside registered gate fields. A visibly
closed gate makes the other dependent evidence moot.

Rule rows have `reason: "rule_precheck"`, `validation_status: "valid"`, zero attempts
and latency, null prompt/response hashes, and false thinking flags. Their
`rule_precheck` object contains `class` (`closed_gate`, `absent_section`, `absent_field`: a Rego-read field missing inside a collected section, answered unknown by a registered field rule, or `empty_required_list`: a collected, exactly empty list that every passing verdict of the policy needs an entry of, answered not met by a registered list rule), `rule_id`,
`section` (an ordered array of affected section names), `field` (a path or null) and
`value` (the normalised gate value or null). Missing gate inputs share the
`absent_section` class and name the field. Absence rows carry
`required_evidence_section_not_collected` plus one limitation per unavailable input,
`required_evidence_section_not_collected:<section>[.<field>]`, and recommend
`collect_missing_evidence_section`. Criticality remains confirmed from the policy item.
`empty_required_list` rows have a null `field` and `value`, requirement `confirmed` false citing
`e0` and every section, no limitations and the one recommendation
`review_policy_against_baseline_text`, as an oracle not-met verdict; the comparison treats them as
model `fail`. Precedence is `closed_gate`, `absent_section`, `absent_field`, then `empty_required_list`.
`totals.rule_answered` counts every class, overlapping `answered` and `unknown`;
the four verdict totals still sum to the policy count.

Version `2026-11-05` adds the `value_rule` class and the shipped
`configs/scuba-value-rules.json` inventory (`spec_version` `v3.9.1`, addenda A1 and A2).
The route covers 102 policies and 1,084 cells (`len(policies)` in that inventory):

| Area | Policies | Policy suffixes (`MS.<area>.`) |
| --- | --- | --- |
| Entra ID (AAD) | 31 | `1.1v1`, `2.1v1`, `2.3v1`, `3.1v1`, `3.2v2`, `3.3v2`, `3.4v1`, `3.5v2`, `3.6v1`, `3.7v1`, `3.8v1`, `3.9v1`, `5.1v1`, `5.2v1`, `5.3v1`, `5.5v1`, `5.6v1`, `5.7v1`, `6.1v1`, `7.1v1`, `7.2v1`, `7.3v1`, `7.4v1`, `7.5v1`, `7.6v1`, `7.7v1`, `7.8v1`, `7.9v1`, `8.1v1`, `8.2v1`, `9.1v1` |
| Exchange Online | 12 | `1.1v2`, `13.1v1`, `2.2v3`, `3.1v1`, `4.1v1`, `4.2v1`, `4.3v1`, `4.4v1`, `5.1v1`, `6.1v1`, `6.2v1`, `7.1v1` |
| Power BI | 8 | `1.1v1`, `2.1v1`, `3.1v1`, `4.1v1`, `4.2v1`, `5.1v1`, `6.1v1`, `7.1v1` |
| Power Platform | 8 | `1.1v1`, `1.2v1`, `2.1v1`, `2.2v1`, `2.3v1`, `3.1v1`, `5.1v1`, `6.1v1` |
| Defender (SECURITYSUITE) | 21 | `1.1v1`, `1.2v1`, `1.3v1`, `1.4v1`, `2.1v1`, `2.2v1`, `2.3v1`, `2.4v1`, `3.1v1`, `3.2v1`, `3.3v1`, `3.4v1`, `4.1v1`, `5.1v1`, `6.1v1`, `6.2v1`, `7.1v1`, `7.2v1`, `7.3v1`, `8.1v1`, `8.2v1` |
| SharePoint | 8 | `1.1v1`, `1.2v1`, `1.3v1`, `2.1v1`, `2.2v1`, `3.1v1`, `3.2v1`, `3.3v2` |
| Teams | 14 | `1.1v1`, `1.2v2`, `1.3v1`, `1.4v1`, `1.5v1`, `1.6v1`, `1.7v2`, `2.1v2`, `2.2v2`, `2.3v2`, `4.1v1`, `5.1v2`, `5.2v2`, `5.3v2` |

Assessment always enables the 102 registered value rules; no setting turns them off.

For a value-rule policy, a usable closed gate wins, then the rule's ordered read
set determines missing or marked sections, then the value predicate answers before
the old absent-field and empty-list checks. The closed gate is decided by the shared
`configs/scuba-rule-precheck.json` gate and recorded as the rule's `closed_gate` cell
(`value_rule` class, verdict not applicable); for MS.TEAMS.2.2v2, 2.3v2 and 4.1v1 an
M365 environment other than exactly `commercial` that the gate does not close is the
not-assessed `environment_unknown` cell. The `value_rule` metadata adds `cell`,
`reason_code` and `reason_text` to `rule_id`, `section`, null `field` and null
`value`. The cell, code and reason text must match the shipped policy inventory.
These fixed texts contain only section names, setting names, known enum names
or generic descriptions of counts. A not-assessed rule answer cites only
the sections that explain it and uses the existing unknown claim. Only `section_not_collected`
uses `required_evidence_section_not_collected`, its named section limitations and
`collect_missing_evidence_section`. Addendum A1 is additive within the unreleased `2026-11-05`
schema: collected but unusable evidence uses `evidence_unusable` plus
`evidence_unusable:<section>:<kind>` for each cited section. Kinds `blocked`, `absent`,
`unusable` and `undecidable` recommend, respectively, `check_licence_or_permissions`,
`recollect_unusable_evidence`, `recollect_unusable_evidence` and
`review_policy_against_baseline_text`. Customer text reads not assessed plus the constant
catalogued reason; no evidence text is interpolated and these recommendation ids define
no display wording. Offline pack parity (`as_pack_response(..., legacy=True)`) retains the earlier vocabulary.
Previously written `2026-11-05` answers keep the earlier limitation and recommendation vocabulary and still
validate, with one exception: a rule fault written before this change carries the cell `rule_evaluation_failed`,
the validator now rejects it, and the fault record's cell is `null`. Complete assessment-byte preservation
therefore cannot be claimed for that path; re-run the assessment to obtain the current record.
A1 and A2 are accepted exactly: 68 contract cells carry their contract on the cell itself, through
`cited_variants`, and `reason_texts_by_code` with `reason_codes`: the exact citation variants for 64 cells (A2 adds
`[protection_policy_rules]` to SS 6.1 and 6.2 `rule_scope_unusable` and `[built_in_protection_rules]` to SS 1.3
`list_element_unusable`), the two paired reason codes and texts for AAD 6.1 `orphan_sub_domain`, and the specified
citation order for the three SS 7.x `preset_rule_unusable` cells. Every not-assessed cell carries `evidence_kind`
(null for `section_not_collected`), its `limitations` and its `recommendations`, which the loader checks against the
reason code; the closed text lists that name any subset (missing sections, AAD 3.5v2 methods, SS 3.2 locations, SS 4.1
alerts) hold every reachable text. Other codes, texts, citation lists and citation orders are rejected; the former
separate `cell_contracts` table and `rule_failure` entry are rejected too.
A met or not-met answer confirms the
requirement and cites every section in the model case; not-met recommends baseline
review. The validator checks the inventory, sections, claims and text but cannot
re-run the predicate, because the assessment bundle does not contain its input
evidence. The prior `2026-10-29` schema is preserved separately and still validates.

Optional Power BI / Power Platform collection adds the following reason within the
unreleased `2026-11-05` assessment schema:

| Reason | Customer text | Recommendation |
| --- | --- | --- |
| `optional_collection_not_enabled` | Not assessed: the optional Power BI / Power Platform collection was not enabled for this run. | None |

It applies only to the catalogue's Power BI / Power Platform policies and their
optional collector sections when missing. Each collector is checked separately in
`run-manifest.json`'s `selected_collectors` list (fallback `collectors` when the key
is absent). An absent, empty or invalid list means unknown selection and retains
the generic reason. A valid list contains unique names from
`configs/collector-definitions.json`; names are canonical lowercase snake case,
with no whitespace. Selected collectors retain their existing failure reasons.
Probe bundles and ScubaGear exports retain the generic missing-evidence reason.
The projection records the reason only on `not_collected` optional sections;
licensing and tenant-ID sections remain independent. The private rule view carries
this cause to an `absent_section` precheck with the exact constant `reason_text`,
one `optional_collection_not_enabled` limitation and no recommendation. The
validator checks the policy, cited sections and matching projection reasons.
Assessment-case evidence remains the exact `not_collected` marker. The optional-collection
reason is independent of legacy `AUDITEX_DISABLE_VALUE_RULES`, which is ignored. Only
explicit optional-collection provenance selects it; value rules remain enabled.

A rule that fails on collected evidence (an Auditex fault, not a tenant setting) answers
the shared reason `rule_evaluation_failed`, catalogued once under `shared_reasons` and added within
`2026-11-05`. It is not a cell: `rule_precheck.cell` is `null` (the assessment schema allows a null cell from this
version) and it is dispatched before any cell lookup. The reason code is `rule_evaluation_failed`, the constant text
"Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a
tenant setting.", the `unknown` claim citing every section the rule reads, no limitation and the new
recommendation `report_product_fault`, which means: report the fault to
`contact+auditex@magrathean.uk`. The failure is logged with the rule id and the
exception class name only; no exception text or evidence reaches the row or the log. The earlier representation, a
cell named `rule_evaluation_failed`, is rejected by the dispatch checker, the pre-check response builder, the
validator and the explainer adapter. A policy without a value rule has the second shared reason,
`rule_not_implemented` ("Not assessed: Auditex has no rule for this policy yet.", no limitation and no
recommendation). Serving answers it as the row-level reason described above, never as a `rule_precheck` record (the
rule-record checkers refuse that code); the catalogue holds its constant text and a test pins the serving constant to it.
No route produces it today because every catalogued policy has a rule.

Serving rules read an in-memory rule view on both the run-bundle and internal
ScubaGear export paths, taken after
withholding and before pruning, the shape gate, the item budget and redaction
(`docs/reference/security-privacy.md`); it is never written to an artefact. A
section the run or export did not collect still answers not assessed (section not
collected).

Version `2026-10-29` replaces the P1 stub with a read-only tier-1 ScubaGear
ProviderExport projection. Incomplete, failed, sampled, truncated, malformed or
unavailable sections become exactly `{"collection_status":"not_collected"}`.
No partial record, empty list or null stands for unknown collection. An explicitly
complete empty source enumeration can still project as a known empty collection.
Pre-checks
always run, including when every section is unavailable; a dependent missing-section
row is answered by its rule, subject to the closed-gate precedence above. The envelope
retains `limitations: ["projection_not_implemented"]` only when no section can be
projected at all, for compatibility. Otherwise envelope limitations are empty; there
is no `projection_partial` limitation.

The required `projection` envelope is separate from the assessment-case evidence:

- `schema_version: "2026-10-29"`.
- `sections`: every section referenced by the shipped policy catalogue, with
  `status` (`projected` or `not_collected`), `reason` (null for projected;
  `missing_artifact`, `optional_collection_not_enabled`, `incomplete_shape`, `collector_error`, `oversize`, `powershell_only`,
  `not_applicable_to_platform`, or for the DNS sections `dns_posture_not_run` and
  `dns_records_not_saved` otherwise), optional `unsupported_conditions` (CA
  field paths that cannot be represented), and `source` (relative artefact paths
  actually read, including authoritative chunks). New `incomplete_shape` results
  also carry `detail`: `field` (the first failing check's dotted field path, without
  array indices) and `kind` (`missing_field`, `unexpected_field`, `unseen_enum_value`,
  `unseen_shape` or `invalid_type`). Paths use adapter/ProviderExport field names;
  CA restriction paths retain their existing Graph spelling. `$` denotes a failure
  of the whole section or source shape that cannot be attributed to a single field;
  arbitrary unknown keys become `unrecognisedField`, since keys can contain personal
  data. Enum failures may include `value` only for finite numbers or explicitly
  recognised non-personal enum tokens. Currently the string allowlist is the
  `AllowInvitesFrom` tokens `everyone`, `none`, `adminsAndGuestInviters` and
  `adminsGuestInvitersAndAllMembers`; unfamiliar strings, display names, e-mails and
  free text are omitted; redaction is unconditional and `--no-redaction` is rejected. This diagnostic allowlist does
  not widen the frozen pack enum domain: `everyone` still withholds the section.
  `detail` is optional in schema `2026-10-29` for backwards compatibility, and is
  never included in assessment-case evidence. CA `unsupported_conditions` lists the non-empty restrictions of
  enabled policies. A projected CA section may also carry `dropped_conditions` (sorted
  `<policy id>:<field path>` strings: the unsupported conditions dropped from policies that are
  not enabled; the id is the policy's GUID, else `policy<position>`) and `null_lists_read_as_empty`
  (sorted ProviderExport field paths of list fields Graph returned as null); a withheld section
  carries neither.
  An `oversize` section carries `detail` only when a scan bound ran out: `kind`
  `scan_bound` and `field` the bound (`scan_max_rows`, `scan_max_bytes` or
  `scan_max_chunks`); an `oversize` without `detail` exceeded the projection budget.
  Optional `scan` (`rows`, `bytes`, `chunks`) reports how much source the section's
  operation reads scanned, projected or not: rows examined, bytes read (chunk lines,
  or the size of the inline payload file) and chunk files opened. Optional
  `ignored_failures` lists the `<collector>.<operation>` names of operations that
  reported a failure the section does not read (collection health, below).
  A `collector_error` section read an operation the collector recorded as failed
  (`error`, `error_class` on the envelope, coverage row, ledger diagnostic or collection
  gap); its `detail` is `error_class` (the collector's class, never the error message)
  and, when attributable, `operation` (`<collector>.<operation>`). The class is checked
  against one vocabulary, `COLLECTOR_ERROR_CLASSES` in
  `azure_tenant_audit/scuba_assessment.py`, shared by the projection and the validator: the
  classes this engine's collectors, adapters, preflight and offline replay write, plus
  `graph_http_<status>` for an HTTP status the Graph classifier does not name. Any other
  value, however token-shaped (`alice_smith`), reads `unclassified`, and the validator
  rejects an unknown class. Optional `ignored_fields` lists, sorted, the field paths the
  source carried that the training shape does not know (names only, never values; a key
  that is not an identifier is masked as `unrecognisedField`). Only OData annotations
  (`@odata.type`, `authenticationStrength@odata.context`) are excluded; every other source
  field an adapter does not project is listed, at every adapter boundary: the SharePoint
  settings row, the authorization policy and its default-role permissions, each SKU row
  and service plan, each administrator's user row, each Conditional Access policy
  (including `id`, `createdDateTime` and `templateId`), the privileged role rows and the
  PowerShell and DNS rows. The normalised records the product writes itself
  (`effective_admin_set`, `sharepoint_tenant_settings`) are read by named field and not
  listed. An extra field that cannot change the meaning of a projected one never
  withholds: the adapter projects only the fields it selects and the projected object
  passes the same frozen shape gate. Field presence depends on the token (a delegated
  token returns `servicePlans[].servicePlanType`, an Azure CLI token does not), not on the
  tenant. Unseen enum values, wrong types and missing fields still withhold. Where an
  extra field can scope or qualify a kept one, only an empty or demonstrably harmless
  value is ignored; a populated one withholds the section as `incomplete_shape` with
  `detail` `{field: <path>, kind: unexpected_field}`. Conditional Access: a known
  restriction with a value (`unsupported_conditions`), or a populated unknown field inside
  `conditions` or `grantControls` (`unrecognisedField`), withholds when its policy is enabled;
  a null or empty restriction, an empty unknown field there, or any unknown top-level field, is
  ignored, and on a policy that is not enabled the populated ones are dropped and listed under
  `dropped_conditions` instead (the pinned rules read enabled policies only). `privileged_roles`: on a role,
  assignment, rule or rule `Setting`, a populated extra withholds unless it restates what
  is kept: `DirectoryScopeId` `/` (tenant-wide), a `RoleDefinitionId` or `TemplateId` equal
  to the row's `RoleTemplateId`, a rule `Target` whose caller and level are the ones the rule
  `Id` names (operations `All`, no target objects, inherited or enforced settings), a
  notification `RecipientType` the `Id` names, and identity or audit metadata (`Id`,
  `Description`, `IsBuiltIn`, `CreatedDateTime`, `ModifiedDateTime`, `CreatedUsing`). An
  administrative-unit `DirectoryScopeId`, any `AppScopeId`, `MemberType`, `Status`,
  `NotificationLevel`, approval stages or an unknown field withholds, so a scoped
  assignment is never read as tenant-wide. `privileged_users`: every role an administrator
  is listed with must be held at directory scope `/` in the admin set's `roles`; a role held
  only at another scope withholds (`roles.scope`, `unseen_enum_value`, the scope never
  echoed), one whose scope is unknown too (`missing_field`), and a scoped assignment of a
  role also held tenant-wide changes nothing.
  `scuba_config` alone carries `synthesis` (see its row below): `source`
  `synthesised:default-config`, `basis` `scubagear_default_config`, `m365_environment`
  (`value`, and `basis` `openid_discovery`, `licence_sku`, `assumed_default`, `ambiguous` or `unreadable`; the last two leave `value` null and withhold the environment-gated policies),
  `break_glass` (`source` `none`, `operator` or `unrecorded`; for an operator list the entry,
  unresolved, unverified, user and group counts and `state`, never the entries) and `policies`,
  the outcome for every policy that reads the section (`projected`, `operator_input_required`,
  `break_glass_unresolved`, `environment_ambiguous`, `unseen_shape` or `oversize`).
  Sections outside this package's
  tier-1 adapters remain `not_collected` with `missing_artifact`, even if other
  Auditex summary artefacts exist for that surface. No summary count is treated as
  a ProviderExport object. Non-M365 bundles use `not_applicable_to_platform`.
- `redaction`: `enabled`, strategy `keyed-hmac-sha256-v1` (assessments written by
  1.4.0 or earlier carry `run-salted-sha256-v1`, which still validates), and counts
  `user_display_names`, `email_addresses`, `immutable_ids`. The key is the run's
  private `operator-inputs/pseudonym.key` (see "Private pseudonym key"), read only
  while `redact` is on and never created by projection; a keyless run uses its
  temporary key. User display names become `User <pseudonym>`; non-null immutable
  IDs become `Id <pseudonym>`, each the run key's pseudonym of the value.
  No identity-to-pseudonym table is persisted. E-mail local parts anywhere in
  projected string values become `***`, retaining the domain. GUID principal IDs,
  role and policy names remain available. No key or salt is written: the envelope
  schema and validator reject either member; counters never enter assessment cases.
  ScubaGear exports have no run folder: their key is derived in memory from the whole
  export, so only a holder of the export can derive it. Pseudonyms support
  pseudonymisation, not anonymisation or a disclosure guarantee.
- `bounds`: the projection budget `max_items` (default 40) and `max_chars` (default
  12,000 canonical JSON characters), and the scan bounds `scan_max_rows` (default
  250,000), `scan_max_bytes` (default 268,435,456, 256 MiB) and `scan_max_chunks`
  (default 10,000). The scan bounds are absent from assessments written before they
  existed. `--projection-max-items`, `--projection-max-chars`,
  `--projection-scan-max-rows`, `--projection-scan-max-bytes` and
  `--projection-scan-max-chunks` accept positive integers.
  - The projection budget applies to the section that would reach the model, never
    to the source read to build it. The item bound covers top-level collections, user
    dictionaries and nested lists of the projected object; the character bound its
    canonical JSON. Both are checked on the projected object, again after redaction
    and after enum-name annotation; exceeding either replaces the whole section
    with the marker and reason `oversize` (no `detail`). Nothing is silently sliced.
    A tenant with thousands of users still projects `privileged_users` when it has
    a handful of administrators.
  - A tenant whose administrator set exceeds the budget withholds `privileged_users` as
    `oversize`: the budget counts each administrator's `roles` list as well as the
    administrators, so one administrator holding more than 40 distinct privileged roles
    (seen on a real tenant: 88, with 130 role assignments and 145 role definitions in the
    authoritative chunks) is enough. Nothing is sliced to fit, since a partial role list
    would read as a narrower admin set. There is no supported operator action today:
    `--projection-max-items` would let the section through, but the default budget is the
    retained projection limit and a larger section is outside it, so the default stays. Whether such a
    tenant should get a summarised role list or a larger budget is a product question recorded for G.
  - The scan bounds are safety limits on one source read, whatever the budget: rows
    examined in one operation, bytes read (the chunk lines of one operation, and the
    size of any JSON artefact read whole, such as an inline payload or a normalised
    file) and chunk files listed. Exhausting one withholds the section as `oversize`
    with `detail` `{field: <bound>, kind: scan_bound}`. Raise them only for a tenant
    that really exceeds them: a section that keeps its source rows (conditional
    access, the PowerShell sections, DNS) holds up to the bound in memory, while
    `privileged_users` and `service_plans` stream and keep only the administrators or
    the distinct plans.
  Row-level pack limitation IDs are unchanged.

The removed `--no-redaction`, `--endpoint`, `--model`, `--dry-run` and `--shadow-model-on-precheck`
options are rejected by `auditex assess` (exit 2), and `AUDITEX_MODEL_*` and
`AUDITEX_DISABLE_VALUE_RULES` are no longer read. Redaction is always enabled.

Projection reads inline `raw/<collector>.json`, offline `raw/sample_input.json`,
or export-only `raw/<collector>/<operation>/summary.json`. Non-empty `chunk_files`
are authoritative; all chunks and counts must validate. Guard-refused chunks
produce a constant evidence-issue code and `chunk_index`, never the refused path
or rows from that file. Dependent collector fan-out stops with incomplete-evidence
coverage; inline samples do not replace refused chunks. Duplicate JSON keys and
non-finite constants are rejected in both JSON and JSONL. Chunk iteration stops
at a scan bound: cumulative bytes, including whitespace, at `scan_max_bytes`, rows
at `scan_max_rows` and chunk files at `scan_max_chunks`; the projection budget is
not involved. Source rows are streamed where the projection is small: `privileged_users`
reads the effective admin set first, then scans `identity.users` once and keeps only
the rows of those principal IDs (an administrator's ID on two user rows, or a user row
without a text ID, withholds the section; a repeated ID of any other user is not
checked, since no index of the list is kept), and `service_plans` streams
`licensing.subscribedSkus` and keeps only the distinct plans.

Collection health is judged per operation. Coverage rows, the coverage ledger,
collection gaps, the manifest's coverage gaps and per-record failure metadata for an
operation the section reads, or for the collector as a whole, override apparently
usable payloads. A failure of another operation of a collector the section reads,
one the collector's payload also carries (for example `identity.userSignInActivity`
refused with `license_required`, which no adapter reads), does not withhold: it is
listed in the section's `ignored_failures`. Attribution comes from a row's `list`,
`name` or `source`, from a coverage-ledger row's `diagnostics[].item` (only a partial
or blocked ledger row, or one that is complete, can be attributed that way), or from
the operation key of a raw envelope; a derived `<operation>Fanout` row counts as its
operation, and the identity collector's `privilegedGroupFanout` row is a derived name of that collector
(so a failed fan-out is listed under `ignored_failures` for `tenant_id` and withholds `privileged_users`). A failure that cannot be attributed to such an unrelated operation (the
collector as a whole, an unrecognised name, a diagnostic without an item) still
withholds. `privileged_users` reads `identity` `users`, `groups`, `servicePrincipals`,
`roleDefinitions`, `roleAssignments` and the privileged-group fan-out
(`roleAssignableGroupMembers`, `privilegedGroupFanout`), and `identity_governance`
`roleAssignmentSchedules` and `roleEligibilitySchedules`: the sources of the effective
admin set. `privileged_roles` reads the two schedules. A manifest `coverage_gaps`
surface summary that merely lists a collector stands only when no coverage row or
ledger row exists to say which operation failed. Empty collections require an explicit successful
collection status, completeness flag or complete coverage entry. A bare empty array
or empty chunk manifest is insufficient; an empty shape must also occur in a frozen
pack row. Chunk paths must remain
under that collector's raw operation or chunks directory. Symlinks and paths
outside the bundle are refused. The projection performs no network, PowerShell,
collection or file writes and adds no collectors. Only the existing assessment
output is written. The original bundle seal and deterministic findings are unchanged.

Complete inputs required for the tier-1 sections follow. Missing properties are
never filled with assumed tenant settings. PascalCase denotes ProviderExport keys;
Graph camelCase is converted recursively for the selected fields.

| Section | Required saved evidence and projection |
| --- | --- |
| `SPO_tenant` | `normalized/sharepoint_tenant_settings.json` with collected, agreeing canonical sharing and OneDrive capabilities; raw `sharepoint_access.sharePointSettings` or `onedrive_posture.sharePointSettings` with all remaining settings. Emits one dict with `SharingCapability`, `ODBSharingCapability`, `DefaultLinkPermission`, `DefaultSharingLinkType`, `FileAnonymousLinkType`, `FolderAnonymousLinkType`, `SharingDomainRestrictionMode`, `RequireAnonymousLinksExpireInDays`, `EmailAttestationRequired`, `EmailAttestationReAuthDays`. Capabilities use the Management Shell mapping 0 disabled, 1 new/existing guests, 2 anyone, 3 existing guests; other enums use the shared numeric maps. Expiry -1 is retained. No `_name` companions are projected; assessment-case construction adds them later. Graph-only settings are usually insufficient. |
| `conditional_access_policies` | Full raw `conditional_access.conditionalAccessPolicies`, not `conditional_access_graph` counts. Requires `DisplayName`, `State`, selected `Conditions` applications, authentication flows, client app types/applications, sign-in/user/agent risks and all user inclusions/exclusions; `GrantControls` built-ins, operator and authentication strength, including `AllowedCombinations` when non-null. Every policy must match a whole observed pack shape. A null, empty or all-empty unsupported condition or control (`null`, `{}`, `[]`, `""`, or an object whose members are all such; `false` and `0` are values) is read as absent, whichever way Graph serialises an unset one. A non-empty unsupported condition or control (locations, platforms, devices, session controls, `includeGroups`, `includeGuestsOrExternalUsers`, the application and service-principal filters and the other restriction keys) on an **enabled** policy withholds the entire section with `incomplete_shape`; the field paths appear in `unsupported_conditions`. The same on a policy whose `State` is `disabled` or `enabledForReportingButNotEnforced` does not withhold: every pinned ScubaGear Conditional Access rule requires `policy.State == "enabled"` (`AADConfig.rego`, the ten `*BaseCheck` functions for MS.AAD.1.1v1, 2.1v1, 2.3v1, 3.1v1, 3.2v2, 3.6v1, 3.7v1, 3.8v1, 3.9v1 and 9.1v1; 3.3v2 reads the 3.1v1 result), so such a policy cannot change a verdict. It stays in the projection with its `State`, and what was dropped from it is recorded as `dropped_conditions` (`<policy id>:<field path>`). A schema list field (`IncludeUsers`, `ExcludeRoles`, `ClientAppTypes`, `BuiltInControls` and the rest) that Graph returns as `null` is read as `[]` and recorded as `null_lists_read_as_empty`: the pinned Rego reads a null list as an empty one (`Count`, `ContainsValue` and `ConvertToSet` in `utils/KeyFunctions.rego`; an `in` over either is false), and Graph's reference documents no nullability for these collections. The result must still match a whole observed pack shape, so a null that reads as an empty list the pack never held withholds as `unseen_shape`. Every dropped or normalised value is recorded. |
| `authorization_policies` | Raw `external_identity.authorizationPolicy` or `consent_policy.authorizationPolicy`; singleton `Id`, `AllowInvitesFrom`, `GuestUserRoleId`, default-role `AllowedToCreateApps` and assigned permission grant policy IDs. Duplicate sources must agree. Graph `defaultUserRolePermissions.allowedToCreateSecurityGroups` and `allowedToReadOtherUsers` are accepted and dropped: dependent SCuBA policies do not read them and the pack shape has no such fields. Other default-role permission fields (`allowedToCreateTenants`, `allowedToReadBitlockerKeysForOwnedDevice`) are dropped and listed in `ignored_fields`. |
| `service_plans` | Full raw `licensing.subscribedSkus`, streamed, each `servicePlans` entry with `servicePlanId` and `servicePlanName`. Emits distinct `{ServicePlanId, ServicePlanName}` rows of the plans whose `provisioningStatus` is `Success`, as ScubaGear's exporter does (`ExportAADProvider.psm1`); a disabled or pending plan is left out, a plan without a status is kept, and a tenant with no provisioned plan projects an empty list. Conflicting duplicate IDs invalidate the section. Licence counts alone do not suffice. |
| `privileged_roles` | An existing `normalized/privileged_roles.json` with ProviderExport-shaped `records`: `DisplayName`, `RoleTemplateId`, complete assignments (`PrincipalId`, start/end timestamps when present, each null or `/Date(ms)/`) and PIM `Rules` with source metadata and typed expiration, notification or approval settings. The `identity_governance` collector reads the PIM role policies of the directory roles and the normaliser writes this file when every read behind it succeeded in full ("PIM role policy reads" below); a refused, missing or cut read leaves no file, so the section is `missing_artifact`, never an empty list (a refused schedule read, which the section reads itself, is reported first as `collector_error`); so does an artefact the builder withholds although every read succeeded, which is named in `collection_gaps` as `identity_governance.privileged_roles` (reason `artefact_withheld`, see "PIM role policy reads"), and the section lists that gap under `ignored_failures`. Rows may carry the normalized `key`, which is never projected. No frozen v7 rule shape matches an expiration or an approval rule as Graph returns it: every frozen rule that carries `IsExpirationRequired` also carries `NotificationRecipients` and a `Setting` object, every frozen rule with a `Setting` object also carries `IsExpirationRequired`, `MaximumDuration` and `NotificationRecipients`, and the pack has no null or empty form of any of them on those rules. The pack rows are ScubaGear Rego unit-test inputs, not exporter output; the pinned exporter writes the properties Graph returns for each rule type and pads nothing. The normaliser does not pad either: a rule carries exactly the properties Graph returned for its type, so an artefact built from Graph rules matches no frozen whole shape and is withheld as `incomplete_shape` with detail `{field: "$", kind: "unseen_shape"}` until a pack that holds its shape (or real exports) is frozen (`PACK_SHAPE_DIGESTS` changes with the pinned model, never before). No rule defaults are fabricated, and no null or empty value stands in for a property Graph did not return. |
| `privileged_users` | Complete `normalized/effective_admin_set.json`, no unresolved principals, plus a complete scan of raw `identity.users` (streamed; only the administrators' rows are kept). Every effective user needs `displayName` and an explicitly present nullable `onPremisesImmutableId`; emits `User1..UserN` entries with `DisplayName`, `OnPremisesImmutableId`, `roles`. The identity collector selects the immutable ID on its existing paged user read, including users after the hybrid sample's first 100; this adds no endpoint or per-user reads and needs no new permission. That read requests 100 to 500 rows per page without an operator row limit and stops at 250,000 users. A remaining next link is a `pagination_not_followed` coverage gap, never a complete user inventory. A run of 50 consecutive empty pages that still carry next links is also stopped as a gap, and its coverage message says so. Live collection writes each page to a chunk and retains only a 20-row sample in memory; projection scans at most 250,000 rows, 256 MiB or 10,000 chunks. Older bundles can supply the same property from `domains_hybrid.syncSampleUsers` for users in that sample (conflicting duplicates withhold). An administrator neither read holds withholds the section (`missing_field`). A cut identity user list is a coverage gap and withholds the section (`collector_error`); a projection scan bound withholds it as `oversize` with `kind: scan_bound`. Those withheld sections produce an unknown requirement with `required_evidence_section_not_collected` in the existing model precheck. Without Entra ID P2 the PIM schedule reads are refused with `license_required`; such a refusal with no rows is the no-P2 case, the admin set comes from the directory role assignments (the effective admin set records the schedule sources `not_applicable`) and the refused reads are listed in `ignored_failures`. Any other refusal of a schedule read withholds (`collector_error`). `privileged_roles` has no such variant: every frozen shape carries PIM `Rules`, so a refused schedule read withholds it as `collector_error`. |
| `tenant_id` | Canonical non-zero Entra UUID from the run identity in `run-manifest.json` or saved raw organisation evidence. Recorded and observed UUIDs must agree; a conflict or domain/authority alias cannot become a tenant ID. Synthetic demo UUIDs remain synthetic, without upgrading the run identity's verification status. |
| `scuba_config` | **Synthesised, not collected** (ScubaGear's operator configuration file has no tenant source): ScubaGear's default configuration, the tenant's cloud and the run's emergency-access list (`rule_parameters.break_glass_accounts`), shown to each reading policy in the shape its training rows carry. AAD policies see `{"Aad": null, "CapExclusions": <empty lists>, "RoleExclusions": <empty lists>}`, MS.AAD.9.1v1 with `M365Environment`; MS.EXO.1.1v2 sees `null` (no allowed forwarding domains); Teams policies see `{"M365Environment": ...}`; the three SecuritySuite model views stay `not_collected` (`operator_input_required`). The private SS 2.1 and SS 2.3 rule views receive verified SensitiveUsers and PartnerDomains respectively from their independent local operator inputs described above; neither list enters the model views or shape gate. SS 3.2 no longer reads `scuba_config` in its value rule. `M365Environment`: the public OpenID discovery `dns_posture` saves (`tenant_region_sub_scope` `GCC` is `gcc`; under the US Government scope, `DODCON` is `gcchigh` and `DOD` is `dod`), else licence SKUs sold only in a US Government cloud, else `commercial` (`assumed_default`); disagreeing signals withhold the four environment-gated policies (`environment_ambiguous`). An emergency-access list is resolved as `--break-glass-accounts` is, to object IDs (never the entered names), and placed under the `Aad[...]` entry the policy's Rego reads (for MS.AAD.3.2v2 that is `MS.AAD.3.2v1`, a shape the training data never held, so that policy is withheld as `unseen_shape` whenever an exclusion list exists) for the policies whose Rego honours an exclusion: `CapExclusions` for MS.AAD.1.1v1, 2.1v1, 2.3v1, 3.1v1, 3.2v2, 3.6v1, 3.7v1, 3.8v1, 3.9v1 and `RoleExclusions` for MS.AAD.7.4v1. An unresolved entry, an unreadable user or group list, or a manifest that did not record the list withholds those ten (`break_glass_unresolved`); a view whose whole shape training never held (users and groups together on MS.AAD.3.8v1 or 7.4v1) is withheld for that policy (`unseen_shape`). The section's top-level value is the AAD default; each policy's own view is what its prompt carries. |
| `dmarc_records` | Saved raw `dns_posture.dmarc_records` with `{domain, rdata[]}` containing complete TXT answers. Parsed posture alone is insufficient. |
| `spf_records` | Saved raw `dns_posture.spf_records` in a complete observed pack shape, including its `compliant`/`message` fields where present. Only explicit `domain`, historic `doamin`, `rdata`, `compliant` and `message` fields are permitted; missing values or spelling variants are never synthesised. |
| `dkim_records` | Saved raw `dns_posture.dkim_records` with `{domain, rdata[]}` containing complete TXT answers. |
| DNS sections, missing | `dns_posture` now saves raw SPF, DKIM and DMARC answers with resolver logs. A run that did not select it still withholds those sections; failed or truncated reads also withhold them. Rules read the health-checked answers and logs before the model view's shape and budget checks. |
| `dkim_config` | Exchange raw `exchange_policy.dkimSigningConfig`: `{Domain, Enabled}`. |
| `accepted_domains` | Exchange raw `exchange_policy.acceptedDomains`: `{Name, DomainName}`. Graph verified domains are not a substitute for accepted-domain policy. |
| `transport_config` | Exchange raw `exchange_policy.transportConfig`: `{Name, SmtpClientAuthenticationDisabled}`. The command selects both fields. Normalised `transportConfig` records are keyed by `Name`; this changes record keys and finding ids compared with older runs. |
| `org_config` | Exchange raw `exchange_policy.organizationAuditConfig`: `{Identity, Name, AuditDisabled}`. The command selects all three fields. Normalised `organizationAuditConfig` records are keyed by `Identity`. Live `Identity` serialisation remains unverified; an unreadable value withholds the section. |
| `meeting_policies` | Teams raw `teams_policy.meetingPolicies`: records containing only the validated fields `Identity`, `AllowAnonymousUsersToStartMeeting`, `AllowCloudRecording`, `AllowExternalParticipantGiveRequestControl`, `AllowPSTNUsersToBypassLobby`, `AutoAdmittedUsers`. Summary policy objects cannot supply missing fields. |
| `sharing_policy` | Raw `exchange_policy.sharingPolicy` with `Name` and string `Domains`, available to the rule view. The model shape gate still withholds shapes without a frozen pack witness. |

PowerShell sections can also use existing `normalized/exchange_policy_objects.json`
or `normalized/teams_policy_objects.json` records only when the matching `source_name`
retains every required ProviderExport field. The usual lossy normalisation does not;
counts, shortened settings or renamed labels cannot recreate missing values.

The synthetic offline demo projects `service_plans`, `tenant_id` and `privileged_users`
(its 46 users are scanned, its seven administrators projected). Across 102 catalogue
policies, all 102 receive value-rule answers and none reports `rule_not_implemented`. No model is
called. Its original
anonymous SharePoint defaults, high-severity sharing findings and explorer score of
65 remain intact. Missing SharePoint fields, unsupported CA scope, failed coverage,
source bounds and sparse PowerShell records are withheld rather than upgraded.
Portable tests assert each projected complete section matches one frozen pack shape;
`tests/fixtures/scuba-projection-shapes-v7.json` pins whole-object keys, nesting,
types and observed enum domains, with source-file SHA-256s, row counts and a row/evidence
witness for every shape. List cardinality is ignored but empty lists and
combinations of distinct item shapes remain distinct; numbered user keys represent
a collection of complete user shapes. Derived SharePoint enum annotations are
excluded from raw shapes and applied only when the assessment case is built. All shape
variants require a real train/test witness; paths or types from separate variants
are never combined to authorise a new object.

Area adapters now supply additional private rule evidence. Their registration does not
relax the frozen model shape gate; collected sections can reach rules while remaining withheld from the model.

| Surface | Run-path rule evidence and remaining gaps |
| --- | --- |
| Entra | The additional authentication-method, application-management, directory-setting and delegated-permission-classification adapters are not merged. Rules remain enabled but missing evidence is not assessed. |
| Exchange | `remote_domains`, `transport_rule` and `sharing_policy` now have adapters; `admin_audit_log_config` is supplied by the Defender adapter module. |
| Security Suite | Sixteen Exchange/Defender list sections and `defender_license` have adapters. Explicit licence refusals are distinguished from inferred ones; inferred licence state withholds dependent evidence. DLP policy/rule, DLP licence and protection-alert adapters remain absent. |
| Teams | `meeting_policies`, `app_policies`, `broadcast_policies`, `client_configuration` and `federation_configuration` have adapters. `tenant_app_settings` remains absent. |
| Power Platform | `dlp_policies`, `environment_creation`, `environment_list` and `tenant_isolation` have adapters. Environment `display_name` is discarded; only machine identifiers and rule settings are retained. `domain_settings` remains absent on the run path. |
| Power BI | `powerbi_access_denied_reason`, `powerbi_license_found` and `powerbi_tenant_settings` have adapters for explicit access/licence state and tenant settings. |

All product rows make zero model calls. Shadow mode and its flag are removed.
Historical model/shadow records still validate under their recorded contracts, with the original
attempt, hash and nested-policy consistency checks.

#### Scope post-check

Current rule-only assessments collect the `scope_post_check` envelope for local review,
independently of verdicts. The row-level marking code has been removed; current assessments
never add `post_check` or the `scope_narrowed` limitation to a row, and continue to write
`totals.scope_narrowed: 0`. No output or schema version changes.
The table `configs/scuba-scope-blind.json` is shared by the envelope summary, historical
validation and tests.

ScubaGear's Rego ignores some Conditional Access scope conditions. The envelope names enabled
policies carrying a condition that a tabled item they could have decided ignores. Disabled and
report-only policies do not count. A candidate must carry a grant of the item and every check
its Rego makes of a deciding policy; the table's `source` cites those checks. A condition the
Rego reads for every item that policy could decide is omitted. An unscoped candidate does not
suppress another candidate's scoped entry. The private rule view and its verdicts are unchanged.

`scope_post_check` contains:

- `status`: `evaluated` or `not_evaluated`.
- `source`: `projection` when the Conditional Access section was projected, otherwise `raw`;
  `null` when not evaluated. Raw bundle evidence uses the projection reader's health checks,
  no-symlink opens and scan bounds, so withheld projections can still yield the scope caveat.
- `reason`: `null` when evaluated; otherwise `missing_artifact`, `incomplete_shape`, `oversize`
  or `not_applicable_to_platform`. More than 1,000 candidate policies exceeds the retained bound.
- `count`: the number of enabled candidate policies carrying an ignored scope condition.
- `policies`: distinct names in sorted order, each with sorted `conditions`, bounded by the
  projection item budget. Names have e-mail local parts masked before being cut to 200 characters;
  the removed `--no-redaction` is rejected by `auditex assess` (exit 2). Conditions are `conditions.locations`,
  `conditions.platforms`, `conditions.devices`, `conditions.clientApplications` and
  `conditions.clientAppTypes`. The grant operator is never listed in the envelope.

An all-inclusive or unstated location/platform include with no exclusions is unscoped, as is
`ClientAppTypes` of exactly `all`, or all agent identities with none excluded. Named or trusted
locations, exclusions, platform subsets, device filters and restricted application sets can
narrow scope. The envelope lists a condition only when an item the candidate could decide
ignores it; a textbook legacy-authentication block or compliant all-agent block is not listed
merely for its required client types or agent selection.

Historical row metadata remains readable under its recorded contract. A marked model row has
`post_check` containing `kind: scope_narrowed`, sorted distinct `policies`, sorted `conditions`
and a positive `count`; its limitations contain `scope_narrowed` and its total counts the mark.
Historical row conditions may also include `grantControls.operator` where the table permits it.
These fields and their schema members remain supported, including files without any scope fields.
Validation still rejects a mark on a non-met or rule row, a not-applicable answer, an untabled
policy, disallowed conditions, unsorted or over-counted lists, inconsistent limitation/mark pairs
or totals, a mark without an evaluated envelope, or an envelope source inconsistent with the
projection. No report, export or explorer renders these rows today; a future historical-row
renderer must present a marked result as **met per ScubaGear, scope narrowed**, naming the
policies and conditions rather than presenting a clean pass.

`model_assessment.json` is a private, named post-finalisation output and may be unlisted by the
original hash manifest; that manifest is never rewritten. It is reported as an unlisted
limitation, and an already sealed output cannot be replaced. The removed dry-run option once wrote
`model_assessment_prompts.jsonl`; no current command writes it.
Consumers should validate optional assessment JSON before using it. Model assessment
never changes findings or the deterministic rule-based baseline alignment. See
[Running the assessment](../guides/model-development.md#running-the-assessment) (the anchor is kept for the `auditex assess` instructions).

Findings must include `evidence_refs`. Each reference must identify at least `artifact_path`, `artifact_kind`, `collector`, and `record_key`. Bundle validation checks duplicate finding IDs, missing references, malformed references, references pointing at missing artifacts, and references whose record does not exist in the artifact they name (see "Evidence references and traceability").

`reports/report-pack.json` includes `proof_table` for board, CLI, and MCP review. New proof rows flatten every finding evidence reference into `finding_id`, `rule_id`, `proof_status`, `collector`, `artifact_path`, `artifact_kind`, `record_key`, and optional JSON pointer or endpoint fields; from `2026-10-22` they also carry `collected_at`, `content_hash` and `unresolved_reason`, and `proof_status` is derived from resolution. A finding's `proof` summary gains `supported_count`, the number of its references that resolved. The same pack now also carries `reviewer_index` with `start_here`, `prove_this`, and `known_limits` rows so customer reviewers can move from posture to proof faster. The validator accepts older per-finding proof summaries, and validates the stricter row shape when the new fields are present. Operators can render the same rows with `auditex report proof-table <run-dir> --format md`. Enterprise handoff starts with `auditex report customer-pack <run-dir> --output-dir <dir>`, `auditex report verify-pack <dir>`, or `auditex report handoff <run-dir> --format md`. The pack writes a README, handoff, full report, API ledger, permission ledger, proof table, JSON copies, selected customer-safe source artifacts, `checksums.sha256`, and generated-file/source-artifact hashes. `pack-manifest.json` source now also carries `validation_summary` and `reviewer_summary`; `verify-pack` checks those against `handoff.json` so customer start-point truth cannot drift. The handoff, API call, permission, and proof-table commands all accept `--output <path>` for persisted customer packs.

Microsoft 365 report packs can also carry `detection_coverage` (`signals[]` with `name`, `title`, `status` of `on`, `off`, or `unknown`, `reason`, `why_it_matters`, and an `evidence_ref` into `normalized/detection_signal_objects.json`, plus `score`, `counts`, `assessed_ratio`, and `limitations`) and the informational `public_footprint` (`domains[]` with discovery status, authentication type, and an `evidence_ref` into `normalized/public_footprint_objects.json`). `score` is computed over `on` and `off` signals only; `unknown` is never counted as `off`. Both sections survive the coverage-gap refresh of the report pack. New normalized sections: `detection_signal_objects`, `public_footprint_objects`, and `identity_protection_objects`. Contract `2026-10-22` adds `intune_policy_assignment_objects`, keyed `intune_policy_assignment:<policyId>`, with `policy_id`, `policy_name` and `assignment_count` for every policy the Intune assignment read returned, including those with none. It also adds `sharepoint_tenant_settings` and `break_glass_assessment` (see "Microsoft 365 sharing, federation and emergency-access rules"). It also adds `device_posture`, `compliance_policy_objects`, `update_management_objects` and `defender_av_objects` (see "Microsoft 365 device, update and malware evidence"); `devices` and `exchange_policy_objects` records gain fields.

Microsoft 365 runs that include the `conditional_access` or `consent_policy` collector also write `normalized/identity_control_verdicts.json`, one record per tenant and control, keyed `identity_control_verdict:<control>`. `control` is `effective_mfa`, `administrator_mfa`, `legacy_authentication_block` or `user_consent` (the last only when `consent_policy` ran). `verdict` is `enforced`, `enforced_with_exclusions`, `not_enforced` or `unknown` for `effective_mfa` and `administrator_mfa`; `blocked`, `blocked_with_exclusions`, `not_blocked` or `unknown` for `legacy_authentication_block`; `restricted`, `limited`, `unrestricted` or `unknown` for `user_consent`. `enforced` and `blocked` need every principal excluded from all of the qualifying policies to be an emergency access account the operator listed with `--break-glass-accounts`: a policy that targets everyone but excludes a role, a guest type, or any other user or group does not require MFA of them, and that reads `*_with_exclusions`, which baselines treat as a gap and never as a pass. Exclusions are compared by person as well as by id: a user excluded by id from one qualifying policy, through a group the run read the members of (role-assignable groups, nested groups included) from a second and through an administrator role they hold from a third is outside all of them, and is listed as a `user` exclusion with the route each policy takes (`via`: `policy_id`, `type`, `id`). A group whose members the run did not read (and the operator did not list as emergency access) might contain any principal: a principal that one policy excludes by a route the run can see, and every other qualifying policy excludes only through such a group, is added as a `possible` exclusion (`possible: true`, with `members_read: false` on that policy's `via` entry), so the MFA and legacy verdicts read `*_with_exclusions` and the administrator verdict reads `unknown` (`administrator_exclusion_unresolved`) unless another policy covers the administrator. A role that is not an administrator role is judged by its id. `unresolved_operator_accounts` lists the entries of `--break-glass-accounts` that matched no collected user or group (or more than one); the verdict is judged without them and the findings name them. `limited` user consent means users can still consent (the Microsoft-managed policy `microsoft-user-default-recommended` and its companion `microsoft-user-default-allow-consent-apps`, or `microsoft-user-default-low`); CIS 5.1.5.1 asks for none, so only a tenant that assigns no self-service consent policy reads `restricted`. A negative verdict needs a complete read: a policy list that was blocked, truncated or never collected gives `unknown`, with the cause in `reasons` and the endpoint states in `policy_collection`, `security_defaults` and `authorization_policy`. `basis` lists what establishes a positive verdict (`security_defaults`, `conditional_access_policy`). When security defaults are on beside a qualifying policy that has gaps, security defaults alone establish the verdict and `basis` lists only `security_defaults`: the policy is not a basis for a Conditional Access benchmark control. Security defaults keep the tenant verdict (and Cyber Essentials, Zero Trust and Secure Score read it as enforcement), but CIS `5.2.2.1` to `5.2.2.3` and SCuBA `MS.AAD.3.2v1` and `MS.AAD.1.1v1` audit a Conditional Access policy: when `basis` lacks `conditional_access_policy`, baseline alignment reads those controls `not_assessed` with the reason `conditional_access_policy_required:basis_security_defaults` instead of `pass` (`_verdict_basis_requirements` in `configs/control-mappings.json`). For `effective_mfa`, `qualifying_policies` are the enabled policies that require MFA for all users on all cloud apps, `excluded_principals` are the principals excluded from every qualifying policy (`type`, `id`, resolved `display_name`, and `sanctioned`, true for an emergency access user or group the operator listed), `unsanctioned_exclusions` and `unsanctioned_exclusion_count` are the part of that list that is a gap, `sanctioned_exclusion_source` is `operator` or `none`, `limitations` carries the caveat that per-user (legacy) MFA states are not read (empty for a plain `enforced`), `non_qualifying_mfa_policies`, `report_only_mfa_policies` and `unverified_policies` carry each near-miss policy with its `reasons`. The `effective_mfa` verdict is the reading Cyber Essentials takes: an administrator role or administrator that every qualifying policy excludes is covered when a role-targeted MFA policy (a near miss only for `not_all_users`) includes the role and leaves nobody out, and the row is marked `covered_by_policy_ids` (the policy is listed in `supplementary_policies`, and the row is not counted in `unsanctioned_exclusions`); groups, other users and roles the policy does not include are never covered this way. `single_policy_verdict` is the reading CIS 5.2.2.2 and SCuBA `MS.AAD.3.2v1` take, which look for one policy that leaves nobody out: it does not credit that cover, and `ca.mfa_split_across_policies` (low, CIS and SCuBA only) is raised when the two differ. `registration_context` repeats the registration counts as context only: registration never produces `enforced`. `legacy_authentication_block` carries the same exclusion fields on its `blocking_policies`. A policy blocks legacy authentication only when it names both legacy client app types (`exchangeActiveSync` and `other`, as ScubaGear and the CIS audit require) and no location condition limits it. Two otherwise identical block policies that each name one of them block both, but neither is the one policy the benchmarks look for: the verdict stays `not_blocked` with the reason `legacy_block_split_across_policies` and the policies in `block_split_across_policies`, and `ca.legacy_auth_not_blocked` is raised at medium, not high. A block of every client type (a country block that exempts the trusted countries), or a legacy block that includes only some locations or excludes any, is a near miss (`legacy_client_app_types_not_targeted`, `narrowed_by_location`, `excludes_locations`). `administrator_mfa` reads MFA against the effective administrator set only: security defaults enforce it (but not a phishing-resistant method), and so does a qualifying policy that targets all users, or every directory role an administrator holds (a role-targeted policy needs a complete administrator set, otherwise `unknown` with the reason `administrator_set_unknown`). What every qualifying policy shares in its exclusions then decides: an excluded administrator role someone holds, or an excluded administrator user, gives `not_enforced` (those administrators are not required to use MFA) unless another enabled policy that reaches them requires it; an excluded group, or a guest type while a guest administrator is possible, gives `enforced_with_exclusions`. Policies are combined per administrator: a role-targeted policy that reaches only some roles (`covers_only_some_administrator_roles`, listed in `non_qualifying_mfa_policies`) still requires MFA of the administrators it reaches, so it covers the role an all-users policy excludes (`supplementary_policies` lists the policies relied on), and role-targeted policies that each reach some administrators cover them together (`enforced` with no qualifying policy, when the administrator set is complete). When the only policy that could cover an excluded administrator cannot be verified, or excludes a user or a group whose members were not read, the verdict is `unknown` (`authentication_strength_unverified`, `administrator_exclusion_unresolved`), not `not_enforced`. While the administrator set is incomplete, an excluded administrator role nobody is known to hold also reads `unknown` (`administrator_set_unknown`) unless a policy that includes the role and leaves nobody out covers it, and a covering role policy that excludes a user is doubted (the user may be a holder the set is missing). The record adds `administrator_set` (`state`, `role_count`, `administrator_count`), `administrator_exclusions`, `phishing_resistant_verdict` (the same reading over the policies whose grant requires a phishing-resistant authentication strength: the built-in one, or a custom strength that allows only FIDO2, Windows Hello for Business or certificate-based multi-factor credentials, and not as one of several alternatives) and `phishing_resistant_policy_ids`. `administrator_mfa` also carries two stricter, static readings that never change `verdict` (Cyber Essentials reads the roles held today): `role_catalog_verdict` (`enforced`, `not_enforced`, `unknown`) judges the policies against the CIS 5.2.2.1 administrator role list, 15 roles by template id (Application, Authentication, Billing, Cloud Application, Conditional Access, Exchange, Global, Helpdesk, Password, Privileged Authentication, Privileged Role, Security, SharePoint and User Administrator, Global Reader), and `phishing_resistant_role_catalog_verdict` judges the phishing-resistant policies against ScubaGear's eight default privileged roles (Global, Privileged Role, User, SharePoint, Exchange, Hybrid Identity, Application and Cloud Application Administrator). A role is covered when a verified policy includes it (all users, or the role) and does not exclude it, whoever holds it today; `role_catalog_uncovered_roles` and `phishing_resistant_role_catalog_uncovered_roles` list each role that is not (`id`, `name`, `reason`: `not_included` or `excluded`). Security defaults cover every administrator role (the phishing-resistant reading still reads `not_enforced`). Findings from these verdicts cite the verdict record and the Conditional Access policy records it names. `normalized/conditional_access_graph.json` policy records gain `targeting`: the raw include and exclude lists for users, groups, roles and guests, applications, `client_app_types`, platforms, locations, risk levels, the device filter (`device_filter_mode` and `device_filter_rule`) and the grant (`operator`, `built_in_controls`, `authentication_strength`). A policy that excludes platforms, applications or devices (exclude-mode filter) never qualifies as enforcing MFA or blocking legacy authentication; the near-miss `reasons` are `excludes_platforms`, `excludes_applications` and `device_filter_excludes_devices`, and the policy summary records `excluded_platforms`, `excluded_applications` and `device_filter`. `normalized/consent_policy_objects.json` authorization policy records gain `permission_grant_policies_assigned`, `allowed_to_create_apps` and `guest_user_role_id`. New rules: `ca.mfa_not_enforced` (also raised, at medium, for `enforced_with_exclusions`), `ca.legacy_auth_not_blocked` (also for `blocked_with_exclusions`), `ca.admin_mfa_not_enforced` (high for `not_enforced`, medium for `enforced_with_exclusions`), `ca.mfa_split_across_policies` (low; CIS `5.2.2.2` and SCuBA `MS.AAD.3.2v1` only: everyone is required to use MFA, but only by combining an all-users policy with a role policy), `ca.admin_mfa_role_set_incomplete` (medium; CIS `5.2.2.1` only, not Cyber Essentials or Secure Score; raised when administrator MFA is enforced but the CIS role list is not covered, for example a policy for the roles held today, or an all-users policy that excludes a role nobody holds), `ca.admin_phishing_resistant_mfa_not_enforced` (low; raised only when administrator MFA is enforced but no phishing-resistant strength reaches every administrator, or the phishing-resistant policies do not cover ScubaGear's privileged roles), `consent_policy.user_consent_unrestricted`, `consent_policy.user_consent_limited` (medium) and `identity.privileged_mfa_not_registered`, plus the diagnostic `ca.enforcement_unverified` and `consent_policy.user_consent_unverified`, which an `unknown` verdict raises instead. An assigned self-service consent policy that is neither a recognised Microsoft built-in nor a tenant-defined one (an unrecognised `microsoft-` id) reads `unknown` with the reason `built_in_permission_grant_policy_not_evaluated`, and a tenant-defined one `custom_permission_grant_policy_not_evaluated`; `built_in_policies` and `custom_policies` list them. Registration reports (`identity.*_mfa_not_registered`) map only to the registration controls (CIS `5.2.3.4`, Secure Score `MFARegistrationV2`): they never decide an enforcement control.

Microsoft 365 runs that include the `identity` or `identity_governance` collector also write `normalized/effective_admin_set.json`: who holds an administrator directory role, resolved once for every rule that needs it. A role counts as an administrator role when its name says administrator (or it is the Global Administrator template), the convention the privileged MFA and stale-account rules always used, or when it is one of the privileged built-in roles that do not say so, matched by role template id: Partner Tier1 Support, Partner Tier2 Support and Directory Writers. The section holds one `effective_admin_set_summary` record (key `effective_admin_set_summary:summary`) and one `effective_admin` record per principal that holds such a role (key `effective_admin:<principal id>`). Each `effective_admin` record has `principal_id`, `principal_type` (`user`, `group`, `service_principal`, or `unresolved` for an id no inventory resolves), `is_user`, `counted`, `display_name`, `principal_name`, `user_type`, `is_guest`, `enabled`, `roles`, `role_names`, `routes`, `scope`, `global_administrator` and `state`. Only users (and `unresolved` principals, which a role assignment can only hold as a user, a group or a service principal that the inventories rule out) are `counted`; a group or service principal that holds a role is listed with `counted: false`, and its members, nested groups included, are expanded to the users and service principals behind them. Each entry of `roles` has `role`, `role_definition_id`, `route`, `scope`, `global_administrator` and `records` (the `section` and `key` of the assignment, schedule and membership records it comes from, which findings cite). `route` is `direct_active` (an entry of `role_assignments`, or an active PIM assignment schedule), `pim_eligible` (a PIM eligibility schedule) or `via_group`, which also carries `group_id`, `group_name`, `group_assignment` (`active` or `eligible`, whether the group holds the role standing or through PIM) and `nested_group` when the user is reached through a nested group. `scope` of a record is `tenant`, `scoped` (every role is limited to an administrative unit) or `unknown` (the role read does not return `directoryScopeId`). For counted principals the licensing collector adds `licence_state` (`known` or `unknown`, with `licence_reason`), `mailbox_licence`, `productivity_licence` and `licence_sku_part_numbers`; a licence counts only when an enabled Exchange Online mailbox plan (`EXCHANGE_S_STANDARD`, `EXCHANGE_S_ENTERPRISE`, `EXCHANGE_S_ESSENTIALS`, `EXCHANGE_S_DESKLESS`, `EXCHANGE_S_STANDARD_MIDMARKET`) or productivity plan (`OFFICESUBSCRIPTION`, `OFFICEMOBILE_SUBSCRIPTION`, `SHAREPOINTENTERPRISE`, `SHAREPOINTSTANDARD`, `SHAREPOINTWAC`, `TEAMS1`, `MCOSTANDARD`, `YAMMER_ENTERPRISE`) is part of an assigned SKU and not disabled for the user; a plan name is matched without a `_GOV` or `_EDU` suffix. A SKU that lists no service plans is classified from its part number against separate mailbox and productivity lists (`EXCHANGESTANDARD` and `EXCHANGEENTERPRISE` are mailbox only, `O365_BUSINESS` is productivity only), and a SKU on neither list leaves the principal's `licence_state` `unknown`. The summary has `state`, `reasons`, `sources`, `admin_count`, `global_admin_count`, `direct_active_count`, `pim_eligible_count`, `group_expanded_count`, `guest_admin_count`, `non_user_principal_count`, `unresolved_principal_count`, `licence_state` and `licence_reasons`. `state` is `complete` only when every source was read in full: `sources` lists `role_definitions`, `role_assignments`, `role_assignment_schedules`, `role_eligibility_schedules` and `group_membership_fanout` with their state (`collected`, `blocked`, `truncated`, `absent`, `not_applicable` or `not_needed`). Otherwise `state` is `unknown` and `reasons` names each gap, for example `role_eligibility_schedules_absent`, `role_assignments_truncated` or `group_membership_fanout_truncated` (the fan-out's `fanout_complete` was false or its list was cut). PIM schedules refused with `license_required` are `not_applicable`: that tenant has none to hide. A skipped `identity_governance` collector is `blocked` with detail `collector_skipped`, never `not_applicable`: a run skips a collector on a permission block, an exception or a missing raw file as well as on a missing licence, and a skipped collector leaves no payload to say which. The fan-out is `not_needed` when no group (or unresolved principal) holds a role and it was not collected. A section whose set is `unknown` still lists the administrators it read. **Not read:** PIM for Groups eligible membership (a user who is eligible to become a member of a role-assignable group) is not collected, so those users are not in the set; the set holds the standing members of such groups only. ScubaGear's `MS.AAD.7.1v1` instructions count them, so a tenant that relies on PIM for Groups can have more Global Administrators than the set shows. Collecting those schedules is a follow-up. `role_assignments` records gain `directory_scope_id` when the source returned it (the collector selects `directoryScopeId`). The `identity.global_admin_*` rules, `identity.privileged_mfa_not_registered`, `identity.privileged_stale_account`, `identity.guest_with_privileged_role`, `identity.service_principal_privileged_role`, `identity.admin_holds_productivity_licence` and `attack_path.no_mfa_to_tier0` read this section; their findings cite the `effective_admin` record and the records in its `roles[].records`, and the attack path finding records `effective_admin_set_state`. New rules: `identity.service_principal_privileged_role` (high; one finding per service principal that holds Global Administrator or Privileged Role Administrator, directly, PIM-eligible or through a role-assignable group: it is listed in the set with `counted: false`, so no administrator count includes it), `identity.admin_holds_productivity_licence`, `identity.stale_guest` (guests with no successful sign-in for 90 days, or `AUDITEX_STALE_GUEST_DAYS`; `build_findings(stale_guest_days=...)` overrides both) and `identity.guest_with_privileged_role`, plus the diagnostic `identity.admin_set_unverified`, which an `unknown` set raises (`identity:admin_set:unverified`, with `reasons` and `sources`) while `identity.global_admin_singleton` stays silent. Baseline alignment reads each of these rules as `not_assessed`, never `pass`, when the set is `unknown` (`admin_set_unknown:<reasons>`), absent (`admin_set_not_collected`), when licences were not read (`licence_data_unavailable:<reasons>`) or, for the sign-in rules (`identity.stale_guest`, `identity.stale_enabled_account`, `identity.privileged_stale_account`), when sign-in activity was unavailable (`signin_activity_unavailable`), including when the identity collector is partial only because `userSignInActivity` was refused with `license_required`. `identity.global_admin_singleton` and `identity.global_admin_sprawl` also carry `framework_thresholds`, one entry per framework bound (`framework`, `control_ids`, `metric`, `observed`, `minimum`, `maximum`, `breached`), from `_rule_thresholds` in `configs/control-mappings.json`: CIS `1.1.3` allows two to four Global Administrators and SCuBA `MS.AAD.7.1v1` two to eight. Baseline alignment reads each framework against its own `breached` value, so a finding for five administrators fails CIS `1.1.3` while SCuBA `MS.AAD.7.1v1` reads `pass`; a framework with no entry takes the finding as it is. `framework_thresholds` is optional and ignored by consumers that do not know it.

#### PIM role policy reads

Microsoft 365 runs that include `identity_governance` read the PIM role policies of the **directory roles** with two operations, both GET: `roleManagementPolicyAssignments` (`/policies/roleManagementPolicyAssignments` with `$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'`, Graph v1.0; the API requires that filter and accepts no `$top`) lists which policy governs which role, and `roleManagementPolicyRules` reads `/policies/roleManagementPolicies/{id}/rules` once per distinct `policyId` (through `$batch` when the client has it; the endpoint accepts no `$top`), at most 250 policies. The aggregate coverage row is `roleManagementPolicyRules` and the derived fan-out row `roleManagementPolicyRulesFanout`; the section carries a `fanout` summary like the other fan-outs. A rule row keeps only `policyId`, `id`, `@odata.type`, `isExpirationRequired`, `maximumDuration`, `notificationType`, `notificationRecipients` and `setting.isApprovalRequired`: the targets, the enablement and authentication-context settings and the approvers' names and ids (`approvalStages`) are not stored. No scope is added to the collector's `required_permissions`: `RoleManagement.Read.Directory`, which it already requires, covers these reads, and scope names are compared exactly (the capability matrix and the interactive consent flow), so a registration that grants the existing set is not shown as `blocked_by_scope` and is not asked to consent again. `RoleManagementPolicy.Read.Directory` is the least-privilege alternative for a new registration (the schedule reads still need `RoleManagement.Read.Directory`) and appears in the permission notes and the admin permission guide only. PIM for Groups policies need `RoleManagementPolicy.Read.AzureADGroup` and are not read. A policy id is a path segment and is percent-encoded (every reserved character, `/` included) in the request; the rows keep the id as Graph returned it.

`normalized/governance_objects.json` gains `role_management_policy_assignment` records (key `role_management_policy_assignment:<assignment id>`; `policy_id`, `role_definition_id`, `scope_id`, `scope_type`) and `role_management_policy_rule` records (key `role_management_policy_rule:<policyId>:<ruleId>`, because a rule id such as `Expiration_Admin_Assignment` repeats across policies; `policy_id`, `rule_id`, `rule_type`, `is_expiration_required`, `maximum_duration`, `notification_type`, `notification_recipients`, `is_approval_required`).

`normalized/privileged_roles.json` is the ScubaGear ProviderExport shape that `auditex.scuba_projection` reads, one row per privileged directory role: `key` (`privileged_role:<role definition id>`), `DisplayName`, `RoleTemplateId` (the role definition id), `Assignments` (`PrincipalId`, `StartDateTime`, `EndDateTime`, from `roleAssignmentSchedules`; a date is a `/Date(ms)/` string, `EndDateTime` is `null` only for a schedule that says `noExpiration`, and `StartDateTime` preserves Graph's `scheduleInfo.startDateTime`: an explicit `null` stays `null`, an absent key stays absent, and a dated value is converted to `/Date(ms)/`) and `Rules` (`Id`, `RuleSource` the role's display name, `RuleSourceType` `Directory Role`, and the fields of its kind: `IsExpirationRequired` and `MaximumDuration` for `Expiration_*`, `NotificationRecipients` and `NotificationType` for `Notification_*`, `Setting.IsApprovalRequired` for `Approval_*`). The enablement and authentication-context rules are not carried; nothing else is copied. A role is privileged by the convention of the effective administrator set (above). The envelope says `collection_status: collected` and `complete: true`, so an empty list is a known empty one. The file is written only when the assignment, rule, schedule and role-definition reads all succeeded in full (none cut, none refused, no policy read failed) and every privileged role has a policy with rules and readable schedules (an expiration the schedule does not state, an unparseable date or a rule missing its typed field leaves no file). Nothing is defaulted or padded: a rule has exactly the properties of its kind and every value in it is Graph's own (an `Expiration_*` rule never carries `NotificationRecipients` or `Setting`, an `Approval_*` rule never carries `IsExpirationRequired`, `MaximumDuration` or `NotificationRecipients`, a `Notification_*` rule never carries `Setting`).

When every read succeeded in full and the artefact is withheld all the same, the collector stays `ok` and the reason is recorded in `normalized/collection_gaps.json`: one record `identity_governance.privileged_roles` with `reason: artefact_withheld`, `rows_collected: 0` and `reasons`, a sorted list of every cause found. A cause is `empty_policy_assignment_list` (the `roleManagementPolicyAssignments` list holds no row although the tenant has privileged roles) or a code and the role definition id it concerns, `<code>:<role definition id>`, where the code is `role_without_policy` (no directory-role policy assignment for the role), `conflicting_policies` (two policies for one role), `policy_without_rules` (the assigned policy has no rule row), `policy_without_exportable_rules` (it has rules, none an expiration, notification or approval rule), `unreadable_rule` (a rule lacks the typed field of its kind), `unreadable_schedule` (a role assignment schedule has no principal, no readable expiration or an unparseable date) or `role_without_name`. The projection still reports `privileged_roles` as `missing_artifact`; the gap is listed under that section's, and `privileged_users`', `ignored_failures` and does not withhold either. Nothing is recorded when a read behind the artefact failed or was cut (its own gap says so) or was never made (a bundle collected before these reads: that is "not collected").

Inference, not confirmed offline: `Assignments` are built from `roleAssignmentSchedules`, which also lists the schedules scoped to an administrative unit (`directoryScopeId`); they are copied without their scope and not filtered, and ScubaGear may read the schedule instances (`roleAssignmentScheduleInstances`) instead. This must be confirmed on a live tenant before the shape gate opens (before a pack that holds the shape is frozen and `PACK_SHAPE_DIGESTS` changes).

A refused or missing policy read is recorded, never read as "no policies": the coverage row is `failed` with its error class, the collector is `partial` (a refused scope reads `blocked_permission` in `normalized/coverage_ledger.json`) and `normalized/collection_gaps.json` names the operation (`identity_governance.roleManagementPolicyAssignments` or `.roleManagementPolicyRules`) with `status`, `error_classes` and `reason`: `endpoint_unavailable` for an HTTP 404, or for Graph's HTTP 400 "Resource not found for the segment" (the endpoint is not served to the tenant or API version), and `read_failed` otherwise. When the assignment list could not be read, no rule is requested and no `roleManagementPolicyRules` section is written. A licence refusal (`license_required`) on either read is a licence-gated section like the PIM schedules (`baselines._LICENCE_GATED_SECTIONS`); when every failed rule read was such a refusal, the derived `roleManagementPolicyRulesFanout` row carries `license_required` instead of `incomplete_evidence` (and is licence-gated too), so the collector reads as licence-limited. A cut fan-out or a rule without a usable id is never excused by a licence. The projection lists these failures under `ignored_failures` for the sections that do not read them (`privileged_users`) and reports `privileged_roles` as `missing_artifact`.

Raw evidence remains local-only. `ai_safe/` artifacts are checked for sensitive key names and token-like values so redacted reasoning surfaces do not drift into raw credential or claim storage.

`data-handling.json` records whether the bundle is read-only, whether body/file content was read, whether write actions ran, provider-specific no-content assertions, and scope risk. Google Workspace audit bundles must assert no Gmail body reads and no Drive file content reads. When a provider requires write-capable OAuth scopes for read-only settings visibility, `scope_risk` and `write_capable_scopes` make that blast radius explicit.

`audit-plan.json` records the autopilot evidence gates, expected collectors, required scopes, and quality gate (`complete`, `partial`, or `unusable`). When optional artifact paths are present in the manifest, validation checks the referenced file and its core semantics.

A collector is trusted in `live-readiness.json` and `audit-plan.json` only with at least one successful non-derived live read; successful empty reads count, while skipped, failed, derived and offline rows do not. Offline audit plans therefore have zero trusted gates. The permissions ledger also exposes gates that are not live-verified.

Quality still follows capabilities, coverage gaps and blockers, so when a sole collector's reads are all skipped without a section-scoped gap or blocker it can be `complete` with `human_reviewer_required: false` and `trusted_gate_count: 0`, while readiness is `setup_only`. After a preflight skip, the manifest and audit plan list the remaining collectors in `selected_collectors`, while readiness includes the original selection.

`live-readiness.json` and `audit-plan.json` classify each blocker as `auth_scope`, `admin_role`, `license`, `service_absent`, `local_tool`, `tenant_policy`, `runtime`, or `unverified`. They now share the same per-collector evidence-gate rows so reviewer wording, blocker kind, and next-step guidance stay aligned across both artifacts. This distinction is required for enterprise handoff because a missing local module, an unlicensed tenant workload, and a missing OAuth scope need different customer actions.

`api-inventory.json` records the enterprise API call ledger: declared collectors, the collectors' declared call rows (`observed_calls`, the expected set), required and missing permissions, status, item counts, read/write classification, data class, and no-content-read safety. Its `schema_version` is `2026-10-22`. That version adds, additively: `observed_ledger` (the methods, endpoints and commands read back from `audit-log.jsonl`, the calls refused, and observed calls outside the declared set); `observed_ledger.teams_admin_rest`, `observed_ledger.instrumentation.teams_admin_rest` and `observed_ledger.outside_declared.teams_admin_rest`; `counts.observed_graph_requests`, `observed_graph_endpoints`, `observed_teams_admin_rest_requests`, `observed_teams_admin_rest_endpoints`, `observed_commands`, `refused_calls` and `observed_outside_declared`; `safety.observation_basis` (`transport_audit_log` or `coverage_ledger_only`), `observed_methods`, `observed_write_calls`, `observed_content_read_calls`, `observed_log_complete`, `malformed_log_lines`, `refused_calls` and `observed_outside_declared`; `observed_ledger.log` (`readable`, `malformed_lines`, and `empty: true` for a log with no event at all next to calls the run declared); and `command` and `command_variants` on declared command rows. `safety.read_only` and `safety.no_content_reads` are re-derived from the observed ledger and can only become stricter than the declaration; any refused call, unverified `$batch` request, malformed log line or empty log (a log with no event at all next to calls the run declared: it was emptied or never written, so it observed nothing) makes `read_only` false (and the audit-plane validator then rejects the bundle). A run that declared no call, and an offline replay (`observation_basis` `offline_replay`), are not affected. The PowerShell adapter logs `command.completed` with the command words, the return code and the outcome (`status` `ok` or `failed`, `error_class`), and `command.failed` (timeout, exception, no `pwsh`) with the command words too; the ledger reads that status instead of `rc=<code>` and ends a command that never completed as `failed`. `validation.json` reports `observed_call_outside_declared` as a warning when the ledger saw a call the collectors never declared (`observed_ledger.outside_declared`), and `auditex gate` and `gate-drift` add a warning naming up to three of them. Consumers that ignore unknown keys are unaffected. Audit-plane bundles fail validation when this artifact reports tenant writes or body/file content reads. See `docs/reference/api-call-catalog.md` for the customer-facing review path.

Endpoint templates replace only identifiers with `{id}`: a GUID, a segment with `@`, an all-digit segment, and an opaque identifier of 24 or more characters that contains a digit or one of `_`, `=` and `-`. A long letters-only segment such as `deviceCompliancePolicies` or `roleEligibilitySchedules` is a resource name and is kept, so sibling endpoints stay distinct and an undeclared one is listed under `outside_declared`. Content-read detection (`safety.no_content_reads`) covers message and attachment endpoints, `$value`, driveItem and OneNote content, calendar `events` and `calendarView` (the default calendar, a calendar by id and a calendar inside a group), group `threads`, `conversations` and `posts`, `getAllMessages`, SharePoint list `items`, To Do `tasks` and the search query endpoint, and a `$select` of `body`, `bodyPreview`, `uniqueBody` or `content` or an `$expand` of a content collection, whether the query is passed as a parameter, left inside a next-page URL or carried in a `$batch` inner URL. It is a denylist: an endpoint it does not name is not classified as content. `observed_ledger.graph` also lists `redirects` (`from`, `host`, `path`, `count`: the hops `GraphClient` followed, never their query) and `redirects_refused` (a redirect that was not followed). Resource-token requests are counted under `auth.token_requests` like the Graph token request.

Run bundles are created with mode `0700` for the run directory and every directory under it and `0600` for every file, whatever the umask of the caller. A tenant or run name that contains `/`, `\`, `..` or a control character is refused, because the names form the run directory name.

Gmail vacation-responder text (`responseSubject`, `responseBodyPlainText`, `responseBodyHtml`), Gmail send-as `signature` and Gmail filter `criteria.query`, `criteria.negatedQuery` and `criteria.subject` are excluded at request level by `fields` masks and are never requested; if one still arrives (an offline fixture) it is dropped and leaves no length or flag behind. `vacation.enableAutoReply`, `restrictToDomain`, `restrictToContacts`, `startTime` and `endTime` are unchanged. Microsoft Graph automatic-reply message bodies (`internalReplyMessage`, `externalReplyMessage`) are not written to `raw/` or `normalized/`; each leaves a `<field>Length` integer and a `has<Field>` boolean in its place, and `status` and `externalAudience` are unchanged. This holds for live collection and for offline replay of a fixture, which copies and normalizes the same fields.

`framework_mappings` uses canonical keys only: `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, `mcsb`, `cyber_essentials`, `google_workspace_baseline`, `nist_800_53`, `iso_27001`, `soc2`, `nis2`, `dora`, `mitre_attack`, and the deprecated `cis_m365_v3`. The validator still accepts `cis_m365_v3` for older bundles and operator overrides, but shipped mappings no longer emit it. Exporters treat those keys as stable taxonomy labels for SARIF, OSCAL, and the CSV `framework_mappings` column. `configs/framework-catalog.json` records the source version, date, URLs, and verified control ids for each benchmark key; see `docs/reference/framework-mappings.md`.

`reports/report-pack.json` carries `baseline_alignment`. For each of `cis_m365_v7`, `cisa_scuba`, `ms_secure_score`, `ms_zero_trust`, and `mcsb` it lists the controls the shipped rules map to, with `status` (`fail`, `accepted_risk`, `pass`, or `not_assessed`), the mapped `rule_ids`, per-rule `rule_statuses`, and open `finding_ids`. Each `rule_statuses` entry has `rule_id`, `status`, and `evaluated`; a rule that was not evaluated also has a `reason`. A rule passes only when it was evaluated: every collector that feeds it completed and the evidence it reads was present. A control passes only when every mapped rule passed. `baseline_alignment.unmapped_findings` (`count`, `open_count`, `accepted_count`, `collectors` as a list of `{collector, count}`, `finding_ids`) counts findings with no `rule_id`, which no control can see. Every finding this version emits carries a `rule_id` (the finalizer refuses one without), so `count` is 0 for these bundles; a non-zero count marks a bundle from an earlier version or findings imported from elsewhere, and its open findings are not in any control row. `baseline_alignment.frameworks.cyber_essentials` is the exception: it lists every requirement in the catalog (Cyber Essentials Requirements for IT Infrastructure v3.3), not only the mapped ones, and each row adds `theme`, `requirement_status` (`automated`, `partial`, `manual`, `ce_plus_assessor_test`, or `provider_responsibility`), `citation`, `evidence_limits`, an `evidence` count object (including `rules_supporting`), a per-rule `confidence` (`full`, `partial` or `supporting`; a `supporting` rule is listed with its status but never decides the row), a row-level `confidence` for a failing row (`full` when a failing rule tests the condition the requirement names for the audited tenant, otherwise `partial`), and `ce_plus_test` where one applies. A row whose deciding rules were not all evaluated is `not_assessed` with `reason` `rules_not_evaluated` and `not_assessed_reasons` (the per-rule reasons); a row mapped only to supporting rules has `reason` `supporting_evidence_only`. A Google Workspace bundle lists only Google rules (a Microsoft rule on a Google tenant reads for a collector the run never had), and a Google rule that ran clean appears as evaluated; a Microsoft 365 bundle lists only Microsoft rules. Its `status` keeps the four values above, but a `manual`, `ce_plus_assessor_test` or `provider_responsibility` row is always `not_assessed` with `reason` `requirement_status:<status>`, and it is never `pass`. A `partial` row can be `fail` or `accepted_risk`; when its mapped rules are all evaluated and clean it is `not_assessed` with `reason` `partial_requirement_no_gap_found`, never `pass`. Only an `automated` row can be `pass`, and v3.3 has none. The section also carries `requirement_status_counts`, `uncatalogued_requirement_ids`, `document_url`, `effective_date` and a `disclaimer` that the output is assessor evidence, not a certification. `baseline_alignment.schema_version` is `2026-10-20` for this shape. `baseline_alignment.secure_score` reconciles the latest Microsoft Secure Score snapshot with Auditex findings: `overall` (score, maximum, percentage) and one row per mapped control profile with Microsoft's score and maximum, `microsoft_state`, `auditex_state`, and `agreement` (`agrees`, `auditex_only`, `microsoft_only`, or `no_microsoft_data`). `normalized/security_score_control_profiles.json` holds the control profile ids, titles, and maximum scores used for that table.

### Evidence references and traceability

A reference `{artifact_path, artifact_kind, collector, record_key, ...}` resolves when all of these hold:

- `artifact_path` is relative and names a regular file inside the run directory. A path with a `..` segment, an absolute path, and a symlink that leaves the run directory are refused (`artifact_outside_run_dir`); a path that names no file is `artifact_missing`; a `.json` file that does not parse is `artifact_unreadable`; any other file type cannot be addressed by record (`artifact_not_addressable`).
- If `json_pointer` is present, the RFC 6901 pointer exists in the artifact (`json_pointer_not_found` otherwise). A pointer that is stated must exist; it takes precedence over `record_key`.
- Otherwise `record_key` names a record in the artifact (`record_not_found` otherwise). A normalized section is addressed through its `records` list, a list artifact (for example `blockers/blockers.json`) through its rows, and a JSONL artifact through its lines (`jsonl_line` is 1-based, `jsonl_line_not_found` when it is out of range or not JSON). A record is named by its `key` or `id`, or, as `index/evidence.sqlite` names it, `<section>:<value>` for its `id`, `display_name`, `name`, `collector` or `surface` (and `<section>:<index>` when it has none). A bare `display_name` or `name` does not name a record.

Finalization seals every finding's references once the artifacts they cite are written and before the report pack is built. Each reference gains `resolved` (boolean), `unresolved_reason` (only when `resolved` is false), `content_hash` (the SHA-256, lowercase hex, of the artifact's bytes) and `collected_at` (the record's own `collected_at` or `observed_at` when it has one, otherwise the run manifest's `created_utc`; a value the builder set is kept). `content_hash` is the artifact as a whole, so it changes when any record in that file changes; it is not a per-record hash. The validator does not trust these markers: it resolves every reference again and compares `content_hash` with the artifact as it is now. Each artifact is read once for the findings, the proof table and the report sections together.

| Code | Severity | Raised when |
| --- | --- | --- |
| `broken_evidence_ref` | error | The artifact is missing, unreadable or outside the run directory; `details.reason` says which. |
| `unresolved_evidence_ref` | error | The artifact is usable but the record, JSON pointer or line is not in it. `details` has `finding_id`, `ref_index`, `artifact_path`, `reason` and the reference's `record_key` or `json_pointer`. |
| `evidence_ref_hash_mismatch` | error | A finding reference's `content_hash`, or a proof row's, no longer matches the artifact. |
| `legacy_unresolved_ref` | error | As `unresolved_evidence_ref` (and its proof-table and report-section forms), for a bundle finalized under an earlier contract version. See below. |
| `broken_report_proof_table_ref`, `unresolved_report_proof_table_ref` | error | A `supported` proof row's reference does not resolve (missing artifact, or missing record). |
| `unresolved_report_evidence_ref` | error | An attack-path hop, a detection signal or a public-footprint domain cites a record that does not resolve; `details.location` names it. |

A bundle is *legacy* when `run-manifest.json`'s `schema_contract_version` is earlier than `2026-10-22`, the version from which every reference must resolve (or absent). The cut-off is that fixed version (`REFS_MUST_RESOLVE_SINCE`), not the current `CONTRACT_VERSION`, so a later contract bump does not turn an edited `2026-10-22` citation into a legacy one. Such a bundle was written when references did not have to resolve, so a citation in it that names a missing record or pointer (for example `raw/app_consent.json` at `/servicePrincipalFanout`, a derived fan-out that has no row in the raw payload) is the old builders' pattern, not a sign of editing. Validation reports it as `legacy_unresolved_ref` instead of `unresolved_evidence_ref`, with the same `details`. It is still an error: the bundle does not validate, the gate still fails closed, and handoff and the customer pack still refuse it. The label is what lets handoff, the explorer and the gate say "legacy citations" rather than imply tampering, which the hash manifest and `evidence_ref_hash_mismatch` report. A missing or unreadable artifact is `broken_evidence_ref` whatever the bundle's age.

What follows from the markers:

- A proof row's `proof_status` is `supported` when its reference resolved and `unsupported` when it did not; a finding with no reference is `missing_evidence`. A reference nobody has checked (a bundle that predates the markers) keeps `supported`; the validator resolves it independently.
- A finding's `confidence` is `high` when every reference resolved, `medium` when some did and `low` when none did or it cites nothing. A value a finding builder supplied is replaced.
- `report_qa.unsupported_claims` lists every finding with no resolved reference, so a finding that cites only records that do not exist fails report QA. `reviewer_index.prove_this[].proof_status` is `partially_supported` when some of a finding's proof rows are supported and some are not.

What the finding builders cite, so that every reference resolves in a bundle the run wrote:

- A finding about one principal cites that principal's records: the Global Administrator finding cites the `role_assignments` record of the assignment and, where the evidence is the account state or an MFA registration, the `users` or `auth_method_registration_objects` record. A finding about a set cites up to 25 of its records; the finding itself carries the full count.
- A finding that rests on a read that returned nothing or only counts cites that read's `normalization_coverage` record (`normalization:<source>`), as `identity_governance.standing_privilege_only` does. `intune_depth.policies_without_assignments` cites the policy read the same way, and the empty assignments from `normalized/intune_policy_assignment_objects.json`: one row per policy the assignment read returned, each with `assignment_count`. It does not cite the assignment read's coverage row, whose `record_count` counts those per-policy rows (two for two policies) and so reads as if there were assignments.
- A collector issue cites the row of `blockers/blockers.json` it was built from (the collector-failure rows in `diagnostics.json` and `blockers/blockers.json` no longer carry their own `evidence_refs`; the incomplete-evidence rows from normalization still do), with `json_pointer` `/<row index>`, `endpoint`, `response_status` and `query_params`. A raw payload holds no row for a derived fan-out and a crashed collector writes none, so raw payloads are no longer cited for collector issues.
- A finding built with no citation of its own, and a Google Workspace collector issue, cite the collector's `normalized/coverage_ledger.json` record `coverage_ledger:<collector>`; the first is marked `evidence_ref_generated: true` because the reference is a stand-in, not a citation. Response-plane blockers cite their row of `blockers/blockers.json` by `json_pointer`.

### Bundle hash manifest

`bundle-hashes.json` is the last file finalization writes (schema: `schemas/bundle_hashes.schema.json`). It holds `schema_version`, `algorithm` (`sha256`), `run_id`, `created_utc` (the run manifest's), `artifact_count`, `artifacts` (`path`, `sha256`, `bytes` for every non-excluded file under the run directory, sorted by path) and `excluded`. The append-only logs (`audit-log.jsonl`, `audit-command-log.jsonl`, `audit-debug.log`) and operating-system metadata change after finalization by design, so they are named under `excluded` with a `reason` and not hashed. The manifest does not hash itself. `index/evidence.sqlite` is closed before it is hashed, so the file holds the whole index and not a stub with the data in a `-wal` sidecar, and no sidecar exists to hash. A SQLite sidecar (`index/evidence.sqlite-wal`, `-shm`, `-journal`) that turns up afterwards is an unlisted file the check refuses (`unexpected`, below): SQLite would replay a `-wal` file over the hashed index, so it could change what every consumer reads while the hashed file stays as it was. The `sqlite_sidecar` value of `excluded[].reason` is no longer written; older manifests may carry it. Its path is fixed; `run-manifest.json` lists it under `artifacts`.

Exactly six `operator-inputs/` paths, the private lists `operator-inputs/sensitive-users.txt` and `operator-inputs/partner-domains.txt`, their separate keys `operator-inputs/sensitive-users.key` and `operator-inputs/partner-domains.key`, the run's pseudonym key `operator-inputs/pseudonym.key` and the local `operator-inputs/.gitignore`, together with a private writer's leftover temporary of one of them (such as `.pseudonym.key.<24 hex>.tmp`), appear only in `excluded` with reason `redacted_operator_input`, without `sha256` or `bytes`; any other file under that directory is hashed at finalisation or reported as unlisted afterwards. This also applies to the customer pack copy of the hash manifest.

Consumers read the index read-only (`azure_tenant_audit.evidence_db.open_index_read_only`: SQLite `mode=ro&immutable=1`, which writes nothing, creates no sidecar, opens on read-only media and ignores a `-wal` file). When `bundle-hashes.json` lists the index and a sidecar stands beside it, `load_run_index_summary` returns nothing (callers fall back to the manifest) and the read-only validation copies the hashed file alone. An index no hash manifest covers (a bundle from before it existed) is still read with its sidecar, because its data may still sit there.

The check recomputes every listed hash and reports `status`:

| Status | Meaning |
| --- | --- |
| `verified` | Every listed file matches, no symbolic link sits in the run, no unlisted SQLite sidecar sits beside the evidence index, and no unlisted file sits at a path the product reads. Files added later that are named post-finalization outputs (`reports/explorer.html`, `reports/rendered-report.<json\|md\|csv\|html\|sarif.json\|oscal.json>`, `reports/{api-calls,permissions,proof-table,handoff}.{json,md}`) and unlisted files elsewhere (for example under `raw/`) are listed as `unlisted` and do not fail the check. |
| `mismatch` | A listed file changed (`modified`: `path`, `expected`, `actual`) or is gone (`missing`). A manifest row that leaves the run directory counts as missing. A symbolic link, to a file or a directory, sits anywhere in the run (`symlinks`; a link is never hashed or followed, and this holds for a bundle with no hash manifest too). A file the manifest does not list sits at a path the product reads (`unexpected`: the run root, `normalized/`, `findings/`, `blockers/`, `reports/`, `ai_safe/`) and is not one of the named outputs above, or an unlisted `index/evidence.sqlite-wal`, `-shm` or `-journal` sits beside the evidence index. |
| `invalid` | `bundle-hashes.json` cannot be read as a hash manifest (not JSON, no `artifacts` rows, or an algorithm other than `sha256`), or the file is gone although `run-manifest.json` lists it under `artifacts` (finalization registers it there before it writes it, so deleting the file cannot turn the check into `absent`), or the file is gone from a bundle whose `run-manifest.json` says it was finalized under contract `2026-10-22` or later (`schema_contract_version`), which writes it. The last two have `manifest_missing: true` and `manifest_missing_reason` (`listed_in_run_manifest`, `required_by_contract`); the message says the file is missing. `manifest_sha256` is set whenever the file exists. |
| `absent` | The bundle was finalized under a contract older than `2026-10-22`, before the manifest existed (`run-manifest.json` does not list it and its `schema_contract_version` is older or absent); it cannot be checked. |

Who checks, and what happens:

- `auditex report handoff` (and the MCP handoff tool) adds an `integrity` block (`status`, `summary`, counts, `modified_paths`, `missing_paths`, `unlisted_paths`, `manifest_sha256`) and recomputes validation, reported as `contract.recomputed` (`valid`, the issue counts and `issue_codes`, `matches_validation_json`, which is false when `validation.json` records a different verdict than the bundle gives now, and `legacy_unresolved_ref_count` and `only_legacy_unresolved_refs`). `handoff_status` is `unusable` when the integrity status is `mismatch` or `invalid` (a bundle that should have a manifest and has none reads `invalid`, with `integrity.manifest_missing` true and a summary that says `bundle-hashes.json is missing`, not that the run predates it), when the recomputed validation fails, when `validation.json` itself says invalid, or on a safety failure; `status_reasons` lists which (`bundle_integrity_mismatch`, `bundle_integrity_invalid`, `recomputed_validation_failed`, `legacy_unresolved_refs`, `validation_invalid`, `not_read_only`, `content_reads`, `write_actions`). `contract.valid` stays the verdict `validation.json` recorded. The bundle is still described, not refused: `handoff` always returns the payload, with a `bundle_integrity` or `contract_validation` limitation. When every recomputed error is a `legacy_unresolved_ref` the reason is `legacy_unresolved_refs` and the summary says it is a legacy bundle, not a sign of editing.
- `auditex report explorer` recomputes validation for `contract_valid` and adds `integrity` to the run payload. It shows a banner for a `mismatch` or `invalid` hash check ("Bundle changed since it was finalized"), for a failed recomputed validation ("Bundle does not validate"), and, when every error is a legacy citation, "Legacy evidence references do not resolve". The page is still written.
- `auditex report customer-pack` refuses a bundle whose hash check is `mismatch` or `invalid` (a current-contract bundle stripped of its manifest included), and one whose recomputed validation fails whatever `validation.json` says: it raises `BundleIntegrityError`, the command exits with status 2 and no output directory is created. `absent` (a bundle finalized before the manifest existed) does not refuse, and the pack records it. The pack's `pack-manifest.json` carries `source.integrity`, its `README.md` states the status, `source-artifacts/bundle-hashes.json` is a copy of the manifest, and `verify-pack` checks that `source.integrity` still equals the `integrity` in `handoff.json`.
- `auditex gate` and `gate-drift` recompute validation and verify the hash manifest, and fail closed (exit status 2). `contract_invalid` covers a failed validation (when the errors include `legacy_unresolved_ref` the message and `contract.legacy_unresolved_ref_count` say so). `bundle_integrity_mismatch` and `bundle_integrity_invalid` block a run whose artifacts no longer match `bundle-hashes.json` (a symbolic link or an unexpected file included), with `integrity.modified` and `integrity.missing` naming up to ten paths; `bundle_integrity_absent` blocks a bundle finalized under contract `2026-10-22` or later that has no manifest (the integrity status is `invalid`, `manifest_missing_reason` `required_by_contract`), while an older bundle without one passes with a warning that its artifacts could not be checked. Files added after finalization that the manifest does not list are a warning. A run whose collectors completed but whose manifest names section-scoped gaps (`coverage_gaps[].section_gaps`, below) passes with a warning that lists them, and `coverage.section_gaps` in the result carries the same records; the rules that read those sections are `not_assessed`. The gate result carries `contract.integrity` (`status`, `checked_count`, `unlisted_count`, `manifest_sha256`). The contract version that decides `bundle_integrity_absent` is read from `run-manifest.json` inside the bundle, so it stops a bundle that merely lost its manifest and not one that was rewritten to look older; `--expect-manifest-sha256` (see "Expected manifest digest") stops that too: `gate` and `gate-drift` check it first and block with `expected_manifest_sha256_mismatch` when `bundle-hashes.json` has another digest or is missing, and with `expected_manifest_sha256_invalid` for a value that is not a SHA-256. `findings_inconsistent` also covers a finding whose `status`, `severity` or `rule_id` differs between `findings/findings.json` and the report pack (`disagreeing_findings` names up to ten ids), not only a different set of ids. The gates count the report pack's rows, so an edit to its statuses is caught by the hash manifest first and by this comparison for an editor who re-hashed.
- `auditex compare` does not recompute validation, but it verifies each run's hash manifest and recorded contract (`verification.integrity`, `verification.problem`: `bundle_integrity_mismatch`, `bundle_integrity_invalid` or `contract_invalid`). A pair with a failing run is `blocked` with reason `run_unverified:<baseline|current>:<problem>`, and a finding delta calls no finding resolved when either run fails (`not_reassessed` reason `run_unverified:...`). A bundle finalized before the hash manifest existed reads `absent`, which is unverified and not a problem; one finalized under `2026-10-22` or later that has none reads `invalid`. `--expect-manifest-sha256 <run-dir>=<digest>` (repeatable; see "Expected manifest digest") adds the problem `expected_manifest_sha256_mismatch`, and `verification` gains `expected_manifest_sha256` and `expected_manifest_sha256_matched`. The markdown header prints `Run verification`.
- Handoff `integrity` also carries `symlink_count`, `unexpected_count`, `symlink_paths` and `unexpected_paths`, and the `bundle_integrity` limitation lists them. A run with files the manifest does not list outside the product's read paths gets a limitation `{surface: bundle_integrity, status: unlisted_files, paths}` (not unusable); named outputs such as the explorer page do not raise it. They get their own limitation, `{surface: bundle_integrity, status: unhashed_outputs, paths}`: reports written into the run after it was finalized (`reports/explorer.html`, `reports/rendered-report.*`, `reports/{api-calls,permissions,proof-table,handoff}.{json,md}`) are readable by an assessor but not hashed, so nothing proves they match the run's evidence, and they are never copied into a customer pack. They are not added to `bundle-hashes.json`: that would change the manifest's digest after it was handed over and break every digest sent separately. The handoff is `ready_with_limitations` while such a file is there; regenerate the report from the run before relying on it. Handoff `safety` gains `observation_basis` (`transport_audit_log`, `offline_replay` or `coverage_ledger_only`), `replay_source` (the file an offline replay was replayed from, otherwise null) and `observed_log_complete`; `counts` keeps `api_calls` (the declared rows) and gains `declared_calls` (the same number), `observed_graph_requests`, `observed_commands` and `observed_outside_declared` (null when the bundle has no transport ledger). The `scope_risk` limitation gains `observation_basis` and never says Auditex "stayed read-only": with a transport ledger it says the audit log recorded no write, refused or content-reading Graph request or tenant command (the DNS, exposure and Power Platform lookups are outside the ledger); without one it says read-only behaviour was not observed for the run.
- `customer-pack` refuses a bundle with a symbolic link or an unexpected file exactly as it refuses `mismatch` (`BundleIntegrityError`, exit status 2), and a non-empty `--output-dir` that holds no earlier pack (`PackOutputError`, exit status 2); a directory that already holds a pack (`pack-manifest.json` of kind `auditex_enterprise_handoff_pack`) is reused and its `source-artifacts/` removed first. A source artifact is copied only when it is a regular file reached without a link and, when the run has `bundle-hashes.json`, listed in it; a refused row has `present: false` and a `skipped_reason` (`symbolic_link`, `not_in_bundle_hashes`). Every source artifact is copied byte for byte except `run-manifest.json`, which records where the operator ran the audit: its copy has `run_dir` set to the run folder name, paths below the run made run-relative, and `waiver_path` and absolute paths in `command_line` reduced to `<local-path>/<file name>`. Its row in `pack-manifest.json` then has `transformed: "pack_relative_paths"` and `source_sha256`, the SHA-256 of the run's own `run-manifest.json` (the value `bundle-hashes.json` lists), next to `sha256`, the digest of the copy. The pack manifest has `schema_version` `2026-10-22` and `path_style: pack_relative`: `run_dir` is the run folder name, `output_dir` is `.`, and every path in `generated_files` and `source_artifacts` is relative to the pack. `handoff.json`, `api-calls.json`, `permissions.json`, `proof-table.json`, `report.md` and the Markdown files carry no absolute path of the operator's machine (paths below the run are run-relative, `review_commands` use `<run-dir>`). Packs written by earlier versions still verify, including after being moved. The command's printed result adds `pack_dir`.
- `auditex report verify-pack` loads `source-artifacts/bundle-hashes.json` from the pack. Whenever the pack carries it, whatever `source.integrity.status` the (editable) pack manifest and `handoff.json` claim, it requires the file's SHA-256 to equal `source.integrity.manifest_sha256` and every file under `source-artifacts/` that the pack manifest lists to match the hash the run was finalized with, found by where the file sits and not by the row that names it (`bundle_hashes_digest_mismatch`, `source_artifact_bundle_hash_mismatch`, `source_artifact_not_in_bundle_hashes`, `invalid_bundle_hashes`). A pack that carries the file but claims a status other than `verified` is `source_integrity_status_inconsistent`. A pack with no copy is `missing_bundle_hashes` when it claims `verified` or when its copy of `run-manifest.json` says the run was finalized under `2026-10-22` or later; a legacy pack with no copy (`absent`) still verifies. The one copy that is not byte for byte, `run-manifest.json`, passes when its row has `transformed: "pack_relative_paths"` and a `source_sha256` equal to the hash listed for it; the copy itself is then bound only by `checksums.sha256` (`--expect-checksums-sha256`), and the result lists it under `transformed_source_artifacts`. It reports any file the pack does not list as `unexpected_file` (symbolic links included). `--expect-manifest-sha256` (the value the handoff reports as `integrity.manifest_sha256`) and `--expect-checksums-sha256` take values received separately (`expected_manifest_sha256_mismatch`, `expected_checksums_sha256_mismatch`). The result gains `digests` (`bundle_hashes_sha256`, `checksums_sha256`, `pack_manifest_sha256`), `source_integrity_status` and `transformed_source_artifacts`; the MCP tool `auditex_verify_customer_pack` takes the same two optional arguments.
- `api-calls.md` and the `API Calls` section of `report.md` label the declared rows "Declared calls", state `Read-only` and `No content reads` with their basis (`observed in the transport audit log`, `replayed from <file>, no tenant contact` or `declared, not observed`) and an `Observation basis` line, and add `Observed calls (transport ledger)`: the basis, audit-log completeness, Graph requests attempted (batch requests, inner calls, unverified batches), methods seen, commands executed, refused calls and calls outside the declared set, with tables of requests (method, endpoint, version, count, statuses), commands (adapter, command text, count, statuses, read-only), refused calls and calls outside the declared set. A bundle with no `observed_ledger`, or a provider that is not instrumented (Google Workspace), says the call list is declared, not observed. An offline replay never claims transport observation: it has no tenant traffic, so its flags read `replayed from <sample file>, no tenant contact` (the file is `run-manifest.json`'s `replay_source.file`; a replay with no recorded file says `an offline sample file`), the observation basis is `offline_replay`, the ledger section says no transport ledger applies and the observed-call lines say none (the scope-risk limitation says nothing was observed about calls to a tenant). `api-inventory.json` of a replay carries `safety.observation_basis` `offline_replay`, `safety.replay_source` and `observed_ledger.basis` `offline_replay` (with `observed_ledger.replay`); reports derive the same wording for an older replay bundle that recorded `transport_audit_log`, from `mode` `offline` in the run manifest.
- `data-handling.json`: `auth_scope_summary.content_capable` lists scopes the scope catalog marks content-capable (Drive readonly), and `scope_risk` is `content_capable_scope_present` when there is no write-capable scope.

The manifest detects edits made after finalization to a bundle you hold. It is not signed, so it does not authenticate who produced the bundle, and anyone who can rewrite the bundle can rewrite the manifest too; send its SHA-256 (`integrity.manifest_sha256`) through a separate channel when origin matters.

#### Expected manifest digest

A bundle that someone rewrote together with its `bundle-hashes.json` passes the hash check, and the contract version that tells a current bundle from a legacy one is read from the same bundle, so a manifest that was removed and a version that was lowered make a current bundle look like one from before the manifest existed. The SHA-256 of `bundle-hashes.json` taken when the run was written, and kept somewhere the bundle's writer cannot reach, settles both. `verify-pack`, `gate`, `gate-drift` and `compare` take it as `--expect-manifest-sha256`:

```bash
shasum -a 256 <run-dir>/bundle-hashes.json            # when the run is written, in the trusted pipeline step
auditex gate <run-dir> --fail-on high --expect-manifest-sha256 <digest>
auditex gate-drift --baseline <old-run> --current <new-run> --fail-on high \
  --expect-manifest-sha256 <old-run>=<digest> --expect-manifest-sha256 <new-run>=<digest>
auditex compare --run-dir <old-run> --run-dir <new-run> \
  --expect-manifest-sha256 <old-run>=<digest> --expect-manifest-sha256 <new-run>=<digest>
auditex report verify-pack <pack-dir> --expect-manifest-sha256 <digest>
```

`gate` also takes a bare digest. For `gate-drift` and `compare` each value is `<run-dir>=<digest>`; a run that is not named is not checked, and a value that names no run of the command, repeats a run with another digest or is not 64 hexadecimal characters is a usage error (exit status 2), never a check that quietly does not run. The check comes first: a run whose `bundle-hashes.json` has another digest, or none, is blocked (`expected_manifest_sha256_mismatch`; `compare` reads `run_unverified:<side>:expected_manifest_sha256_mismatch` and calls no finding resolved) whatever its other contents say. When it matches, the gate result's `contract.integrity` carries `expected_manifest_sha256` and `expected_manifest_sha256_matched: true`. The digest covers the manifest and so every artifact it lists; it does not cover files the manifest does not list (the named post-finalization outputs), and it proves nothing about who wrote the run before the digest was taken. The MCP compare tool does not take it yet.

### Finding status

The engine writes two finding statuses: `open`, and `accepted_risk` together with the waiver that matched (`waiver`, `waiver_applied`). A *matching waiver* names the finding or its rule (`finding_id` or `rule_id`) and every match field it populates equals the finding's, the test `apply_waivers` ran. Validation raises `unwaived_accepted_status` (error) for a finding whose status is `accepted_risk`, `accepted` or `waived` with no matching waiver, and `unknown_finding_status` (warning, `details.status` and the finding ids) for any other status, `closed` and `resolved` included. The gates read the status the same way: an accepted or closed status counts only when a matching waiver stands behind it, and any other finding is open (`unbacked_status_count` and a warning say how many claimed more). `accepted` and `waived` stay accepted spellings; `closed` and `resolved` are honoured only with a waiver. A waiver that has passed its `expires_on` date accepts nothing, whichever status value claims it: a finding whose `accepted_risk`, `accepted`, `waived`, `closed` or `resolved` status rests on an expired waiver counts as open in `gate` and `gate-drift` (`counts_by_severity`, never `accepted_count` or `closed_count`; `expired_waiver_status_count` and a warning say how many). At or above the threshold it fails, with `reason` `stale_accepted_risk` for an accepted status and `expired_waiver` for a closed one, and is counted in `stale_accepted_risk_count_at_or_above_threshold`; `gate-drift` lists it once, under `stale_accepted_risks_at_or_above_threshold` (not also as new or reactivated). A waiver with no `expires_on` never expires.

### Rule parameters and reassessment

`run-manifest.json` records the windows the run's rules were judged with under `rule_parameters`: `stale_sync_days` (Intune check-in, `--stale-sync-days`, `AUDITEX_STALE_SYNC_DAYS`, default 14), `stale_guest_days` (`AUDITEX_STALE_GUEST_DAYS`, default 90) and `stale_account_days` (90) on Microsoft 365, and `stale_user_days` and `stale_device_days` (`--stale-user-days`, `--stale-device-days`, default 90) on Google Workspace, each with a `schema_version`. A larger number is a laxer window. A finding that is gone from a later run is `resolved` by `compare` and `gate-drift` only when the later run used the same or a smaller window; otherwise it is `not_reassessed` with `rule_parameters_laxer:<name>`, or `rule_parameters_unrecorded:<name>` when either run did not record the window (a bundle from before it was recorded).

On Microsoft 365 `rule_parameters` also records `break_glass_accounts`: the emergency-access list the verdicts exempted (`--break-glass-accounts`, else `AUDITEX_BREAK_GLASS_ACCOUNTS`), de-duplicated and sorted, `[]` when none was given. It is a rule input, not a window: the Conditional Access rules (`ca.mfa_not_enforced`, `ca.admin_mfa_not_enforced`, `ca.legacy_auth_not_blocked`, `ca.break_glass_exclusion_missing` and the rest of the `ca.*` rules) judge the policies with those principals exempted, so they judge the same policies as enforced once a staff group is listed, and their findings vanish without anything having been fixed. A vanished finding of a `ca.*` rule is `resolved` only when both runs recorded the same list (compared case-insensitively, ignoring order); otherwise it is `not_reassessed` with `rule_parameters_changed:break_glass_accounts`, or `rule_parameters_unrecorded:break_glass_accounts` when either run did not record it. `rule_parameters.changed` lists the two lists and the gate-drift warning names the change. A list is an operator input that the run's `normalized/break_glass_assessment.json` already resolves to account names, so recording it adds no new disclosure. The gate-drift result carries `rule_parameters` (`baseline`, `current`, `changed`) and a warning when they differ; the gate result carries the run's `rule_parameters`.

Google Workspace rules are reassessed against their inputs as Microsoft 365 rules are: a vanished `*_2sv_*` finding needs `google_directory` and `google_policies` complete in the later run and a `two_step_policy_status` that is not `unknown` (`rule_collector_<status>:<collector>`, `rule_inputs:two_step_policy_unknown`, `rule_inputs:two_step_policy_not_collected`); a vanished external-principal finding (`google.group_external_member`, the `google.gmail_external_*` and filter rules, `google.drive_external_permission`, `google.drive_domain_permission`, `google.calendar_external_acl`, `google.calendar_domain_acl`) needs `google_directory` complete and an `internal_domains_status` that is not `unknown` (`rule_inputs:internal_domains_unknown`).

### Rules that need the whole input (review v3)

A rule reads `not_assessed` with a reason, never `pass`, when an input it judges is missing:

- `registration_report_incomplete:<n>` (`identity.user_mfa_not_registered`, `identity.privileged_mfa_not_registered`, `identity.global_admin_mfa_not_registered`, `attack_path.no_mfa_to_tier0`): the registration rules read only the rows the registration report returned, so an enabled member user or a counted administrator with no row (or a row without an `isMfaRegistered` answer) was never judged. `<n>` counts them from `normalized/users.json` and `normalized/effective_admin_set.json`: every enabled member user and counted administrator for the user rule and the attack path, the counted administrators who are not Global Administrators for the privileged rule, the Global Administrators for the Global Administrator rule. An empty report, in a live run or an offline replay (`auth_methods` as `{}`, `null` or `[]` also makes the collector `partial` with `section_absent` rows), no longer passes CIS `5.2.3.4`, the Cyber Essentials MFA requirements, MCSB IM-6 and PA-1 or Zero Trust identities.
- `collector_not_complete:<collectors>` for the attack-path rules `attack_path.app_owner_to_tier0` and `attack_path.privilege_escalation`: the graph is built from `identity`, `app_consent` (ownership and grants), `directory_relationships` (group and application owners) and `identity_governance` (PIM-eligible assignments; a skipped, `not_applicable` one is tolerated). `app_consent` is partial in any tenant with more than 10 principals to expand, so these rules read `not_assessed` there unless a path was found.
- `tenant_domains_unknown` (`sharepoint.external_principal`): an external principal is one outside the tenant's verified domains, which `domains_hybrid` reads. The rule is gated on `domains_hybrid` and needs a verified domain record in `normalized/domain_hybrid_objects.json`; the run's tenant name is added to the domain list only next to one that was read. `auditex compare` and `gate-drift` do not call a finding resolved when the later run's domain read failed (`rule_collector_<status>:domains_hybrid`, `rule_inputs:tenant_domains_unknown`).
- `risk_detail_hidden` (`security.risky_signin`): every sampled sign-in has a `hidden` risk level (no Microsoft Entra ID P2), so the rule, which skips a sign-in that reports no risk, judged nothing.
- `malware_filter_settings_not_returned`, `casMailboxSmtpAuth_not_read_in_full`, `mailbox_smtp_auth_count_not_returned` (`exchange.*`, see the table above).

### Resumed runs and offline replay

`--resume-from` carries earlier collectors forward with the status they finished with and never reads an incomplete one as complete. A collector the checkpoint holds as `ok`, with its raw payload still on disk, is not run again and keeps `ok` (message `Resumed from checkpoint (ok)`); a collector the checkpoint holds as `skipped` because the tenant cannot have the data keeps `skipped` and reads `not_applicable`. A `partial` or `failed` collector, a collector the preflight skipped as blocked (checkpoint `error_class` `preflight_blocked`) and an `ok` collector whose raw payload is gone are run again, and the new observation replaces the earlier summary and coverage rows of that collector. Every collector that finished in an earlier session is part of the resumed run whether or not this session selects it: it is carried, added to `selected_collectors`, normalized and judged with the rest, so the report, `findings/findings.json`, the blockers and the normalized sections describe the whole run folder and not only what was selected (a resume with `--collectors licensing` after a run of four collectors still reports on all four). A checkpointed collector that is not part of the resumed session and was not carried (it did not finish, was skipped by the preflight, lost its raw payload or was read over another time window) keeps the run `partial` (event `run.resume.incomplete`). A resumed run rewrites `diagnostics.json`, `blockers/blockers.json` and `findings/findings.json` from what the whole run now holds and removes each (and its manifest fields) when nothing is left to report, as a fresh run that has none never writes them, so a collector that succeeds on resume no longer leaves the blocker an earlier session wrote; it removes `normalized/<section>.json` files the resumed run no longer produces. The writer seeds its coverage from `coverage.json` and from `index/coverage.jsonl` (the newest row of an endpoint wins), so a session that was interrupted before finalization keeps its collectors' coverage rows, and a carried collector with no summary row is added to `summary.json`. A collector checkpoint records the `since` and `until` it was read over; a time-windowed collector (`security`, `defender`) whose recorded window differs from the resumed session's is run again (a checkpoint with no recorded window is accepted only by a session with no window of its own). The event `run.resume` lists `completed_collectors` and `rerun_collectors`; a carried collector logs `collector.resumed`.

`exchange_policy` and `dns_posture` are non-fatal default workload collectors.
A failed or partial read keeps its actual status, diagnostics,
coverage gap and customer reason; policies depending on unavailable evidence stay
`not_assessed`. When these are the only incomplete collectors, the overall run
status remains `partial`, but collection exits **0**, in live collection and offline
replay. One stderr line names the incomplete non-fatal collectors, says the run is
partial and directs the operator to diagnostics; the same line is in `summary.md`
and `summary.json` as `partial_workload_notice`. It includes no tenant data or error
text. Failures of required collectors and their authentication retain their
existing non-zero exits. No `ok_with_gaps` status is introduced. Coverage gates
continue to reject partial runs unless `--allow-partial` is supplied.

`--offline` replay (and `auditex demo`, the MCP `auditex_run_offline_validation` tool and `make contract-smoke`) honours the markers a sample section carries. A section with an `error` or `error_class`, or one flagged `collection_truncated` (or, in an older sample, `collection_limit_reached`), becomes a coverage row (`type` `offline_sample`: `status`, `error_class`, `error`, `item_count`, `collection_truncated`, `truncation_reason`, `result_limit`) written to `coverage.json`, and its collector is `partial`: the ledger reads `partial_success` (or `blocked_permission` for a permission error), the blocker is raised as in a live run, the manifest gaps and `normalized/collection_gaps.json` name the cut list, the run is `partial` (exit status 1, except for the non-fatal workload collectors above) and the rules that read the collector are `not_assessed`. A section with no marker needs no row and the collector stays `ok` and `complete_offline_sample`. A collector the sample holds but that holds nothing (`{}`, `null`, a list) delivered none of its sections: every section its live run records (`query_plan` in `configs/collector-definitions.json`; the Google Workspace sections in `auditex.google_workspace.collectors.COLLECTOR_SECTIONS`) is written as a failed row with `error_class` `section_absent`, the collector is `partial` and the replay exits 1, with the same non-fatal workload exception. A collector that holds any key is not second-guessed section by section: minimal fixtures omit sections on purpose and the plan is not a schema (a flat `{"value": [...]}` sample is such a delivery). A domain posture record that carries a `resolver_error` is written as a failed `posture:<domain>` row with `error_class` `dns_resolver_error`, as a live run does. The Google Workspace replay does the same, and its capability rows read `offline_sample`, so a clean replay is `complete_offline_sample` in the ledger, never `complete_exact_scope`. A replay records what it was replayed from in `run-manifest.json` as `replay_source` (`file`, the sample's file name and never its directory, and `sha256`), and its audit log's `run.started` event carries `mode: "offline"`; reports use both to say the evidence was replayed and that no tenant was contacted (see "Bundle hash manifest"). `--as-of YYYY-MM-DD` (on `azure-tenant-audit --offline`, `auditex run --offline` and `auditex google run --offline`) judges the replay's date-derived values at 12:00 UTC on that date (from 1970-01-01 to 2999-12-31) instead of the wall clock: operating-system end of support, app credential `expiry_state` and `expiry_days_remaining`, dormant applications, stale sync, whether an update ring's quality-update pause is still in force (`intune_depth.update_ring_deferral_excessive`), stale account and guest windows, Global Administrator password age, which app credentials count as current in the `attack_graph` of `reports/report-pack.json` and, on Google Workspace, ChromeOS auto-update expiry, stale user, administrator and device windows and 2-step verification enforcement dates. Without it the wall clock is used as before; a live run, a malformed date and a date outside that window are refused with exit status 2 before any run folder is written. The date adds no field to the bundle. Waiver expiry still reads the wall clock, so an old date cannot bring an expired waiver back into force. `make contract-smoke` passes one fixed date on every replay, so its recorded digests do not depend on the day it runs.

### SARIF and OSCAL exports

`auditex report render --format sarif` writes SARIF 2.1.0 and `--format oscal` writes OSCAL 1.1.2 Assessment Results. The tests validate both against the official JSON Schemas (vendored under `tests/schemas/`, so a test run needs no network).

The OSCAL shape changed with contract `2026-10-22`, because the earlier export did not validate against the schema (a finding had no `target`, and `target-ids`, `remediation` and `uuid-ref` are not OSCAL properties). Consumers of the earlier export must change:

- Each Auditex finding is one OSCAL `observation` (`methods: ["EXAMINE"]`, `collected`, `subjects` of `{subject-uuid, type: "inventory-item", title}`, and `relevant-evidence` rows `{href, description, props}` with the artifact path as `href` plus `#<json_pointer>` when there is one, and the `record-key`, `sha256` and `resolved` properties of the reference) and one OSCAL `finding`. The finding's `target` is `{type: "objective-id", target-id: <rule id as an OSCAL token>, status: {state: "not-satisfied", reason: "fail"}}`; the remediation text is its `remarks`. The finding's `props` carry `auditex.finding_id`, `auditex.severity` and `auditex.rule_id`, plus one `framework-control` property per mapped control, with `class` the framework key and `value` the control id; these replace `target-ids`. An empty value is never written, because the schema forbids it.
- Collection time is the run manifest's `created_utc`: the result's `start`, and its `end` (that time plus the manifest's `duration_seconds`). An observation's `collected` is the earliest `collected_at` among its own evidence references, or the run's time when it has none. Only a bundle with no usable `created_utc` falls back to the export time, and the result's `auditex.collection_time_basis` property says `export_time` instead of `run_manifest_created_utc`. `metadata.last-modified` is the export time.
- `import-ap` is `#auditex-assessment-plan`, a fragment with no assessment plan behind it: the schema requires the field, and Auditex produces results without a plan.

SARIF keeps its shape. Each result's `properties` gains `auditex.confidence` and `auditex.evidence` (the first ten references with `artifact_path`, `record_key`, `json_pointer`, `content_hash` and `resolved`).

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
are rejected. Successfully saved pages survive a later-page collection failure,
except an `incomplete_evidence` safety stop: the standard chunk writer removes
that endpoint's chunks and metadata sidecars from disk and the artifact manifest.
Custom chunk callbacks must provide `discard(chunk_files)` to support this removal;
without it, the section is withheld but its previously written files remain.

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

Without `--top`, every list is paged to its last row, except `identity.users`,
which stops at a safety ceiling of 250,000 users. The ceiling also applies with
`--top 0` and with a `--top` above 250,000, so the user list never exceeds 250,000
rows. If a next-page link remains, it ends with an explicit `pagination_not_followed` gap. User registration details,
role assignments, Conditional Access policies, groups and applications on
Microsoft 365, and users, groups, OAuth tokens and devices on Google Workspace
are paged to the end.
`--top N` is an explicit operator limit for very large tenants, applied to every
list (`--top 0` means no operator limit; the `identity.users` ceiling still applies). A list that stops before its last row is a
coverage gap, never a silent pass:

- The list's coverage row (`coverage.json`) has `collection_truncated: true` and a
  `truncation_reason`: `operator_limit` (the `--top` limit was reached and the list
  continued), `pagination_failed` (a later page could not be read, so the rows read
  so far are a prefix), `next_link_refused` (a next-page link outside Microsoft
  Graph was not followed), `fanout_limit` (a collector's own bound on how many
  objects it expands) `input_limited` (a derived result built from a list that
  was cut) or `pagination_not_followed` (a next-page link the collector did not
  follow, from an unpaged response or at a collector safety ceiling). A limit hit sets the row `status` to `partial` with `error_class`
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
- A **section-scoped** row (`section_scoped: true`, see below) is not a truncation of its
  collector: `list_truncations` leaves it out, whatever it flags, so a cut or refused
  section-scoped read cannot make a bundle invalid while the run reads `ok`. It is a
  section gap instead (next bullet).
- A section gap is a section-scoped read that was cut, refused or skipped while its collector stayed
  `ok`. `collection_gaps.section_gap_records` groups each read's rows with their derived
  `<section>Fanout` row into one record: `collector`, `section`, `status` (`failed` when the
  read itself failed, `skipped` when every row of the section was skipped, else `partial`),
  `reason` (the truncation reason, the explicit skip reason, or `read_failed`),
  `rows_collected`, `error_classes` and `fanout_total` where known. The run states them in
  four places without making the collector or the run `partial` (exit status 0):
  `run-manifest.json` and `summary.json` carry `coverage_gaps[].section_gaps`, with
  `scope: "section"` and `status: "partial"` when every collector of the surface is `ok`
  (`surface_coverage` then reads `partial` for that surface, with `section_gap_collectors`,
  and the provider scorecard and the report pack's limitations follow); `normalized/collection_gaps.json`
  lists each as a record with `section_scoped: true`, `status` and `error_classes` (a cut
  section keeps its truncation `reason`; a refused one has `reason` `read_failed`; a skipped one
  keeps its explicit skip reason); the handoff lists the
  coverage gap among its limitations and reads `ready_with_limitations`; `auditex gate` and
  `gate-drift` warn (see "Bundle hash manifest", where the gate checks are listed). `validation.json` reports `section_gap_not_recorded` as a
  warning when a section-scoped coverage row is not named in the manifest (a bundle written
  before section gaps were recorded stays valid).

Some bounds are samples by design and are not gaps: the Entra sign-in and directory
audit logs and the Google Reports event logs and Drive file crawl keep the most
recent 500 rows (narrow them with `--since` and `--until`), the hybrid sync check
reads the first 100 users, and capability probes and preflights read a few rows to
test access. Their coverage rows carry `bounded_sample: true` and
`collection_truncated: false`. An explicit `--top` below a sample bound is still a
gap; a `--top` at or above it does not raise the bound, on Microsoft 365 or Google Workspace.

A list cut at such a bound is recorded in `normalized/bounded_samples.json` (written only when a list was cut): one record per list, key `bounded_sample:<collector>.<list>`, with `rows_collected`, `sample_limit` and, for the Entra sign-in and directory audit logs, `oldest` and `newest` (the timestamps of the rows kept). The raw section carries `bounded_sample: true` as well as the coverage row, so an offline or resumed bundle with no coverage row reads the same. The marker is set only when the list really continued past the bound. A rule whose question cannot be answered from a sample reads `not_assessed` with the reason `bounded_sample:<collector>.<list>` when no finding was raised: `security.risky_signin` (`bounded_sample:security.signIns`), `security.privilege_change_event` (`bounded_sample:security.directoryAudits`) and, on Google Workspace, `google.drive_anyone_with_link` and `google.drive_public_discoverable` (`bounded_sample:google_drive_posture.driveFiles`: the 500-file crawl; the Google normalized snapshot now writes `normalized/bounded_samples.json` too). A finding raised from the sample is real evidence and still reads `fail`; a log read whole (under the bound) can still read `pass`; `rule_inputs_gap` returns the same reason, so a vanished security finding in a later run is `not_reassessed`. `collection_gaps.SAMPLE_JUDGED_RULES` maps the rules; the hybrid sync users, the risky-user summary and the usage reports are recorded in the section but judged as samples by design.

Per-object fan-outs are not samples. Each reads only the first objects of its list and
adds a derived `partial` coverage row (`truncation_reason` `fanout_limit`, with
`fanout_total` and `fanout_limit`, `rows_collected` being the objects expanded) when more
exist, so the collector is `partial` and the rules that read it are `not_assessed`:

| Collector | Fan-out | Objects expanded | Coverage row |
| --- | --- | --- | --- |
| `sharepoint_access` | site permissions | first 10 sites | `sitePermissionsFanout` |
| `intune_depth` | device configuration assignments | first 10 policies | `deviceConfigurationAssignmentsFanout` (section-scoped) |
| `teams` | team channels | first 10 teams | `teamChannelsFanout` |
| `app_consent` | service principal owners and role grants | first 10 principals plus Microsoft Graph | `servicePrincipalFanout` |
| `identity` | members and owners of role-assignable groups | 50 groups | `privilegedGroupFanout` |
| `identity_governance` | PIM role policy rules of the directory roles | first 250 policies | `roleManagementPolicyRulesFanout` |
| `intune` | compliance policy assignments | first 100 policies | `deviceCompliancePolicyAssignmentsFanout` (section-scoped, see below) |
| `intune` | Defender antivirus state (`windowsProtectionState`) | first 100 Windows devices | `windowsProtectionStatesFanout` (section-scoped, see below) |
| `intune_depth` | update ring assignments | first 100 rings | `windowsUpdateRingAssignmentsFanout` (section-scoped) |
| `intune_depth` | quality and feature update profile assignments | first 100 profiles each | `windowsQualityUpdateProfileAssignmentsFanout`, `windowsFeatureUpdateProfileAssignmentsFanout` (section-scoped) |
| `directory_relationships` | group members and owners, application owners | 100 groups and 100 applications | `relationshipGroups`, `relationshipApplications` and the per-parent member and owner rows |

**Section-scoped fan-outs.** The Intune fan-outs marked above (compliance assignments, Defender state, update ring and update profile assignments, and the beta update profile lists) differ from the others: their coverage rows carry `section_scoped: true`, do not flag `collection_truncated`, and do not make the collector `partial`. The collector's status comes from its base reads (`managedDevices`, `deviceCompliancePolicies`, `deviceConfigurationProfiles`; for `intune_depth`, its own lists), so a fleet of more than 100 Windows devices, or one failed assignment read, does not turn every other Intune rule `not_assessed`. The gap is kept in the section (`collection_truncated`, `truncation_reason`, a `fanout` summary with `scoped_gap`), listed under `collection_gaps`, and read by the rules that depend on it (`defender_state_truncated`, `policy_assignments_not_read_for_every_policy`, `ring_assignments_not_read_for_every_ring`), which never pass on it. A failed base list still makes the collector `partial`. The per-policy assignment reads of `intune_depth` (`deviceConfigurationAssignments` and its fan-out past 10 profiles) are section-scoped too: a tenant with more than ten profiles used to read the update ring rules `not_assessed` for that alone, so `ce.sum.automatic_updates` could never be evidenced. `intune_depth.policies_without_assignments` still reports `policy_assignments_not_read_for_every_policy`. Each section gap is named by the run (`collection_gaps`, `coverage_gaps[].section_gaps`, the handoff and a gate warning), whether the read was cut (`fanout_limit`, `operator_limit`, `pagination_failed`) or refused (`read_failed`, with the error classes), including a Defender state read for 100 of 150 devices, both beta update profile lists refused (403), a refused compliance assignment read, `windowsProtectionState` refused on every device and 111 compliance policies cut at 100.

A rule that reads a fan-out can still `fail` from what the expanded objects show. The
`intune_depth.policies_without_assignments` finding counts policies from
`intune_depth`'s own `deviceConfigurations`, and `identity_governance.standing_privilege_only`
needs a successful, empty `roleEligibilitySchedules` read; neither is raised when the read
failed or was cut. Baselines evaluate the Intune rule only when
`normalization_coverage` shows both the policy inventory and the assignments were read in
full (`device_configurations_not_collected`, `device_configurations_not_read_in_full`,
`no_device_configurations` and `policy_assignments_not_read_in_full` are the reasons it
reports otherwise). The assignment read also has to cover every profile: when the collector
stopped at its fan-out limit (the `deviceConfigurationAssignmentsFanout` gap, or fewer
`intune_policy_assignment_objects` rows than profiles), a profile it never expanded may be
assigned, so the finding stays silent and the rule reads `policy_assignments_not_read_for_every_policy`.
The rule counts device configuration profiles only: compliance policies, app protection policies,
Conditional Access policies and authentication-method policies are not counted.

The Google Workspace fan-outs run one call per object and are the slow part of a large
domain: `google_directory` makes two calls per user (aliases and OAuth tokens) and one or
more per group (members); `google_gmail_settings` makes eight calls per user
(auto-forwarding, filters, forwarding addresses, send-as, IMAP, POP, vacation and
delegates); `google_groups_settings` one per group; `google_calendar_posture` one per
calendar. A 20,000-user domain is about 160,000 Gmail settings calls on its own, so that
fan-out is bounded: `google_gmail_settings` reads at most 500 mailboxes without `--top` (the
`--top` value with it), and a longer user list records a `mailboxSettingsFanout` coverage row
(`truncation_reason: fanout_limit`) and makes the run partial. For a large domain set `--top`
so the user and group lists, and with them the fan-outs, are limited; every cut list is then
recorded as a gap, which is the point.

For ordinary lists in the shared Graph endpoint runner, a later-page failure or refused
next link retains rows already read, in both the chunked and the in-memory path, with
`pagination_failed` or `next_link_refused`. Graph paging stops a repeated page URL with
`incomplete_evidence`. The shared endpoint runner then clears the affected endpoint's
payload and row count; the run writer also discards its chunks, metadata sidecars and
manifest entries. Other paging followers handle already-yielded rows themselves, so
cycle detection alone does not guarantee that an entire section is withheld.
Strict policy lists in the shared runner withhold the affected endpoint's evidence on
any read or validation failure, including exceeding 5,000 pages; ordinary lists have
no default page-count ceiling. The strict validator reads one additional page to
detect that ceiling, without publishing its rows.

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

No list read drops its next-page link silently. `defender.secureScoreControlProfiles`, `defender.secureScores`, `licensing.subscribedSkus` and `identity.domains` were unpaged reads (the first returned 200 rows and a next link in a live run); they now go through the shared paging path without `$top` and are kept whole inline (the endpoint-spec flag `inline: true`), so an operator `--top` below the list length cuts them like any other list (below about 250 it makes `defender` partial). An unpaged response that still carries `@odata.nextLink` is a gap with `truncation_reason` `pagination_not_followed`, and the capability-gated list endpoints (`/security/incidents`, `/security/alerts_v2`, `/identityGovernance/appConsent/appConsentRequests`) follow the next link or record the same reason. A test fails the build when a collector reads a list with a direct `get_json`.

**DKIM CNAME parity.** For raw SCuBA records, a NOERROR CNAME-only answer is retained as `rdata`,
matching the pinned ScubaGear DoH fallback, and stops the selector walk as a non-key answer.
When the response instead carries NXDOMAIN (DoH `Status: 3`) with only CNAME answers, the walk
continues to the next selector and logs `Query returned NXDomain` with no query answers.
This response shape is inferred from RFC 6604, not observed live. The shared query API retains
the CNAME records and NXDOMAIN outcome. When other answers remain, CNAME entries are dropped.

A DNS resolver failure is unknown, never a missing record. The DNS-over-HTTPS client raises for SERVFAIL, REFUSED, FORMERR and NOTIMP; only NXDOMAIN and NOERROR without an answer mean the record is absent. A response with no `Status` (or one that is not a number) and a response with the truncation flag (`TC`) are not statements about the record either: they raise too, so a malformed answer cannot read "absent" and raise a false "missing" finding. A DKIM record with an empty `p=` is a revoked key (RFC 6376) and counts as an absent selector. An MTA-STS policy fetch that did not answer (unreachable, HTTP 429 or 5xx) fails the domain's row with error class `public_lookup_error` and makes the collector `partial`; a 404 or an invalid file is an answer and stays a finding. The domain's coverage row is `failed` with error class `dns_resolver_error`, so the `dns_posture` collector and the run are `partial`, a blocker names the error, and the rules read `not_assessed` with `collector_not_complete:dns_posture` (an offline bundle whose collector is complete but whose record carries `resolver_error` reads `resolver_error`). The record has every presence flag unknown (`present: null`; DKIM `selectors_unresolved`) and the normalized `dns_posture_objects` record omits `spf_present`, `dmarc_present`, `mta_sts_dns_present`, `tls_rpt_present` and `bimi_present` and lists `dkim_selectors_unresolved`. No SPF, DMARC, DKIM, MTA-STS, TLS-RPT or BIMI finding is raised for such a domain (Microsoft 365 and Google Workspace), and it no longer mutes `exchange.dkim_signing_disabled`.

Mailbox forwarding is read server-side: `Get-EXOMailbox -ResultSize 501 -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward -Filter 'ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null'` returns the mailboxes that forward whatever the tenant size (it was the first 50 mailboxes of the tenant, recorded nowhere). The collector bound is 500 (`FORWARDING_MAILBOX_LIMIT`); one row more is requested so a longer list is detected, and then 500 are kept and the coverage row is `partial` with `truncation_reason` `fanout_limit`, `result_limit` 500 and `rows_collected` 500, so `exchange.mailbox_forwarding_configured` reads `not_assessed` unless a finding was raised. Normalized `mailboxForwarding` records carry `forwarding_address` (a forwarding contact) next to `forwarding_smtp_address`.

Fan-out gap rows (`deviceConfigurationAssignmentsFanout`, `teamChannelsFanout`, `sitePermissionsFanout`) state the real total, the base list's `item_count`, and not the 20-row inline sample. `onedrive_posture` builds `oneDriveSites` and `teamSites` from every site read (and streams them to chunk files when the source was), so the OneDrive finding's `personal_site_count` and site list cover all sites; if the site list could not be read in full the derived sections carry `error_class` `incomplete_evidence`. The `app_consent` `servicePrincipalFanout` row carries `rows_collected`, the principals expanded.

Every eDiscovery command coverage row (inventory, export and checkpoint-resume rows) carries `command_variants`, all the spellings the operation may run, so the declared set contains the fallback that ran and `configs/collector-definitions.json` matches the collector (`ediscovery case search list` replaces the two spellings that never ran). `command.completed` events of the m365 CLI adapter are logged after the output is classified: a command that exits 0 but prints CLI help, nothing or non-JSON is `status: error`, not `ok`.

### Microsoft 365 sharing, federation and emergency-access rules

These rules read tenant settings, not one record per site or per policy. Each one stays silent when
the setting it needs was not read, and baseline alignment reads it `not_assessed` (never `pass`) with
the reason shown.

**`normalized/sharepoint_tenant_settings.json`** holds one `sharepoint_tenant_settings` record per
collector that read `/admin/sharepoint/settings` (`onedrive_posture`, `sharepoint_access`), keyed
`sharepoint_tenant_settings:<collector>`. `read_state` is `collected`, `blocked` or `absent`. A
collected record carries the settings it could read, each in one canonical form whichever spelling
the payload used (Microsoft Graph names and strings, or SharePoint Online Management Shell names and
numbers): `sharing_capability` and `onedrive_sharing_capability` (`disabled`,
`existingExternalUserSharingOnly`, `externalUserSharingOnly`, `externalUserAndGuestSharing`),
`sharing_domain_restriction_mode` (`none`, `allowList`, `blockList`), `allowed_domain_count`,
`blocked_domain_count`, `default_sharing_link_type` (`none`, `direct`, `internal`, `anonymous`),
`anonymous_link_expiry_days` (0 when links never expire), `file_anonymous_link_type` and
`folder_anonymous_link_type` (`none`, `view`, `edit`). A setting the payload does not carry is
absent; one in a form this tool does not recognise is listed under `unrecognised` with its raw
text. Domain names are kept as counts. Microsoft Graph v1.0 returns the sharing capability and the
domain restriction mode; the default link type and the anonymous-link settings are read only when
the settings payload carries them (for example an export from the SharePoint Online Management
Shell), so on a Graph-only run those rules report `sharing_setting_not_read:<setting>`.

`onedrive_posture_objects` records gain `sharing_capability_source`: `tenant` when the collector
copied the tenant's single value onto the site, `site` when the site carried its own.

The federation record now uses `Identity` (`Global`) as its key. Its finding id is
`teams_policy:tenantFederationConfiguration:Global:external_federation_open`;
comparisons against older runs can show the old id resolved and this id newly raised.

`teams_policy_objects` records for `tenantFederationConfiguration` gain `allow_teams_consumer`,
`allowed_domains_state` (`open`: no allow list; `allow_list`; `unknown`: not collected or an unrecognised
shape), `allowed_domain_count` and `blocked_domain_count`.

| Rule | Condition | Severity | Not assessed when |
| --- | --- | --- | --- |
| `onedrive.external_sharing_enabled` | One finding for the tenant, with the personal sites in `evidence.sites` (up to 50, with the full count). The OneDrive capability is `oneDriveSharingCapability` when read, otherwise the SharePoint value, which OneDrive inherits unless set stricter. Anyone links: high; new and existing guests: low; existing guests only or off: no finding | high, medium or low | `sharepoint_settings_not_collected`, `sharing_setting_not_read:sharing_capability` |
| `sharepoint.external_sharing_broad` | `sharing_capability` allows more than existing guests. Anyone links: high unless anonymous links are known to expire within 30 days and both file and folder links are known to be view-only (then medium); a setting that was not read never mitigates. New and existing guests: low. CIS `7.2.3` allows new and existing guests, ScubaGear `MS.SHAREPOINT.1.1v1` passes only existing guests or off, so the low finding breaches SCuBA only (`framework_thresholds`) | high, medium or low | as above |
| `sharepoint.sharing_domains_unrestricted` | External sharing is on and `sharing_domain_restriction_mode` is `none` (medium; low when only existing guests may be shared with), or `blockList` (low). CIS `7.2.6` accepts a block list, ScubaGear `MS.SHAREPOINT.1.3v1` passes only an allow list, so a block list breaches SCuBA only. Sharing off is not applicable | medium or low | `sharing_setting_not_read:sharing_domain_restriction_mode` |
| `sharepoint.default_link_type_broad` | `default_sharing_link_type` is not `direct` (specific people), the requirement of CIS `7.2.7` and `MS.SHAREPOINT.2.1v1`: `anonymous` is high; `internal` and `none` (no default set) are low | high or low | `sharing_setting_not_read:default_sharing_link_type` |
| `teams.external_federation_open` | `AllowFederatedUsers` is true and no allow list restricts it (`allowed_domains_state` `open`). Federation to an allow list (including an allow list object with no domains, which allows federation with none), federation that is off, and a configuration whose allow list was not collected, is empty, or has an unrecognised shape raise nothing. `AllowFederatedUsers` must be a boolean; any other value reads `federation_setting_not_read`. `AllowTeamsConsumer`, `AllowPublicUsers` and the blocked-domain count are evidence only | medium | `federation_configuration_not_collected`, `federation_setting_not_read`, `federation_allow_list_not_read` |
| `ca.break_glass_exclusion_missing` | See below | high or medium | `break_glass_accounts_not_identified`, `break_glass_accounts_unresolved` |

The tenant-level SharePoint findings have the ids `sharepoint_tenant:external_sharing_broad`,
`sharepoint_tenant:sharing_domains_unrestricted` and `sharepoint_tenant:default_link_type_broad`, one each at
most, and carry `framework_thresholds` rows (`framework`, `control_ids`, `metric`, `observed`, `requirement`,
`breached`) so that baseline alignment fails a control only for a framework whose requirement the finding
breaches: a low finding for new and existing guests or a block list fails the SCuBA controls and leaves the CIS
ones passing.

The OneDrive finding used to be one `high` finding per personal site (`onedrive_posture:<site>:external_sharing_enabled`)
repeating the tenant's setting. Its id is now `onedrive_posture:tenant:external_sharing_enabled`. A site
cannot be more permissive than the tenant, and the collector copies the tenant value onto every site, so
no site can show its own exceedance from collected data; a site that carries its own value above the
tenant's is listed in `evidence.sites_exceeding_tenant_setting` and counts at its own level.

**Emergency access.** `normalized/break_glass_assessment.json` holds one `break_glass_assessment`
record per run that collected Conditional Access policies (`break_glass_assessment:tenant`): `state`
(`assessed`, `no_accounts_identified`, `operator_accounts_unresolved`), `account_source` (`operator`,
`inferred`, `none`), the account labels, `unresolved_accounts`, `unresolved_account_details` (one `entry` and `reason` per unresolved entry: `not_found`, or `ambiguous_display_name` for a display name more than one account carries), `unverified_accounts` (object IDs that are not among the collected users or groups; they still match a policy's exclusion by id), `policies_in_scope` and
`policies_missing_exclusion`. An entry is looked up in the full user and group lists the run read (the chunk files, never the 20-row inline sample) by object ID, user principal name, mail and display name; an entry that matches nothing is recorded in `unresolved_accounts` and named in the findings, never dropped. The same resolution is used by the break-glass check and by every identity control verdict. Conditional Access policy records gain `missing_break_glass_exclusion`,
`break_glass_in_scope`, `break_glass_enforces` (`mfa` or `block`) and the accounts the policy does and
does not exclude. The same list is the allow-list for the MFA and legacy-authentication verdicts: an exclusion of one of its users or groups does not count against them (see the identity control verdicts above). The accounts come from `--break-glass-accounts` (comma-separated object IDs, user
principal names, mail addresses, display names or group names, or `@file`, one per line) or `AUDITEX_BREAK_GLASS_ACCOUNTS`; the option
wins. Entries are separated by commas or semicolons (or lines in a file); spaces are part of an entry, so a group
is listed by its display name; a `#` that starts a line or follows whitespace begins a comment, and one inside an
entry (a guest user principal name contains `#EXT#`) does not; there is no limit on the number of entries. List the group your policies exclude when the accounts are excluded through it: a group counts as excluded when
the policy excludes it, or an excluded group whose members the run read (role-assignable groups) contains the account. Without a list the accounts are inferred from users and groups whose name says break glass or
emergency access and from Global Administrator role holders (a role excluded with `excludeRoles` counts).
A policy is judged when it is enabled, requires MFA (a built-in `mfa` control or an authentication
strength), blocks, or requires a compliant or hybrid-joined device with no MFA alternative (`enforces` `device`: those
controls alone, or the operator is AND), and reaches the accounts: it targets all users, targets a role one of the accounts holds
(roles come from the effective administrator set; a group or an object the run did not collect has no known roles, so a role-targeted policy
is judged at `medium`, reach `administrator_roles_unverified`), or names one of the accounts or groups. Report-only policies, policies whose
grant is a session control, a password change or a device control with an MFA or other alternative, policies aimed at other groups or at
roles none of the accounts holds, and policies aimed at a user action or an authentication context (which cannot block a sign-in) are not judged. A judged policy passes when it excludes at least one listed
account or group; the finding is one for the tenant, `conditional_access:ca_break_glass_exclusion:tenant`,
that names each policy without an exclusion (`affected_objects`, `evidence.policies` with `enforces`,
`reach` and `broad`) and cites the policy records and the assessment. Severity is `high` only for an
operator-supplied list and a policy that can lock every administrator out (MFA, or a block that is not
legacy-protocol only, over all users or the Global Administrator role and all applications); otherwise `medium`. A policy for another administrator role (Helpdesk Administrator, say) cannot lock a Global Administrator out, so it is judged but never `high`. A device
requirement is judged but never broad, so it is `medium`, and an inferred list never rates above `medium`. This replaces one `high` finding per policy
(`conditional_access:ca_break_glass_exclusion:<policy id>`) raised for every enabled policy that excluded none
of every holder of seven roles.

### Microsoft 365 device, update and malware evidence

The `update_management_summary` record (section `update_management_objects`) also carries `profiles_with_unknown_assignments` (update profiles whose assignments were not read) and `update_profiles_gap`, which is absent when the profile reads are complete and otherwise one of `update_profiles_blocked`, `update_profiles_truncated` (a beta profile list that was refused or cut), `profile_assignments_blocked`, `profile_assignments_truncated`, `profile_assignments_absent` (assignments not read for a list that has profiles) or `profile_assignments_unknown`. A rule that exempts a tenant because an update profile is assigned reads this field, so an unreadable profile list is not read as "no profile assigned". An `absent` profile list (a bundle from before the lists were collected) is not a gap.

Cyber Essentials asks whether devices are encrypted, supported, patched and protected against malware. A
tenant audit sees part of that, through Intune and Exchange Online, and only for the devices Intune
manages. Every check is three-valued: a field that is absent, `Unknown` or unparseable is unknown, never a
pass and never a failure; a list that was blocked, cut or not collected makes the checks that read it
unknown as a whole. Baseline alignment reads an unknown rule `not_assessed` with the reason shown, and the
Cyber Essentials rows for these requirements are `partial`, so none reads `pass`.

**`normalized/devices.json`** records gain `is_encrypted`, `jail_broken` (`true`/`false`; Intune's
`Unknown` is left out), `owner_type` (`company`, `personal`, `unknown`; read from the v1.0 field
`managedDeviceOwnerType`, with the beta `ownerType` as a fallback), `enrolled_at`, `enrollment_type` and
`os_family` (`windows`, `macos`, `ios`, `android`). A field the payload does not carry is absent.

**`normalized/device_posture.json`** holds one `device_posture_summary` record (`device_posture_summary:tenant`):
`read_state` (`collected`, `truncated`, `blocked`), `device_count`, `platform_counts`, and for each check how many
devices it says nothing about: `encryption_on`/`encryption_off`/`encryption_unknown`,
`jailbreak_clean`/`jailbreak_jailbroken`/`jailbreak_unknown`/`jailbreak_not_applicable` (Intune reports
jailbreak state for iOS and Android only), `last_sync_unknown`, `compliance_unknown` (compliance state not
`compliant`, `noncompliant`, `error` or `conflict`) with `compliance_in_grace_period` (the part of it that is
`inGracePeriod`), `os_lifecycle_unknown` with
`os_lifecycle_unknown_reasons`, and `os_lifecycle_edition_dependent` (the edition decides support, see below) as of `os_lifecycle_evaluated_on`. `auditex compare` ignores `os_lifecycle_evaluated_on`, and `run_offline` and `auditex demo` take an evaluation instant (`as_of`) so a replay is judged as of a fixed day; the demo tenant is pinned to the day its fictional snapshot was taken.

**`normalized/compliance_policy_objects.json`** holds one `compliance_policy` record per compliance policy
(`platform`, `policy_type`, `settings` (`passcode_required`, `passcode_min_length`, `encryption_required`,
`min_os_version`, `jailbreak_blocked`, `defender_required`, `firewall_required`, `threat_protection_required`,
`secure_boot_required`; a setting the policy type does not have is absent, so unknown), `assignments_known`,
`assigned`, `assigned_to_all_devices`, `assigned_to_all_users`, `group_target_count`, `exclusion_count`;
group ids are not kept), one `compliance_platform_coverage` record per platform (`device_count`,
`policy_count`, `assigned_policy_count`, `unassigned_policy_count`, `assignments_unknown_count`) and one
`compliance_policy_summary`. Microsoft Graph v1.0 does not return Defender settings for a Windows policy, so
`defender_required` is usually absent there. Compliance policies built from settings-catalog templates are
not listed by `/deviceManagement/deviceCompliancePolicies`.

**`normalized/update_management_objects.json`** holds one `update_ring` record per Windows Update for Business ring
(`quality_deferral_days`, `feature_deferral_days`, `quality_deadline_days`, `quality_paused`,
`quality_pause_expires_at`, `automatic_update_mode`, and the assignment fields above), one `update_profile` record
per Windows quality or feature update profile (`profile_type`, `api_version` `beta`), and one
`update_management_summary` (read states, ring and profile counts, `rings_assigned`,
`rings_assigned_to_all_devices`, `profiles_assigned`, `windows_comanaged_device_count`, `windows_device_count`). Update rings are `deviceConfigurations` of the
`windowsUpdateForBusinessConfiguration` type, read from the v1.0 list the collector already holds; quality and
feature update profiles exist on Graph beta only.

**`normalized/defender_av_objects.json`** holds one `defender_av_state` record per Windows device whose state was
requested (`read_status` `ok`, `not_reported` for HTTP 404, `failed`; `av_state`, `realtime_state`,
`signature_state`; the raw `malware_protection_enabled`, `real_time_protection_enabled`,
`signature_update_overdue`, `product_status`, `tamper_protection_enabled`) and one `defender_av_summary`
(`windows_device_count`, `devices_expanded`, `devices_not_expanded`, `state_read`, `state_not_reported`,
`state_read_failed`). The state is read with `GET /deviceManagement/managedDevices/{id}/windowsProtectionState`
for at most 100 Windows devices; a larger fleet leaves a `fanout_limit` entry in `collection_gaps` and the section's `collection_truncated` flag. That gap is scoped to the section: the `intune` collector stays `ok` when its device and policy lists were read in full, so the other Intune rules keep their evidence and only the Defender rules read `defender_state_truncated`. The Intune reports API
(`getDefenderAgentsReport`, `reports/exportJobs`) is a POST export job and is not used.

**`normalized/exchange_policy_objects.json`** records for `malwareFilterPolicy` (`is_default`, `enable_file_filter`,
`zap_enabled`), `transportConfig` (`smtp_client_auth_disabled`), `casMailboxSmtpAuth` (`smtp_auth_enabled_mailbox_count`) and `dkimSigningConfig` (`dkim_enabled`,
`dkim_status`, `domain_name`) are new, and `acceptedDomains` records gain `domain_type` and `default_domain`.

| Rule | Condition | Severity | Not assessed when |
| --- | --- | --- | --- |
| `intune.device_noncompliant` | `compliance_state` is `noncompliant`, `error` or `conflict`. One finding per device, `intune:<id>:device_noncompliant`. Supporting evidence for `ce.sum.vulnerability_fixes_14_days`, never a failure of it | medium | any device's compliance was never evaluated (`unknown`, no value, `configManager`) or the device is in its grace period (`inGracePeriod`: not compliant yet, access still granted); the device list was not read in full; there are no devices |
| `intune.device_encryption_off` | `is_encrypted` is false. One finding per device, `intune:<id>:device_encryption_off` | high on Windows and macOS, medium otherwise | any device has no value; the device list was not read in full |
| `intune.device_jailbroken` | An iOS or Android device reports `jail_broken` true | high | an iOS or Android device reports no value; the device list was not read in full |
| `intune.device_stale_sync` | No Intune check-in within the window: 14 days by default (the Cyber Essentials window for updates), `--stale-sync-days` or `AUDITEX_STALE_SYNC_DAYS` (1 to 3650; an invalid value is ignored) | medium | any device has no last-sync time; the device list was not read in full |
| `intune.device_os_end_of_life` | The release is past its end-of-support date in `configs/os-end-of-life.json` (see below) | high for a vendor-published date with no extended programme open, otherwise medium | the version is missing, unparseable or not in the table; the Windows edition decides support (Home/Pro against Enterprise/Education, or a Long-Term Servicing edition sharing the build); the device list was not read in full |
| `intune.compliance_policy_missing_platform` | A platform has enrolled devices and no compliance policy of its type (`no_policy`), or none of its policies is assigned (`no_assigned_policy`). One finding per platform | medium | the policy list or its assignments were not read in full for the platform |
| `intune.defender_av_off` | `malwareProtectionEnabled` is false, or `productStatus` says the service is not running or runs without malware protection | high | the Defender state was not read for a Windows device, or the device list or the state fan-out was cut |
| `intune.defender_realtime_protection_off` | `realTimeProtectionEnabled` is false | medium | as above, or the field is absent |
| `intune.defender_signatures_stale` | `signatureUpdateOverdue` is true, or `productStatus` says the signatures are out of date | medium | as above, or the field is absent |
| `intune_depth.update_ring_not_assigned` | Windows devices are enrolled, no update ring is assigned (none exists, or none has an assignment), no update profile is assigned and no Windows device is co-managed by Configuration Manager. A ring assigned only to groups is not flagged: group membership is not resolved. Update settings made through settings catalog policies, group policy or WSUS are not read | medium | the rings, their assignments or the device list were not read in full; there are no Windows devices; an assigned update profile or a co-managed device shows updates managed another way (`update_managed_by_other_means`); the beta quality or feature update profile lists, or their assignments, were refused or cut when no ring is assigned (`update_profiles_blocked`, `update_profiles_truncated`, `profile_assignments_blocked`, `profile_assignments_truncated`, `profile_assignments_absent`, `profile_assignments_unknown`, from `update_profiles_gap` on the update summary): "no profile" was not established |
| `intune_depth.update_ring_deferral_excessive` | An assigned ring lets quality updates wait more than 14 days: the deferral alone, or the deferral plus the deadline and restart grace period when a deadline is set (`install_delay_days` in the evidence); or it has them paused (a pause whose expiry has passed does not count) | medium | no ring is assigned; a ring's settings were not returned |
| `exchange.malware_filter_weakened` | An anti-malware policy has the common attachment types filter or zero-hour auto purge off. Every policy is judged on its settings: the default one keeps the finding id `exchange_policy:malware_filter:default_weakened`, a custom one gets `exchange_policy:malware_filter:<identity>:weakened`. The recipients a custom policy covers (its malware filter rule) are not read | high when both are off, otherwise medium | `Get-MalwareFilterPolicy` was not read in full, returned no default policy or omitted a setting of any policy |
| `exchange.smtp_auth_enabled_tenant_wide` | `SmtpClientAuthenticationDisabled` is false for the tenant, or the tenant default is true and `casMailboxSmtpAuth` counts mailboxes that switch it back on for themselves (finding `exchange_policy:cas_mailbox:smtp_auth_enabled`, once per run, with the count and no address) | medium | `Get-TransportConfig` was not read or omitted the setting, or the per-mailbox count (`Get-CASMailbox`, an aggregate `Measure-Object \| Select-Object Count`, so the answer is never empty and no mailbox is named) was not read in full |
| `exchange.dkim_signing_disabled` | DKIM signing is off for an authoritative accepted domain other than `*.onmicrosoft.com`. One finding per domain. `DomainType` and `DomainName` are read whether Exchange returns names, integers or objects | medium | `Get-DkimSigningConfig` or `Get-AcceptedDomain` was not read, there is no custom domain, a domain has no signing row, or `dns_posture.dkim_missing` already reports the disabled domain (`reported_by:dns_posture.dkim_missing`) |

**Mail protection rules are judged on their own command rows.** The three Exchange rules do not wait for the whole `exchange_policy` collector: it runs multiple independent commands and is `partial` when a command genuinely fails. `Get-ProtectionAlert` is a by-design section skip because Auditex does not open a Security & Compliance session; that skip alone does not make Exchange partial. Each rule reads `not_assessed` unless its own command rows were read in full (`malwareFilterPolicy`, `transportConfig` with `casMailboxSmtpAuth`, `dkimSigningConfig` with `acceptedDomains`), and `auditex compare` reassesses a vanished finding on the same rows. CIS `2.1.9` and ScubaGear `MS.EXO.3.1v1` now need `exchange.dkim_signing_disabled` as well as `dns_posture.dkim_missing`: selectors published in DNS no longer make them `pass` on their own. Exchange Online returns enumerations as integers in some builds, so the adapter asks for names (`ConvertTo-Json -EnumsAsStrings` where PowerShell has it) and the normalizer reads either form.

**End-of-life table.** `configs/os-end-of-life.json` is read from disk and never from the network. It records
`verified_on`, and for each Windows build (10 and 11, General Availability Channel) and each macOS, iOS, iPadOS and
Android major version: `end_of_support`, the earlier `end_of_support_home_pro` where Windows editions differ,
`ltsc_end_of_support` (the latest end date of a Long-Term Servicing edition that shares the build: LTSC, LTSB or IoT Enterprise LTSC), `extended_support_until` (Windows 10 Extended Security Updates, whose enrolment Auditex cannot see), `basis`,
`confidence` (`vendor_published` for Microsoft dates; `derived` for Apple and Android, which publish none),
`status` on the verification date, `sources` and a `note`. A device is past end of life only after the last day of the
latest date for every edition on its build, the Long-Term Servicing one included. Between the Home/Pro and Enterprise/Education dates,
and between the general date and `ltsc_end_of_support` on a build an LTSC edition shares (17763, 19044, 26100 and the like), `osVersion`
does not show the edition, so the state is unknown (`os_edition_dependent_for_<n>_devices`). Windows Server shares some builds and is not a
Windows client here (`platform_not_covered`). iOS and iPadOS 17 are not called end of life: Apple still issued iPadOS 17 security updates
on 2026-05-11. Tests check the schema, that no release past its last day is labelled supported, and that every release cites a source.

**Detection coverage.** The `defender_alert_api` signal (title "Defender alert source present") is `on` only when an
alert from a Defender service (`serviceSource`) was seen, or a Defender service plan is licensed, and the alerts API
answers. An API that answers with an empty or Entra-only alert list is `unknown` (reason
`alerts_api_answered_no_defender_evidence` or `alerts_api_answered_licensing_not_read`), never `on`.

### Google Workspace evidence scope, domains and rules

What a Google bundle states about how far its evidence reaches, and the sections the Google rules read.

**Subject scope.** Evidence that is one subject's view rather than the tenant's says so:

- A coverage row, a capability-matrix row and a finding carry `subject_scoped`: `admin` (the delegated admin's, or the signed-in user's, view) or `user` (each user's own settings, read by acting as that user). Drive (`driveFiles`, `sharedDrives`) and Calendar (`calendars`, `calendarAcls:*`) are `admin`; `calendarResources` is a tenant-wide Directory inventory and is unlabelled. A finding built from `admin` evidence also carries `evidence_scope` and ends its description with the same note.
- `google_gmail_settings` is `user` under domain-wide delegation: one delegated read per active user, as that user (`mailboxSettings:<user>`). Without delegation (OAuth) it reads the signed-in mailbox only (`mailboxSettings:me`, `admin`) and records a `mailboxSettingsScope` coverage row, status `partial`, `error_class: subject_scope`, with the number of users not read. Suspended and archived accounts are not read; `mailboxSettingsSkipped` (status `ok`) carries `skipped_suspended` and a `note`.
- `normalized/snapshot.json` carries `subject_scope` (collector to `admin` or `user`) and `mailbox_settings_skipped_suspended`; `auth-context.json` carries `per_user_delegation` and the `subject_scope` of the selected collectors.

**Internal domains.** `--domain` is a label and never filters users or groups, which are listed for the whole customer (`customer=my_customer` unless `--customer-id` is given). `normalized/google_domains.json` has one record per primary, secondary and alias domain from the Directory domains list (`domain_name`, `domain_kind`, `verified`, `parent_domain` for an alias). The snapshot carries `internal_domains` (those domains and the `--domain` label), `internal_domains_status` and `internal_domains_source`:

| `internal_domains_status` | Meaning | External-principal rules |
| --- | --- | --- |
| `known` | The whole Directory domains list was read | Evaluated against every internal domain |
| `partial` | The list was read but cut short by `--top` or only partly read | Evaluated against the domains that were read, and `google.internal_domains_unknown` says an internal address on a domain that was not listed may be reported as external |
| `label_only` | The list was not read; only `--domain` is known | Evaluated against the label, and `google.internal_domains_unknown` says an internal secondary or alias domain address may be reported as external |
| `unknown` | Neither the list nor a label | Not evaluated; `google.internal_domains_unknown` says so (raised only when there is evidence the rules would have read) |

The external-principal rules are `google.group_external_member`, the `google.gmail_external_*` and forwarding-filter rules, `google.drive_external_permission`, `google.drive_domain_permission`, `google.calendar_external_acl` and `google.calendar_domain_acl`.

**Sections.** `google_users` rows carry `is_privileged` (`is_admin` or `is_delegated_admin`; the 2-step verification, suspended-admin, stale and never-signed-in rules use it, while the super-admin counts use `is_admin` alone), `archived` and `creation_time`. `google_two_step_policies` holds the Cloud Identity 2-step verification policies read by `google_policies` (`setting_type`, `org_unit`, `group`, `sort_order`, `policy_type`, `enforced_from`, `allow_enrollment`, `allowed_sign_in_factor_set`, `enrollment_grace_period`); each policy record carries `policy_scope`: `organisation` (the root organisational unit, no group), `org_unit`, `group`, or `unclassified` when the root unit is unknown. The root unit has no row in the Directory org unit list, so it is taken as the parent of the top-level units; an org unit list that was read and is empty means the root is the only unit, and without the list (not collected, failed) no policy can be called organisation-wide. The snapshot's `two_step_policy_status` is `enforcing` (the organisation-level policy is in force), `partial` (only some organisational units or groups are enforced, the organisation-level policy is not), `scheduled` (every enforcement date is in the future), `not_enforced` (the policy read completed and no policy enforces) or `unknown` (not read, failed or cut, or an enforcing policy cannot be placed because the root unit is unknown: never read as not enforced). An organisational unit that opts out of an organisation-level policy cannot be seen from the policy list alone; the per-user `isEnforcedIn2Sv` flag is the authority for who is covered. Mobile devices (`google_mobile_devices`) gain `encryption_status` and `encryption` (`encrypted` or `not_encrypted`), `device_lock_status` and `device_lock_policy` (`enabled` or `disabled`), `security_patch_level` and `security_patch_date`, `os_release` and `device_type`; ChromeOS devices gain `auto_update_expiration` (from `autoUpdateThrough`, else the deprecated `autoUpdateExpiration`) with `auto_update_source`, `platform_version`, `model`, `boot_mode`, `org_unit_path` and `support_end_date`. The Directory API does not enumerate the values of `encryptionStatus` and `devicePasswordStatus`: a value this tool does not recognise leaves `encryption` or `device_lock_policy` absent (unknown) and keeps the raw text beside it. The device list requests the posture fields by name with the `FULL` projection, so installed-app and recent-user telemetry is not collected. The lock fields avoid the word the bundle's sensitive-key scanner rejects.

**Rules.** An absent field is unknown, never a pass: one `google.evidence_unknown` finding per check (`user_login_time`, `user_2sv_enforcement`, `mobile_encryption`, `mobile_compromised_status`, `chromeos_auto_update_expiration`) gives the number of objects without the field and cites the first of them.

| Rule | Condition | Severity | Cyber Essentials (confidence) |
| --- | --- | --- | --- |
| `google.user_2sv_not_enforced` | Active non-privileged user with `isEnforcedIn2Sv` false (enrolment is not enforcement) | medium | `ce.uac.mfa_cloud_services` (full) |
| `google.org_2sv_policy_not_enforced` | The policy read completed and the organisation-level 2-step verification policy is not in force: high when no policy enforces, medium when only some organisational units or groups do (the finding names them) | high or medium | `ce.uac.mfa_cloud_services` (full), `ce.uac.mfa_admin_accounts` (partial) |
| `google.stale_user` | Active user whose last sign-in is older than `--stale-user-days` (default 90); high for a privileged account; a privileged account past 365 days is `google.admin_stale_login` instead | medium | `ce.uac.remove_unused_accounts` (full), `ce.sc.unnecessary_accounts` (partial) |
| `google.never_logged_in_user` | Active non-privileged user who never signed in and is older than 30 days (or of unknown age) | low | `ce.uac.remove_unused_accounts`, `ce.sc.unnecessary_accounts` (both partial) |
| `google.chromeos_device_past_aue` | Active ChromeOS device past `auto_update_expiration` | high | `ce.sum.supported_software` (full), `ce.sum.vulnerability_fixes_14_days` (partial) |
| `google.mobile_device_encryption_off` | Mobile device (not blocked) with `encryption` `not_encrypted` | medium | none |
| `google.internal_domains_unknown`, `google.evidence_unknown` | Diagnostics: the domain set is missing or limited, or a field a check needs was not returned | medium | none |

The delegated-admin flag also moves `google.admin_2sv_not_enforced`, `google.admin_2sv_not_enrolled`, `google.suspended_admin` and `google.admin_stale_login` onto delegated admins. `google.mobile_device_compromised` reads the API's `deviceCompromisedStatus` (the older `compromisedStatus` key still works). The Directory API documents the field only as "the compromised device status" and lists no values, so Auditex classifies by the texts seen in the Admin console and API output and the Cloud Identity Devices enum: `compromised` ("Compromised", "Compromise detected"), `not_compromised` ("No compromise detected", "Not compromised", "Uncompromised") and `unknown` for an absent field, `UNKNOWN`, `COMPROMISED_STATE_UNSPECIFIED` or any text not listed. Each `google_mobile_devices` record carries `compromised_status` (the raw text) and `compromised_state`; only `compromised` raises the rule, and devices in the `unknown` state are counted in one `google.evidence_unknown:mobile_compromised_status` finding (with the unrecognised texts), never passed or failed. The stale-sync rules (`google.mobile_device_stale_sync`, `google.chromeos_device_stale_sync`) use `--stale-device-days` (default 90); the description names the threshold.

**One collector issue per surface.** A per-object failure no longer raises a finding per object. Every `google.collector_issue` for a surface (`group-members`, `aliases`, `oauth-grants`, `group-settings`, `calendar-acls`, `mailbox-settings`, a Gmail setting such as `delegates`, or a whole list such as `users`) is one finding with the id `google.collector_issue:<collector>:<surface>`. Its `returned_value` carries `surface`, `object_count`, up to 50 `objects` (`objects_truncated` when more), `error_classes` and the three most common `errors` with their counts; a failure with no object keeps the error text as its `returned_value`. The severity is `high` when any failure is a permission error. The per-object rows stay in `blockers/blockers.json` and the `google_*_errors` sections. A finding id built from a per-object failure changes from `google.collector_issue:<object-id>` to the surface id, so a waiver written for the old id must name the new one or the rule.

**Waivers.** `auditex google run --waiver-file` takes the file the Microsoft 365 run takes (`azure_tenant_audit.waivers`): every populated field must match (AND), a waiver names a `finding_id` or `rule_id` (`collector` and `category` only narrow it), an expired waiver never matches, and a file that is missing, unreadable or invalid stops the run with exit status 2 before any API call or output. A matched finding becomes `accepted_risk` with its `waiver`; the manifest records `waiver_path`.

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

### Default Exchange/DNS coverage

`exchange_policy` and `dns_posture` bypass preflight reads and run once in the
collection phase. Required collectors retain the existing runnable-selection
semantics, including preflight-skipped licensing.
Coverage gap `error_classes` group operation rows by their owning `collector`,
including required collectors, rather than by operation `name`.

The by-design `exchange_policy.protectionAlerts` IPPS skip has coverage status
`skipped`, `section_scoped: true` and reason/error class `ipps_session_not_opened`.
It leaves collector/run status `ok` when other reads succeed, while section gaps,
collection gaps, handoff, explorer and AI context retain the limitation. Offline
replay preserves explicit skips; historical session failures remain failures.
Real Exchange/DNS failures remain partial, with collection exit 0 when these are
the only failures; partial runs still block coverage gates by default.

Explicitly array-wrapped Exchange policy list reads serialise zero rows as `[]`.
Only lists that can legitimately be empty use this wrapper: transport rules,
inbound/outbound connectors, forwarding mailboxes, Defender assignment/preset
rules and optional Safe Attachments/Safe Links policies. The unused protection-alert
command remains wrapped but is never invoked. Accepted/remote domains, default
sharing and malware policies, DKIM signing configuration, default anti-phish,
hosted content/connection filter policies and the ATP organisation setting stay
unwrapped; missing output is a failure, as it is for scalar and count reads.
An empty accepted-domain envelope is unusable and DNS falls back to Graph-verified
domains with the Email service. A non-empty accepted-domain list containing only
coexistence domains still legitimately produces an empty DNS record universe.

Every command through the shared PowerShell adapter starts with
`$ErrorActionPreference = 'Stop'`, including Microsoft365DSC and lab-only response
actions. PowerShell errors should therefore terminate with a non-zero exit;
non-zero exits and recognised authentication/command failures remain failures.
Exit-0 JSON evidence is retained when stderr contains a warning. The empty-output
success branch requires both an explicitly array-wrapped read and empty stderr;
empty stdout with stderr is `command_error`. Error-preference propagation into
Exchange module proxy functions has not been verified with PowerShell.

## Explainer (additive field, schema 2026-11-05)

The deterministic template port provides
`azure_tenant_audit.explainer.explain(record, redacted_sections, section_order)`.
It returns exactly an Explainer object:
`{explanation: string, remediation_steps: [string], evidence_refs: [string]}`.
References are non-empty, unique View ids ordered by the approved record citations
(with e0 first, including A1 order exceptions); the compact result permits at
most 80 words and three sentences, six steps and 30 words per step. Public
baseline attribution and internal provenance are resource metadata, not extra
customer-output fields. The explainer never changes a verdict, claim or evidence
id. A controlled `ExplainerError` means the caller suppresses the explanation
and retains the original assessment.

An optional `explainer` object is part of a `value_rule` policy row in
`model_assessment.json` schema `2026-11-05`. It must cite `e0` first and only
ids in the requirement claim. Met and not-applicable rows have no steps;
not-met rows have at least one. Historical date-named schemas reject the field.
`rule_not_implemented` has no explainer and the schema rejects one there.
The expanded `render_full` helper is outside the compact schema and is not the
integration entry point.

Assessment enables the explainer after building the rule answer. A failure suppresses only the explainer and logs the
policy id and exception class, without the exception message. The whole fixed
rule read set must exist in the model case, and a fault explanation also needs
that set collected. Optional-collection `absent_section` rows are suppressed.
Ten SECURITYSUITE policies (1.3, 2.1-2.3, 3.1, 3.3, 3.4 and 7.1-7.3) cannot
be explained because their model cases omit `defender_license`, `atp_policy_rules`
or `defender_dlp_license`; no evidence is invented to fill those gaps.

Reports read the assessment through the guarded run-file reader, validate it
and match its run id before adding `policy_explanations`, containing only
`policy_id`, `verdict` and `explainer`. The section is absent for an invalid,
unreadable or unredactable assessment, or when no row has an explainer.
JSON includes the structured section; Markdown and HTML show what each policy
means and numbered actions. CSV, SARIF and OSCAL do not include the section.

A1 (5 November 2026, 11:25 GMT) governs these shared reasons, dispatched before
cell lookup. Neither adds a decision cell to the 1,084-cell v3.9.1 inventory:

| Reason | Exact reason and explanation | Action |
| --- | --- | --- |
| `rule_evaluation_failed` | Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting. | `report_product_fault`; fixed step: Report this fault to the product team at contact+auditex@magrathean.uk. |
| `rule_not_implemented` | Not assessed: Auditex has no rule for this policy yet. | No recommendation; fixed step: No action is possible until a rule exists for this policy. |

Both use `verdict: not_assessed`, `cell: null`, no collection or baseline
steps, and no exception diagnostics. The fault requires the fixed collected
policy read set. The product now emits exactly this representation, so the adapter
no longer normalises anything: a shared reason with a non-null cell, including the
old cell named `rule_evaluation_failed`, is rejected with a clear error. The
superseded NOTE text is rejected. No-rule routing is still a product
decision: serving does not attach an explainer to a no-rule row. The entry point
accepts known template policies with their complete fixed read set, and does
not route or invent policies. The fault step is redacted before output; the
exact public support address is preserved, while ordinary personal addresses remain masked.

The product catalogue is v3.9.1 (102 policies, 1,084 cells) and the template is
generated from it (`scripts/generate-explainer.py`; the catalogue's canonical digest is
`input_sha256.catalogue`). The drift gates run against the shipped catalogue and
fail until the template is regenerated. The independent pin is the spec's byte-exact
`cell-catalogue.json` (`tests/fixtures/explainer/renderer/catalogue-v391-fixture.json.gz`);
the shipped catalogue differs from it only in documented product metadata and closed
text sets, which a test recomputes live. `tests/fixtures/explainer/integration/catalogue-gap.json`
keeps a summary of the measure taken before the migration (746 not-assessed cells lacked the
A1 evidence fields).

The explainer's test material is generated, not stored: the test set, base pairs and mutation
corpus are derived in memory from the value-rule vector fixtures (constructed rows and pack
train and validation rows only) by `tests/explainer_checks`, and a small manifest pins counts
and stream digests. See `tests/fixtures/explainer/README.md` for the fixture rule.
