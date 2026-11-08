---
id: M01
name: boundary-proof
weight: 30
status: planned
---
# M01 boundary-proof
Tier A milestone: M01-T01, M01-T03 and M01-T04 each get an independent review from the other provider at a frozen head. The parked model layer is classified here, never developed or removed.

## Goal
The AGENTS.md boundaries that 1.3.0 promises are proven by tests on `main`: every outbound call site is classified against the transport policy in ARCHITECTURE.md, no request outside that policy can reach a tenant or a third party, no collector reads message or file content, PowerShell and Google calls are read-only, no secret appears in argv, logs or diagnostics, MCP annotations and credential wording match the registry, and no forbidden evaluation rows ship.

## Definition of Done
- [x] Review: terra's M01-T02 inventory assigns every outbound call site under `src/` (HTTP, SDK and subprocess) to one transport class in ARCHITECTURE.md, with no unclassified row: `test -s .plan/work/M01-T02/transport-inventory.md && ! grep -n '| unclassified |' .plan/work/M01-T02/transport-inventory.md` (evidence: REV-M01-T02 round 4, Codex: every classification finding fixed, section E complete and minimal, no unclassified row; section G completeness moved to M01-T04 by DEC-007)
- [x] A test fails when any module under `src/` issues a non-GET HTTP request outside the allow-list frozen from that inventory: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py` (evidence: merge.sh verify for M01-T03 passed, squash 49c2b75; REV-M01-T03 Codex approve at 798a49c after the DEC-011 bounded round)
- [ ] Tests prove that no collector requests message or file content, every PowerShell cmdlet and Microsoft 365 CLI command that an executable command site in `src/` or `configs/` can issue is on a read allow-list (wrapper verbs only at their known wrapper sites), and every Google API call is a read method under read-only scopes: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py`
- [x] Every parser flag that can carry a secret is in its redaction set and has an abbreviation and a redaction test: `.venv/bin/python -m pytest tests/test_secret_cli_matrix.py tests/test_cli_abbreviations.py tests/test_vendored_cli_abbreviations.py` (evidence: merge.sh verify passed for M01-T01, squash 27759ed; REV-M01-T01 approve at f6ffc78, sol for a Codex author)
- [x] MCP read-only annotations and credential wording in docs match the registry: `.venv/bin/python -m pytest tests/test_mcp_registry.py` (evidence: merge.sh verify for M01-T05 passed, squash c02a0d1; REV-M01-T05 codex approve at 1e25c95)
- [x] Review: shipped `examples/model_development/` rows are classified and none is a held-out or sealed evaluation row, or G has ruled on them `test -s .plan/work/M01-T06/result.md` (evidence: M01-T06 luna classification, 48 synthetic rows, none held-out; M01-T06-check terra pass incl. build-model-examples.py --check)
- [ ] Review: for each of M01-T01, M01-T03 and M01-T04 the review says `verdict: approve`, ran on the other vendor from the author (launcher in each `dispatch.txt`), and the squash commit on `main` carries `Plan-Review: REV-<id> approve <reviewed sha>`, so the approval binds to the reviewed head, not the squash commit: `for t in M01-T01 M01-T03 M01-T04; do r=.plan/work/REV-$t; s=$(sed -n 's/^reviewed: *\([0-9a-f]\{12\}\).*/\1/p' $r/result.md | head -1); grep -qx 'verdict: approve' $r/result.md && [ "$(sed -n 's/^launcher: \([a-z]*\).*/\1/p' $r/dispatch.txt)" != "$(sed -n 's/^launcher: \([a-z]*\).*/\1/p' .plan/work/$t/dispatch.txt)" ] && git log main --format=%B --grep="Plan-Task: $t" | grep -q "Plan-Review: REV-$t approve $s" || { echo "$t"; exit 1; }; done`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M01-T01 | Close secret-flag redaction gaps across all parsers | codex | M | cross-cutting | done |
| M01-T02 | Inventory and classify every outbound call site in src | terra | M | - | done |
| M01-T03 | Enforce the frozen HTTP allow-list with a test | codex | M | - | done |
| M01-T04 | Prove the content-read, cmdlet and Google read boundaries | codex | M | - | done |
| M01-T05 | Align MCP and privacy docs with the registry | terra | S | - | done |
| M01-T06 | Classify shipped model-development example rows | luna | S | - | done |
| M01-T07 | Add Gmail settings fields masks (G1, G2, G5) | codex | S | tier-a | todo |
| M01-T08 | Stop collecting ApplyHtmlDisclaimerText (G6) | terra | S | tier-a | todo |
| M01-T09 | Add fields masks to alerts.list and groups.get (G8, G9) | codex | S | tier-a | todo |
| M01-T10 | Strip the Intune custom-profile payload after receipt (G10) | terra | S | tier-a | todo |
| M01-T11 | Drop the unused gmail.settings.sharing scope | terra | S | tier-a | todo |
| M01-T12 | Make the runtime read guard refuse content cmdlets | codex | M | tier-a | todo |

## Acceptance criteria
### M01-T01 Close secret-flag redaction gaps across all parsers
- Inventories every argparse flag in `src/auditex/cli.py`, `guided.py`, `demo.py`, `mcp_server.py`, `google_workspace/` and the engine `cli.py` and `argument_parser.py` that can carry a secret value or a path to a secret file, and states in `.plan/work/M01-T01/inventory.md` which redaction set covers it.
- Each uncovered flag is added to the right set (`command_runner.SENSITIVE_ARGS`, the Google `run._SENSITIVE_COMMAND_FLAGS`, or the engine sets `secret_hygiene.SENSITIVE_ARG_FLAGS` and `auth_runtime.SENSITIVE_CLI_ARGS`); `tests/test_secret_cli_matrix.py` gains one parametrised case per flag covering the full flag, an abbreviation and the `=value` form.
- `guided.py` never logs, prints or writes an argv that contains `--client-secret` unredacted; a test drives the guided app flow with a sentinel secret and asserts it is absent from stdout, stderr and every written file.
- `command_builders.build_probe_command` and `test_build_probe_command_never_carries_a_client_secret` (`tests/test_auditex_product.py`) agree: either the builder never emits `--client-secret` for probe commands, or the test name and docstring state what it does prove.
- verify: `.venv/bin/python -m pytest tests/test_secret_cli_matrix.py tests/test_cli_abbreviations.py tests/test_vendored_cli_abbreviations.py tests/test_command_builders.py tests/test_auditex_product.py`
- files: `src/auditex/command_runner.py`, `src/auditex/guided.py`, `src/auditex/command_builders.py`, `src/auditex/google_workspace/run.py`, `src/azure_tenant_audit/secret_hygiene.py`, `src/azure_tenant_audit/auth_runtime.py`, `tests/test_secret_cli_matrix.py`, `tests/test_auditex_product.py`, `.plan/work/M01-T01/inventory.md`

### M01-T02 Inventory and classify every outbound call site in src
- Lists every outbound call site under `src/` with file:line, library, method or verb, destination and gate: `requests` and `Session` calls, `urllib` `Request`, Graph `$batch`, `google.auth` token refresh and Google API client calls, and every `subprocess` launch (PowerShell, CLI logins, probe, local system tools).
- Assigns each row exactly one transport class from ARCHITECTURE.md Interfaces; the known non-GET sites are classified explicitly: `graph.py` token and `$batch` POSTs, `notify.py` Teams and Slack webhook, Jira issue and GitHub issue POSTs (operator-configured sinks), `model_serving.py` chat-completions POST (parked model endpoint, loopback default), and the Power Platform `client.request` path.
- A site that fits no class is marked `unclassified` and goes to sol (and G when it is a product question) before M01-T03 starts; the parked model layer is classified only, no code change.
- Changes no repository file; the orchestrator records the frozen allow-list as an auto DECISIONS.md entry before M01-T03 is dispatched.
- verify: `test -s .plan/work/M01-T02/transport-inventory.md && ! grep -n '| unclassified |' .plan/work/M01-T02/transport-inventory.md`
- files: `.plan/work/M01-T02/transport-inventory.md` (read-only)

### M01-T03 Enforce the frozen HTTP allow-list with a test
- Runs after M01-T02 and its DECISIONS.md entry; the allow-list is that inventory, nothing wider.
- A new test statically enumerates every HTTP call site under `src/` (`requests`, `Session` methods, `urllib`, Graph `$batch`) and fails on any method other than GET unless the call site is in the allow-list kept in the test with its transport class and reason per entry; a new non-GET call site fails the test until it is classified.
- A runtime test confirms the read guard refuses a non-GET Graph request and a `$batch` carrying a non-GET sub-request.
- The `graph.py` read-guard comment names every allowed method and endpoint class.
- verify: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py`
- files: `tests/test_http_verb_allowlist.py`, `src/azure_tenant_audit/graph.py` (comment only unless a guard gap is found), `tests/test_read_guard.py`

### M01-T04 Prove the content-read, cmdlet and Google read boundaries
- Runs after M01-T02 (it uses the subprocess and SDK rows); files disjoint from M01-T03, so the two may run in parallel.
- `tests/test_read_boundaries.py` runs the `api_inventory` content classifier over every endpoint in `configs/collector-definitions.json` and every endpoint literal under `src/azure_tenant_audit/collectors/` and `adapters/`, and fails on any message, mail, file or attachment content read outside `_CONTENT_EXEMPT_PREFIXES`.
- It scans executable command sites only (command strings, command lists and config command fields that can reach a runner) in `src/` and `configs/`, and explicitly excludes non-executable mentions such as docstrings, comments and documentation strings (for example `src/azure_tenant_audit/adapters/read_guard.py:95`). The commands found split into two sets. Trusted wrapper operations (exactly `Import-Module`, `Connect-ExchangeOnline` and `Invoke-Expression`) are accepted only from a closed, test-local table keyed by file and purpose: the Exchange connect preamble in `adapters/powershell_graph.py`, the module-version guard in `adapters/m365dsc.py` that reaches `PowerShellGraphAdapter.run` as a `read_guard.VettedCommand` whose `vetted_text` passes the guard, and the module availability probe in `probe.py`; a wrapper verb at any other executable command site fails. Every other token is an audited command and must be on the `api_inventory` read allow-list, which gains no wrapper verb, and a test asserts `read_guard.check_command` still refuses each wrapper verb submitted as an ordinary command. It also checks that every Microsoft 365 CLI command the collector definitions can issue passes `adapters/read_guard.check_command` while a write verb is refused.
- It enumerates the Google API calls in `src/auditex/google_workspace/` and fails on any method other than a read (`list`, `get` and equivalents) or any requested scope that is not read-only or explicitly metadata-only.
- A gap in `api_inventory.py` classification is fixed there; a gap elsewhere in `src/` is reported in `result.md` as a new task, not fixed here.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_inventory.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py`
- files: `tests/test_read_boundaries.py`, `src/azure_tenant_audit/api_inventory.py` (only on a classifier gap)

### M01-T05 Align MCP and privacy docs with the registry
- `docs/reference/security-privacy.md` lists the MCP tools whose `read_only_hint` is false and why (local writes, gated response tools), replacing "Read-only annotations are unchanged".
- The credential wording in `docs/reference/security-privacy.md` and the `McpToolEntry` docstring says that Google tools take confined paths to credential files, not secret values, if that is what the registry does; otherwise the registry is the source and the gap is reported.
- A test in `tests/test_mcp_registry.py` asserts the set of tools with `read_only_hint` false equals the set the doc lists.
- verify: `.venv/bin/python -m pytest tests/test_mcp_registry.py tests/test_mcp_paths.py`
- files: `docs/reference/security-privacy.md`, `src/auditex/mcp_registry.py` (docstring only), `tests/test_mcp_registry.py`

### M01-T06 Classify shipped model-development example rows
- For each file in `examples/model_development/`, `result.md` records row count, `split` values, `provenance` values and whether any row is real, held-out, sealed or derived from a held-out set, with evidence.
- Changes nothing; any removal goes to G through the deletion gate and a CLEANUP entry.
- verify: `git diff --quiet -- examples/model_development && test -s .plan/work/M01-T06/result.md`
- files: `.plan/work/M01-T06/result.md` (read-only)

### M01-T07 Add Gmail settings fields masks (G1, G2, G5)
- Dependencies: M01-T04 merged.
- `settings.getVacation` (`client.py:300`) requests a `fields` mask that excludes `responseSubject`, `responseBodyPlainText` and `responseBodyHtml`; `settings.sendAs.list` (`:297`) requests `sendAs(...)` without `signature`; `settings.filters.list` (`:290`) requests `filter(id,action,criteria(...))` without `criteria.query`, `negatedQuery` and `subject`. Each mask lists only fields that `google_workspace/normalize.py` or `findings.py` read.
- A test calls each method through a fake service and asserts the `fields` argument is present and contains none of the excluded names, so a reverted mask fails.
- `minimise_gmail_settings` and `minimise_user_text` stay as defence in depth; `test_discarded_gmail_text_never_leaves_the_collector` still passes.
- `_TEXT_EXPOSURES` rows G1, G2 and G5 in `tests/test_read_boundaries.py` change to "removed at request level".
- The normalised Gmail output (including the derived `...Length` and `has...` flags) is byte-identical to before on the existing fixtures.
- Amended by DEC-012: excluded text no longer feeds live output, so the length fields derived from it are dropped; presence stays only where a non-text field reports it; offline fixtures and the contract are updated to match; if a value rule reads a dropped field, stop and report under questions_for_g.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_data_minimisation.py tests/test_google_parity.py`
- files: `src/auditex/google_workspace/client.py`, `tests/test_google_workspace.py`, `tests/test_read_boundaries.py`

### M01-T08 Stop collecting ApplyHtmlDisclaimerText (G6)
- Dependencies: M01-T04 merged.
- `ApplyHtmlDisclaimerText` is removed from the `Get-TransportRule | Select-Object` list in both `collectors/exchange_policy.py:126` and `configs/collector-definitions.json` (same text in both), from `normalize.py:2107` (`apply_html_disclaimer_text`), from the field set in `scuba_adapters_exchange.py:38`, and from `docs/reference/api-call-catalog.md:172`; `PrependSubject` is kept (G7).
- No SCuBA verdict changes: rule and vector tests, `scripts/generate-rule-packs.py` and the rule-pack drift test show no diff.
- Existing fixtures that carry the field (`tests/test_scuba_adapters_exchange.py:225`, `tests/test_enterprise_depth_collectors.py:758`, `tests/test_exchange_policy_scuba_inputs.py:20`, `examples/demo_tenant/*.json`) are updated, and a test asserts the shipped command text no longer contains `ApplyHtmlDisclaimerText`.
- `_TEXT_EXPOSURES` row G6 changes to "removed at request level"; G7 is unchanged.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_exchange_policy_scuba_inputs.py tests/test_scuba_adapters_exchange.py tests/test_enterprise_depth_collectors.py tests/test_exchange_collector.py tests/test_read_guard.py && .venv/bin/python scripts/generate-rule-packs.py && git diff --quiet -- configs/scuba-value-rules.json && make contract-smoke`
- files: `src/azure_tenant_audit/collectors/exchange_policy.py`, `configs/collector-definitions.json`, `src/azure_tenant_audit/normalize.py`, `src/auditex/scuba_adapters_exchange.py`, `docs/reference/api-call-catalog.md`, `examples/demo_tenant/demo_tenant.json`, `examples/demo_tenant/demo_tenant_remediated.json`, `tests/test_exchange_policy_scuba_inputs.py`, `tests/test_scuba_adapters_exchange.py`, `tests/test_enterprise_depth_collectors.py`, `tests/test_read_boundaries.py`

### M01-T09 Add fields masks to alerts.list and groups.get (G8, G9)
- Dependencies: M01-T04 merged; M01-T07 merged first (same `client.py`, same owner).
- `alerts.list` (`client.py:260`) requests `fields=nextPageToken,alerts(alertId,type,source,createTime,startTime,endTime,deleted,customerId,metadata)`, so `data.messages[].messageBodySnippet` and `subjectText` are never received; the mask keeps every field normalisation reads (id, type, severity, status, createTime), and a test with a fake alert carrying a message snippet shows the snippet is absent from the stored raw record.
- Groups Settings `groups.get` (`client.py:340`) requests `fields=` exactly the seven settings read at `normalize.py:571-590`, so `customFooterText` and `defaultMessageDenyNotificationText` are never received; a test asserts the `fields` argument and that every setting the normaliser reads is in it.
- `_TEXT_EXPOSURES` rows G8 and G9 change to "removed at request level".
- Normalised alert and group outputs are unchanged on the existing fixtures.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_google_collection_gaps.py tests/test_google_parity.py`
- files: `src/auditex/google_workspace/client.py`, `tests/test_google_workspace.py`, `tests/test_read_boundaries.py`

### M01-T10 Strip the Intune custom-profile payload after receipt (G10)
- Dependencies: M01-T04 merged; G's answer on G10 (recommendation: yes, keep the read and discard `payload` after receipt). Do not dispatch before that answer is recorded in DECISIONS.md; if G says no, close the task as rejected.
- A new minimiser in `data_minimisation.py` removes `payload` (base64 `.mobileconfig` bytes) from every record of `/deviceManagement/deviceConfigurations` before raw evidence is written, called from `collectors/intune.py:42` and `collectors/intune_depth.py:58`; `payloadName` and `payloadFileName` are kept only if an Intune rule or finding reads them.
- A test feeds an iOS and a macOS custom-profile record carrying a sentinel `payload` through both collectors and asserts the sentinel is absent from raw evidence, normalised output and the written bundle files; the existing Intune rules give identical results on the fixtures.
- `_TEXT_EXPOSURES` row G10 states "discarded after receipt" and names the new minimiser; the read itself stays unchanged (no `$select`, because the collection is polymorphic).
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_data_minimisation.py tests/test_intune_endpoint_collector.py tests/test_collection_coverage_fixes.py && make contract-smoke`
- files: `src/azure_tenant_audit/data_minimisation.py`, `src/azure_tenant_audit/collectors/intune.py`, `src/azure_tenant_audit/collectors/intune_depth.py`, `tests/test_data_minimisation.py`, `tests/test_intune_endpoint_collector.py`, `tests/test_read_boundaries.py`

### M01-T11 Drop the unused gmail.settings.sharing scope
- Dependencies: M01-T04 merged.
- `https://www.googleapis.com/auth/gmail.settings.sharing` is removed from `google_workspace/auth.py` (lines 25 and 37), `google_workspace/collectors.py:406`, `azure_tenant_audit/scope_catalog.py:25` and `_ACCEPTED_WRITE_CAPABLE_SCOPES` in `tests/test_read_boundaries.py`; the `gmail.settings.sharing` mention in the high-risk scope terms at `google_workspace/findings.py:1415` stays, because an operator-granted scope must still be flagged.
- Every Gmail settings read the collector makes (`delegates.list`, `forwardingAddresses.list` and the rest) is shown to be covered by `gmail.settings.basic`, with the Google reference page or method scope list cited in the test or a comment.
- The scope-catalog, setup-guide and troubleshooting docs no longer instruct operators to grant the scope (`docs/guides/admin-permission-guide.md`, `docs/guides/troubleshooting.md`), and a test asserts the scope appears in no requested-scope list under `src/`.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_google_workspace.py tests/test_scope_catalog.py tests/test_setup_guide.py tests/test_google_parity.py`
- files: `src/auditex/google_workspace/auth.py`, `src/auditex/google_workspace/collectors.py`, `src/azure_tenant_audit/scope_catalog.py`, `docs/guides/admin-permission-guide.md`, `docs/guides/troubleshooting.md`, `tests/test_scope_catalog.py`, `tests/test_setup_guide.py`, `tests/test_read_boundaries.py`, `tests/test_google_workspace.py`, `tests/test_google_parity.py` (retired-scope assertions only, DEC-012)

### M01-T12 Make the runtime read guard refuse content cmdlets
- Dependencies: M01-T04 merged; independent of M01-T03 (disjoint files).
- Decision for the implementer: the code is a verb allow-list (`read_guard._allowed_word` accepts every `Get-<noun>`, and `words_are_read` shares it), and the shipped commands use some 50 distinct `Get-*` cmdlets across Exchange, Teams, Microsoft Graph, `Get-Module` and `Get-Command`. A full allow-list would make every new collector edit the guard, so implement an explicit content deny-list in `read_guard.py` applied inside `_allowed_word`, so `check_command`, `words_are_read` and `classify_command` all refuse alike.
- The deny-list refuses at least: `Get-MgUserMessage`, `Get-MgUserMailFolderMessage`, any `Get-Mg*Attachment*`, `Get-MgUserEvent`, `Get-MgDriveItemContent`, `Get-MgUserDriveItemContent`, and the Exchange cmdlets that return message or file content; names are matched case-insensitively and also when written with a module prefix (`Microsoft.Graph.Mail\Get-MgUserMessage`).
- A new `tests/test_read_guard_content_cmdlets.py` asserts each denied cmdlet is refused standalone, after a pipe and inside a wrapper script, that `words_are_read` is false for it, and that every shipped PowerShell command (collected as in `tests/test_read_guard.py::_shipped_powershell_commands`) and `Get-Module`, `Get-Command`, `Get-MessageTrace` and `Get-EXOMailbox` still pass.
- The `read_guard.py` module docstring names the deny-list; `tests/test_read_boundaries.py` is not edited.
- verify: `.venv/bin/python -m pytest tests/test_read_guard_content_cmdlets.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py`
- files: `src/azure_tenant_audit/adapters/read_guard.py`, `tests/test_read_guard_content_cmdlets.py`
