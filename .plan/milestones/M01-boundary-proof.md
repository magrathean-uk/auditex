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
- [ ] Review: terra's M01-T02 inventory assigns every outbound call site under `src/` (HTTP, SDK and subprocess) to one transport class in ARCHITECTURE.md, with no unclassified row: `test -s .plan/work/M01-T02/transport-inventory.md && ! grep -n '| unclassified |' .plan/work/M01-T02/transport-inventory.md`
- [ ] A test fails when any module under `src/` issues a non-GET HTTP request outside the allow-list frozen from that inventory: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py`
- [ ] Tests prove that no collector requests message or file content, every PowerShell cmdlet and Microsoft 365 CLI command that an executable command site in `src/` or `configs/` can issue is on a read allow-list (wrapper verbs only at their known wrapper sites), and every Google API call is a read method under read-only scopes: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_api_observed_ledger.py tests/test_exchange_protection.py tests/test_pack_integrity_and_permissions.py`
- [x] Every parser flag that can carry a secret is in its redaction set and has an abbreviation and a redaction test: `.venv/bin/python -m pytest tests/test_secret_cli_matrix.py tests/test_cli_abbreviations.py tests/test_vendored_cli_abbreviations.py` (evidence: merge.sh verify passed for M01-T01, squash 27759ed; REV-M01-T01 approve at f6ffc78, sol for a Codex author)
- [x] MCP read-only annotations and credential wording in docs match the registry: `.venv/bin/python -m pytest tests/test_mcp_registry.py` (evidence: merge.sh verify for M01-T05 passed, squash c02a0d1; REV-M01-T05 codex approve at 1e25c95)
- [x] Review: shipped `examples/model_development/` rows are classified and none is a held-out or sealed evaluation row, or G has ruled on them `test -s .plan/work/M01-T06/result.md` (evidence: M01-T06 luna classification, 48 synthetic rows, none held-out; M01-T06-check terra pass incl. build-model-examples.py --check)
- [ ] Review: for each of M01-T01, M01-T03 and M01-T04 the review says `verdict: approve`, ran on the other vendor from the author (launcher in each `dispatch.txt`), and the squash commit on `main` carries `Plan-Review: REV-<id> approve <reviewed sha>`, so the approval binds to the reviewed head, not the squash commit: `for t in M01-T01 M01-T03 M01-T04; do r=.plan/work/REV-$t; s=$(sed -n 's/^reviewed: *\([0-9a-f]\{12\}\).*/\1/p' $r/result.md | head -1); grep -qx 'verdict: approve' $r/result.md && [ "$(sed -n 's/^launcher: \([a-z]*\).*/\1/p' $r/dispatch.txt)" != "$(sed -n 's/^launcher: \([a-z]*\).*/\1/p' .plan/work/$t/dispatch.txt)" ] && git log main --format=%B --grep="Plan-Task: $t" | grep -q "Plan-Review: REV-$t approve $s" || { echo "$t"; exit 1; }; done`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M01-T01 | Close secret-flag redaction gaps across all parsers | codex | M | cross-cutting | done |
| M01-T02 | Inventory and classify every outbound call site in src | terra | M | - | todo |
| M01-T03 | Enforce the frozen HTTP allow-list with a test | codex | M | - | todo |
| M01-T04 | Prove the content-read, cmdlet and Google read boundaries | codex | M | - | todo |
| M01-T05 | Align MCP and privacy docs with the registry | terra | S | - | done |
| M01-T06 | Classify shipped model-development example rows | luna | S | - | done |

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
