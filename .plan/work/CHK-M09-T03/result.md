## RESULT CHK-M09-T03
status: done
summary:
check: pass
checked: 3bfb17418fd7c9787b097ca7333d069c83b9ea21
Verify exit 0: lint clean, 230 tests passed, contract-smoke and the result grep passed. 227 negative cases failed as they must (95 CLI and script, 105 Python API, 27 guard mutations), none accepted; two survivors are explained under Findings. Every run set PYTHONPATH to the worktree src because the linked .venv installs main's src.
changes: none
verification:
- make lint && pytest (8 files) && make contract-smoke && grep -qx 'product-certificate-only: yes' .plan/work/M09-T03/result.md: exit 0, pass
- scripts/tenant-audit-full, bootstrap-local-tools.sh, tenant-bootstrap/scripts/run-audit-collector.sh, removed scripts, `make -n login`, `auditex` (auth, run, probe live, guided-run, setup-guide, response run) and `azure_tenant_audit` negatives: 95 commands, each exit 1 or 2 (127 for a removed script), canary never echoed, pass
- Python API negatives (command builders, specs, flow_plan, setup guide, removed_auth_flag, removed modules, MCP tools and path confinement, m365 adapter, exchange collector): 105 cases, all refused, pass
- Mutations on a git-archive copy of HEAD (M01-M29 plus reruns M15b, M24b, M25b, M26b, M27b): 27 guard failures as they must, pass; M11/M11b and M18 survived (see Findings)
risks:
- No test covers the no-echo message in `scripts/bootstrap-local-tools.sh`; the script does refuse and not echo, but a regression would pass the suite.
- `docs/reference/security-privacy.md` is changed by T03 but is not in the task's `files:` list.
- `git status --porcelain` is empty after the verify; `outputs/` from contract-smoke is git-ignored.
questions_for_g: none
### Findings
Full per-case lines and output are in `.plan/work/CHK-M09-T03/evidence.md`.
- tenant-audit-full removed options (--client-secret, --access-token, --use-azure-cli-token, --interactive, --include-exchange, --reauth, --m365-app-id, also `=value`): expected refusal naming the option; actual exit 1, value not echoed.
- tenant-audit-full `--opt=VALUE`, unknown or positional argument, option missing its value, and missing tenant, client id, key or thumbprint: expected refusal; actual exit 1 or 2, argument shown only by position.
- tenant-audit-full live run with a missing key file, a mode 644 key file and a malformed thumbprint: expected engine refusal; actual exit 2, certificate error. The first missing-key run failed only because system python3 lacks `requests`, so I reran it with the venv python3 first on PATH.
- tenant-audit-full `--dry-run` with a real-looking key path, thumbprint and password name: expected none shown; actual exit 0, all three redacted.
- `auditex auth` (bare, status, login, import-token, inspect-token, contexts, list): expected refusal; actual exit 2 with the removal message and nothing created.
- Removed flags (--client-secret, --access-token, --auth-context, --use-azure-cli-token, --interactive, --scopes, --browser-command; `=` form, abbreviated, space-joined) on `run`, `probe live`, `guided-run`, `setup-guide m365` and the engine: expected refusal; actual exit 2, canary absent.
- `probe live`: `--mode delegated`, two password sources and an abbreviated flag exit 2. With no certificate it exits 1 and records blocker `missing_app_credentials`, with no tenant call.
- `guided-run`: unknown flows, a missing or "organizations" tenant, missing client id or key, two password sources, and a missing key file all exit 2.
- Builders, specs, `flow_plan`, setup guide and MCP tools (empty certificate, paths outside the MCP root, removed keyword arguments, removed tool names): expected ValueError, TypeError, McpPathError or a blocked status; actual as expected.
- m365 adapter: write commands, `rm -rf /`, control characters and chained commands are refused with `command.refused` logged and no process started; allowed reads return `command_not_found` with no process. The exchange collector starts no process and records 7 named skips.
- Static guards (az login, m365 login, auth env file, recreated login script and Makefile target, azure-cli install, PSGallery trust, script refusals, MCP token parameter, removed tool, builder certificate and mode, flow fallback, adapter guard, collector process, setup-guide gaps and empty selection, agent prompt, conftest redirect): each failed as it must.
- Survivors: M11/M11b is the bootstrap gap above, and M18 (builder accepts two certificate password sources) is unchanged code from cbfedfb. M15, M24, M25, M26 and M27 first survived because my mutation was misplaced or redundant; the reruns failed as they must.
- Outside the diff, not counted: `setup-guide m365 --auditor-profile <unknown>` exits 0 (the `get_profile` fallback is the same on main), and an empty selection there ends in an uncaught ValueError traceback, as on main.
