## RESULT INV-mcp
status: done
summary: MCP server slice inventoried by reading code only. 34 registry entries, 7 with readOnlyHint false. Response tools are gated behind AUDITEX_ENABLE_RESPONSE at three points. No confirmed broken references or dead code. Nothing was executed beyond inventory commands, so no test status is claimed.
changes: .plan/work/INV-mcp/notes.md (created; outside the repo tree)
verification: rg, awk, sed, ls, wc and git log (read-only); clean-development doctor (diagnostic, tail -40 only). No tests, builds or installs run; no tenant contact.
risks: Audit, probe and Google paths may write to a tenant (unverified); MCP callers may reach mode=response via auditex_probe_live (gate exists, not run); docs wording on read-only annotations.
questions_for_g: none
### Findings
1. exists
- `src/auditex/mcp_server.py` (1165 lines), `src/auditex/mcp_registry.py` (280), `src/auditex/mcp_paths.py` (124), `src/auditex/features.py`, `src/auditex/command_builders.py`, `src/auditex/auth_runtime.py:248-259`.
- Entry point `pyproject.toml:49`. Six MCP test files under `tests/test_mcp_*.py` plus MCP-touching tests in `tests/test_auditex_product.py`, `tests/test_redaction_profiles_d3.py` and others (list in notes).
- Docs: `docs/reference/security-privacy.md:98`, `README.md:161`, `docs/guides/product-manual.md:394`, `docs/guides/troubleshooting.md:31,201`.
2. works
- Registry to handler wiring: `src/auditex/mcp_registry.py:259-268` skips entries with no handler. Read only.
- Response plane off by default: `src/auditex/mcp_registry.py:250-256`, `src/auditex/mcp_server.py:187-189,485-486`, `src/auditex/command_builders.py:173-174`. Read only.
- Argparse `allow_abbrev=False`: `src/auditex/mcp_server.py:766-767`. Read only.
- Startup refuses without a safe root: `src/auditex/mcp_server.py:781-785`. Read only.
- Shareable wrappers redact with PROFILE_SHAREABLE: `src/auditex/mcp_server.py:513-520,577-583`. Read only.
- Referenced files exist: `src/azure_tenant_audit/response.py`, `configs/collector-definitions.json` (`ls`).
- Not run: no test, lint or import command.
3. broken
- none confirmed.
4. dead candidates
- none confirmed. `auditex_auth_use` is live at `src/auditex/mcp_registry.py:78`; `iter_tool_specs` is used at `tests/test_setup_guide.py:11` and `tests/test_scubagear_export.py:1547`.
5. contradictions
- `docs/reference/security-privacy.md:98` says "Read-only annotations are unchanged"; 7 of 34 registry entries have `read_only_hint=False`. Wording risk (inferred).
- `src/auditex/mcp_registry.py:17-24` says no tool takes a secret; `auditex_google_probe` and `auditex_run_google_workspace_audit` accept `service_account_key`, `oauth_client` and `token_cache` paths (`src/auditex/mcp_registry.py:123,130`). Accurate only if credential file paths are not "secrets" (inferred).
- `AGENTS.md:4,32` says MCP audit tools never write to a tenant; six other write-capable hints exist, and tenant-write behaviour of audit paths is unverified (Q1).
6. open questions
- Q1: Do audit, probe or Google paths write to a tenant? Settle by reading `src/azure_tenant_audit/graph.py` read-only enforcement (commit `0f5be30`) and `configs/collector-definitions.json`.
- Q2: Do they read message bodies or file content? A narrow search found only usage-report download-redirect handling (`src/azure_tenant_audit/graph.py:34-84`). Settle with an exhaustive `rg` over `configs` and `src`.
- Q3: Can MCP callers reach `mode="response"`? `src/auditex/mcp_server.py:1034` exposes `mode`; the gate is at `src/auditex/command_builders.py:173`. Settle by running `tests/test_auditex_product.py` (lines 422-438).
- Q4: Does `tool_handlers()` map any `*_raw` function? Settle by reading `src/auditex/mcp_server.py:801` onward.
- Q5: Test status for `tests/test_mcp_*.py` needs a dependency-installed venv; not run here.
- Neighbour: `tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/` is vendored MCP guidance, outside the slice.
