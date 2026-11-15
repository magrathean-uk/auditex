---
id: M09
name: certificate-only
weight: 10
status: active
---
# M09 certificate-only
Plan v4 amendment 11 (DEC-107, G: "Reader app"; DEC-108, the lead's rulings). Auditex audits Microsoft 365 one way only: the app-only reader app with a certificate credential, set up once by the customer's Global Administrator, no sign-in per audit. Every other Microsoft 365 authentication way goes: delegated interactive sign-in, the Azure CLI token mode, the client-secret mode, the access-token and saved-auth-context modes, the guided delegated path (`gr-audit`, `ga-setup-app`), the Microsoft 365 CLI sign-in, and the `auditex auth` token surfaces, with their guides, scripts and tests. Google Workspace authentication is untouched. G also asked (manager, 15 Nov): "reader app: ensure you write down exactly, in document or how to, what permissions it needs so tenant admin will know. be precise." That guide is M09-T01. M09 ends at a release candidate; the release itself waits for G's yes naming the version.

## Order and file ownership
- M09-T01 (the permissions guide, a new file) starts at once and shares no file with T02 or T03. M09-T02 (engine) starts at once. M09-T03 (product layer) starts after M09-T02 merges. M09-T04 (docs, skills, shipped content) starts after M09-T01 and M09-T03 merge. M09-T05 (release candidate) last.
- Each task's `files:` line is its own; a shared file passes on by merge only. The removal map is `.plan/work/M09-map/map.md` (read-only investigation at a979cbc).

## Goal
A customer's tenant admin can set up the reader app from one exact guide; every Auditex Microsoft 365 entry point (both CLIs, guided run, probe, setup guide, MCP tools, scripts) runs with the certificate and nothing else; no code, flag, guide or test for another Microsoft 365 sign-in way remains, except redaction entries and the replay of old bundles; a release candidate passes `make release-check`.

## Definition of Done
- [ ] The reader-app permissions guide lists every permission, role and admin setting the collectors use, matched against the lab app of run m08e3, and the other vendor approves it for exactness: `grep -qx 'permissions-guide: exact' .plan/work/M09-T01/result.md && grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M09-T01/result.md`
- [ ] The engine accepts only the certificate: `grep -qx 'engine-certificate-only: yes' .plan/work/M09-T02/result.md && grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M09-T02/result.md`
- [ ] The product layer accepts only the certificate: `grep -qx 'product-certificate-only: yes' .plan/work/M09-T03/result.md && grep -qE '^[[:space:]]*(summary: )?verdict: approve' .plan/work/REV-M09-T03/result.md`
- [ ] No removed mode survives outside redaction lists, replay code, CHANGELOG history and tenant-bootstrap: ``! git grep -nE -- '--(interactive|use-azure-cli-token|access-token|auth-context|client-secret|browser-command)\b|az login|m365 login|gr-audit|ga-setup-app' -- src docs README.md configs agent skills scripts Makefile ':!src/azure_tenant_audit/secret_hygiene.py' ':!src/azure_tenant_audit/auth_runtime.py' ':!src/azure_tenant_audit/command_runner.py' ':!src/azure_tenant_audit/response.py' | grep -v -i 'replay\|redact'``
- [ ] The release candidate passes: `grep -qx 'release-check: pass' .plan/work/M09-T05/result.md`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M09-T01 | Reader-app permissions guide for the tenant admin, exact | sol | M | hard | done |
| M09-T02 | Engine certificate-only: modes, flags, probe certificate flags, tests | sol | L | risk:high | todo |
| M09-T03 | Product layer certificate-only: guided, setup guide, MCP, auth surfaces, scripts, configs | sol | L | risk:high | todo |
| M09-T04 | Docs, skills, agent files and shipped content for the one way | terra | M | - | todo |
| M09-T05 | Release candidate 1.6.0 (stops before the tag) | terra | S | gate | todo |

## Acceptance criteria
### M09-T01 Reader-app permissions guide for the tenant admin, exact
- Writes `docs/guides/reader-app-permissions.md`, the one guide a customer's tenant admin follows. For every permission: the API exactly as the Entra admin centre names it (Microsoft Graph, Office 365 Exchange Online, Microsoft Exchange Online Protection, Office 365 SharePoint Online, Power BI Service, and any other), the permission name, its type (application), whether it needs admin consent, a one-line reason and the SCuBA policies or collectors that need it. Then everything outside API permissions: the Global Reader directory role on the app's service principal (Exchange, compliance and Teams), `Exchange.ManageAsApp` on each Exchange API, `Sites.FullControl.All` with the statement that Auditex never writes with it and why Microsoft offers no read-only scope, the Power BI and Fabric admin-portal settings for service principals and their security group, the Power Platform management app registration, the certificate (create, upload the public key, keep the private key on the audit machine, expiry), how the admin checks it worked (one `auditex` command and what a good result shows), and how to remove everything after the engagement. States the stolen-key risk.
- Built from the calls the collectors actually make (`configs/collector-permissions.json`, `docs/reference/api-call-catalog.md`, the collector code), and checked against the lab app's working grant: the token claims and coverage of run m08e3 (`normalized/auth_context.json`, coverage and run manifest in the run folder named in `.plan/work/M08-T06/result.md`) and the lab app record in the operator's records folder. Lists every difference between the code's needs and the lab grant, and resolves each (nothing extra, nothing missing). No live tenant call.
- Adds the file to shipped content (`pyproject.toml` data-files and `shipped_content.py`; the parity test passes) and links it from `docs/guides/setup-guide.md` and `docs/guides/admin-permission-guide.md` (one line each; T04 rewrites the rest).
- Writes `permissions-guide: exact`, `permissions-listed: <n>` and `lab-grant-differences: <n> resolved` under `### Findings`.
- verify: `test -s docs/guides/reader-app-permissions.md && .venv/bin/python -m pytest -q tests/test_permission_docs_parity.py tests/test_architecture_modules.py && grep -qx 'permissions-guide: exact' .plan/work/M09-T01/result.md`
- files: `docs/guides/reader-app-permissions.md`, `docs/guides/setup-guide.md` (one link line), `docs/guides/admin-permission-guide.md` (one link line), `pyproject.toml` (data-files line), `src/azure_tenant_audit/shipped_content.py`, `tests/test_permission_docs_parity.py` (new checks for the guide), `tests/test_architecture_modules.py` (shipped-content list only), `.plan/work/M09-T01/result.md`

### M09-T02 Engine certificate-only: modes, flags, probe certificate flags, tests
- In `src/azure_tenant_audit/`: removes the Azure CLI token, interactive (MSAL public client), client-secret and access-token and saved-auth-context paths (auth_runtime, config, graph, cli, run, probe, auth_context, response, collectors exchange_policy, sharepoint_admin, sharepoint_access, adapters capabilities and powershell_graph delegated branches) and their engine CLI flags; the certificate path, `token_claims`, `inspect_token_claims`, `build_auth_context_payload` and every redaction entry stay (DEC-108). `probe` gains the certificate options the audit CLI has, before the secret option goes. The selection-by-auth-mode concept and `APP_MODE_ONLY_COLLECTORS` go. Bundles keep `mode` and `auth_mode` with the constant `app`; validation and replay still accept old bundles with other values. The frozen HTTP allow-list test is edited under DEC-108. Tests of removed modes are removed; certificate, single-sign-in static guards (no interactive call anywhere), abbreviation and redaction tests stay and pass; a test proves each removed flag is refused with a message naming the certificate way.
- `tenant-bootstrap/scripts/run-audit-collector.sh` and its test switch to the certificate options (the lab kit keeps working; DEC-108).
- Tier A: other-vendor review `REV-M09-T02` and an executing check `CHK-M09-T02` at the same head.
- Writes `engine-certificate-only: yes` under `### Findings`.
- verify: `make lint && .venv/bin/python -m pytest -q tests/test_certificate_auth.py tests/test_single_sign_in.py tests/test_cli.py tests/test_cli_abbreviations.py tests/test_secret_cli_matrix.py tests/test_secret_hygiene.py tests/test_probe.py tests/test_http_verb_allowlist.py && make contract-smoke && grep -qx 'engine-certificate-only: yes' .plan/work/M09-T02/result.md`
- files: `src/azure_tenant_audit/**`, `tests/**` (tests of the engine paths named above), `tenant-bootstrap/scripts/run-audit-collector.sh`, `tenant-bootstrap/tests/test_audit_cli_profiles.py`, `CHANGELOG.md`, `.plan/work/M09-T02/result.md`

### M09-T03 Product layer certificate-only: guided, setup guide, MCP, auth surfaces, scripts, configs
- In `src/auditex/`: guided run keeps only the certificate flow (`_run_azure_login`, the Microsoft 365 CLI helpers, `ga-setup-app` and the saved-secret write go); `operator_flow.py` keeps one flow; `setup_guide.py` builds only the reader-app guide with certificate commands and points to `docs/guides/reader-app-permissions.md`; `auditex auth` keeps at most a certificate check (DEC-108) and loses login, import-token, inspect-token, contexts and the Azure CLI and Microsoft 365 CLI status; `auditex probe live` takes the certificate options; the MCP server drops the auth tools and `auditex_run_delegated_audit` (replaced by one certificate run tool), and its probe, run, setup-guide and response tools lose mode, access-token, auth-context and secret parameters; the Microsoft 365 CLI adapter is no longer used for live collection (its parsers stay for replay). Scripts (`tenant-audit-login`, `tenant-audit-full`, `bootstrap-local-tools.sh`, `load-local-auth.sh`, `m365-home.sh`), the Makefile `login` target, `configs/tenant-audit.example.env` secret and token lines, `configs/collector-permissions.json` delegated key and `agent/tenant-audit-skill.json` delegated, token and secret entries go or are rewritten for the certificate. Tests follow; the MCP registry and command-builder tests pass.
- Tier A: other-vendor review `REV-M09-T03` and an executing check `CHK-M09-T03` at the same head.
- Writes `product-certificate-only: yes` under `### Findings`.
- verify: `make lint && .venv/bin/python -m pytest -q tests/test_auditex_product.py tests/test_cli_extensions.py tests/test_setup_guide.py tests/test_mcp_registry.py tests/test_mcp_paths.py tests/test_command_builders.py tests/test_operator_flow.py tests/test_single_sign_in.py && make contract-smoke && grep -qx 'product-certificate-only: yes' .plan/work/M09-T03/result.md`
- files: `src/auditex/**`, `scripts/**`, `Makefile`, `configs/**`, `agent/**`, `tests/**` (tests of the product paths named above), `CHANGELOG.md`, `.plan/work/M09-T03/result.md`

### M09-T04 Docs, skills, agent files and shipped content for the one way
- Rewrites `docs/guides/setup-guide.md`, `docs/guides/admin-permission-guide.md`, `docs/guides/product-manual.md`, `docs/guides/troubleshooting.md`, `docs/development/runbook.md`, `docs/reference/security-privacy.md`, `docs/reference/api-call-catalog.md`, `docs/reference/output-contract.md`, `README.md` and `profiles/*.md` for the certificate reader app only, every permission detail deferring to `reader-app-permissions.md`; deletes `skills/delegated-auth/` and rewrites the other skills that mention delegated sign-in; updates shipped content (both lists; parity test passes). The DoD grep line passes.
- verify: `.venv/bin/python -m pytest -q tests/test_permission_docs_parity.py tests/test_architecture_modules.py && ! git grep -nE -- '--(interactive|use-azure-cli-token|access-token|auth-context|browser-command)\b|az login|m365 login|gr-audit|ga-setup-app' -- docs README.md skills profiles`
- files: `docs/**`, `README.md`, `profiles/**`, `skills/**`, `pyproject.toml` (data-files), `src/azure_tenant_audit/shipped_content.py`, `tests/test_permission_docs_parity.py`, `tests/test_architecture_modules.py` (shipped-content list only), `CHANGELOG.md`, `.plan/work/M09-T04/result.md`

### M09-T05 Release candidate 1.6.0 (stops before the tag)
- Bumps the version to 1.6.0 (M08 and M09 since 1.5.0), finishes the CHANGELOG entry (the one-way change stated first, with the removed modes listed), runs `make release-check` and `make dist`, records the wheel and sdist sha256. No tag, no GitHub release: the lead asks G through the manager, naming 1.6.0.
- verify: `grep -qx 'release-check: pass' .plan/work/M09-T05/result.md`
- files: `pyproject.toml` (version), `src/**/__init__.py` (version string), `CHANGELOG.md`, `.plan/work/M09-T05/result.md`
