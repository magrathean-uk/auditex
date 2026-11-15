# M09 removal map (read-only investigation at a979cbc, 15 Nov 2026)
Line numbers are from a979cbc and may drift. Test bodies were classified by name, not read. Rulings on D1-D6 are DEC-108.

## 1. Engine auth (src/azure_tenant_audit/)
- auth_runtime.py:28-103 acquire_azure_cli_access_token: REMOVE. :105-140 capture_signed_in_context (/me, directory roles): REMOVE. :142-171 inspect_access_token, build_auth_context_payload: KEEP (every run writes normalized/auth_context.json).
- config.py:22-23,26 client_secret, access_token, interactive_scopes: REMOVE. :11-14 MIXED_CREDENTIALS_MESSAGE: reword. :37-48 check_single_credential: simplify, KEEP.
- graph.py:397-408 ensure_token: drop access-token, interactive and _app_token fallbacks; keep cert branch. :410-457 app_token_for: secret POST :426-457 REMOVE; cert branch :417-423 and Teams/SharePoint None returns KEEP. :459-519 _certificate_token, _certificate_exchange: KEEP. :521-566 _app_token: REMOVE. :568-673 interactive helpers, delegated_token_for, signed_in_username: REMOVE. :299-303 _public_app, _interactive_lock, interactive_prompts: REMOVE. :323-328 secret masking goes with _app_token. :675-683 token_claims: KEEP.
- certificate_auth.py: KEEP.
- cli.py: :18-40 imports trim; :164-175 _other_credential_selected trim; :707-712 saved-context load REMOVE; :796-823 az token and interactive fallback REMOVE; :815-860 source checks and auth_mode rewrite cert-only; :862-876 session-context and access-token claims REMOVE; :877-883 saved context REMOVE.
- run.py:56-57 auth_mode derivation, :92-96 interactive scopes, :98-110 non-app notice: REMOVE.
- selection.py:18,29-32 auth_mode filter: dead (callers run.py:86,104, setup_guide.py:277).
- profiles.py:5-8 APP_MODE_ONLY_COLLECTORS dead; :16 delegated_role_hints; supported_probe_modes at :53,110,134,152,164,181,245 drop "delegated"; :58-60,113 global-reader text rewrite.
- probe.py:47 SUPPORTED_PROBE_MODES; :66-70 access_token, use_azure_cli_token, auth_context, client_secret fields REMOVE; certificate fields ADD; :605-662 delegated/azure_cli/access_token branch REMOVE; :679-706 app branch KEEP cert-only; :295-330 m365_cli_auth toolchain row.
- auth_context.py:32-46, :112-152 REMOVE; :66-110 inspect_token_claims KEEP.
- response.py:9,65,151-175 saved-context lookup REMOVE.
- collectors/exchange_policy.py:157-163 delegated branch REMOVE; :183-200 _compliance_session cert gate KEEP.
- collectors/sharepoint_admin.py:86,95-98 second-sign-in reason text, :351-362 interactive and secret branches, :407-447 delegated token REMOVE; :434-440 app path and token_fits KEEP.
- collectors/sharepoint_access.py:97 auth_mode == "app" predicate: cert check.
- collectors/teams_policy.py:92-104 comments only.
- adapters/capabilities.py:14-37 supported_auth_modes trim; adapters/powershell_graph.py delegated Exchange connect branch (about :213-260, unverified) REMOVE.
- Microsoft 365 CLI candidates: collectors/exchange.py, collectors/exchange_defender_commands.py, adapters/m365_cli.py, adapters/m365dsc.py, m365_home.py, adapters/read_guard.py:476-497 (keep parsers for replay).

## 2. CLI flags and redaction
- Engine cli.py build_parser :178-302: REMOVE --client-secret (184), --access-token (204), --auth-context (205), --use-azure-cli-token (206-210), --interactive (213), --scopes (214), --browser-command (215). KEEP --authority, --graph-scope, certificate options (185-203).
- auditex probe live (src/auditex/cli.py:216-240): --mode app only; REMOVE --access-token, --auth-context, --use-azure-cli-token, --client-secret; KEEP --client-id; ADD certificate flags.
- auditex auth (cli.py:247-285): status, list, use, export-env, login, import-token, inspect-token, capability.
- auditex response run --auth-context (cli.py:445) REMOVE; setup-guide m365 --mode (:499) app only; guided-run (guided.py:359-400) REMOVE --auth-mode, --client-secret, --browser-command, --local-mode, --skip-login-check; KEEP certificate flags.
- Redaction lists KEEP every entry: secret_hygiene.py:27-46, auth_runtime.py:18-21, response.py:20, command_runner.py:17-31.
- Pinned inventories: tests/test_secret_cli_matrix.py:20-40, tests/test_cli_abbreviations.py:242-280, tests/test_vendored_cli_abbreviations.py:93.
- command_builders.py: AuditRunCommandSpec :48-51,72-73,105-111 and ProbeCommandSpec :187-218 REMOVE fields; certificate builder :67-98 KEEP.

## 3. Product layer
- guided.py: REMOVE _run_azure_login :160-171, _offer_m365_setup :174-190, m365 helpers :245-275, _ensure_m365_login :276-346, _run_ga_setup_flow :403-482, delegated Exchange helpers :133-157, saved-secret write :221-244, delegated branches in run_guided :503-520,580-600,606-616,630-649,670-680. KEEP _certificate_argv :349-357, ProgressRenderer, app argv :618-641.
- operator_flow.py REWRITE (gr-audit, ga-setup-app go); tests/test_operator_flow.py, README.md:80-91, docs/development/runbook.md:43.
- setup_guide.py build_m365_setup_guide :254-491 (mode, delegated steps, client-secret commands to certificate, sign-in notice); render_setup_guide_markdown :547-548.
- auth.py :114-204, :240-293, :294-378 REMOVE; local auth env :24-112 (D4).
- auth_runtime.py (product) ProductAuthRuntime :183-420 REMOVE; build_doctor_report :652+ and adapters :41-150 mostly REMOVE.
- bootstrap.py :91-96, :120-123, :190-203 az REMOVE.
- mcp_server.py: REMOVE auth tools :875-885 and helpers :285-350; REWRITE auditex_run_delegated_audit :943-966, build_cli_command :362-396, build_probe_command :451-483, auditex_probe_live :1085-1111, response auth_context :1189,1209, setup_guide mode :887-925. mcp_registry.py :70-89, :109-115; output_writers.py:202; demo.py:453.
- Scripts: scripts/tenant-audit-login (whole), scripts/tenant-audit-full (:41-72, :154, :180-192), scripts/bootstrap-local-tools.sh (:108-116, :237), Makefile:24-31 login; scripts/load-local-auth.sh, scripts/m365-home.sh.
- Config: configs/tenant-audit.example.env:3-4; configs/collector-permissions.json:237 delegated key, notes :218,298; configs/collector-presets.json:22.
- agent/tenant-audit-skill.json entries :27, :58, :110, :148, :159, :205, :227; agent/agent-prompt.md:19.

## 4. Docs, skills, shipped content
- docs/guides/setup-guide.md :5-20,60-80,160-192,193-243; admin-permission-guide.md REMOVE :135-175, :359-381, EDIT :18-19,106-134,176-205,221-232,321-327, KEEP :206-220,336-358; product-manual.md :9,60-100,401-410; troubleshooting.md :36-45.
- docs/development/runbook.md :28-35,43,161; docs/reference/security-privacy.md :112,150,170-173,342-344; api-call-catalog.md :88,230,294; output-contract.md :676.
- README.md :25,80-108,162; profiles global-reader, security-reader, intune-reader, exchange-reader, app-readonly-full.
- skills/delegated-auth/ DELETE (shipped_content.py:69-72, pyproject data-files); skills/auditex-operator/SKILL.md:16, skills/app-readonly-escalation/SKILL.md:3,8,23 REWRITE. CHANGELOG entry.

## 5. Tests
- Remove whole: tests/test_auth_runtime.py, tests/test_auth_namespace.py (except :211 if the env file stays), tests/test_m365_home.py, tests/test_local_auth_scripts.py.
- Engine: test_single_sign_in.py remove :183,204,216,252,262,273,425,435,452, keep static guards :334-352 (update :342); test_certificate_auth.py rewrite :448,464,494, keep :135-411,442-480; test_cli.py remove :116,868,908,1181, rewrite :218,284,473,526,1526, keep :1241,1419-1498; test_http_verb_allowlist.py:165-171; test_architecture_modules.py:25,134-158.
- Product: test_cli_extensions.py remove :289,323,440,534,566,615,658, rewrite :224-276,362,490,734,836; test_auditex_product.py remove :290,329,361,394,528,541,601,617,672,2085, rewrite :509, keep :458; test_command_builders.py remove :46,67; test_probe.py remove :216,241, rewrite :289,362; test_setup_guide.py rewrite :194,231,240,271,284, keep :298; test_mcp_paths.py:205-210; test_mcp_registry.py:13,62; test_mcp_offline_operator_inputs.py:167.
- Others: test_ipps_session.py remove :187,325; test_teams_admin_rest.py:887; test_teams_policy_collector.py:310; test_sharepoint_admin_collector.py remove :200,230,239,249,298, rewrite :188; test_sharepoint_admin_guard.py:164,173; test_exchange_session.py:101; test_review_v3_run_level.py:575; test_first_collection_graph_fixes.py:225; test_command_output_privacy.py:249; test_response.py:112,176; test_key_guard_swaps.py:397; test_secrets_isolation.py:23.

## 6. What breaks
- Shared with the cert path: GraphClient.app_token_for (power_bi.py:26, power_platform.py:44, exchange_policy.py:157, teams_policy.py:104, sharepoint_admin.py:436); auth_context.inspect_token_claims and sanitize_token_claims; build_auth_context_payload; CERTIFICATE_ARG_FLAGS.
- Bundle: run-manifest.json mode required (contracts.py _REQUIRED_FIELDS, run.py:542); normalized/auth_context.json auth_mode (contracts.py:88, run_bundle.py:244-248, tenant_identity.py:96). Keep with constant app; replay accepts old values.
- Reason codes kept for old bundles: teams_token_unavailable, sharepoint_admin_second_sign_in_required, sharepoint_admin_certificate_required, ipps_session_not_opened.
- tenant-bootstrap/scripts/run-audit-collector.sh:20-22,87-88,171-177, run-bootstrap-azurecli.sh, tenant-bootstrap/tests/test_audit_cli_profiles.py.
- api_inventory.py:398-431 and read_guard.py m365 parser: keep for replay.

## Size
Engine about 18 files, 800 lines; product about 11 files, 1,300 lines; scripts and config 6 files, 400 lines; docs about 20 files; tests about 30 files touched, 4 removed whole.
