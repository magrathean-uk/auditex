## RESULT INV-gws
status: done
summary: Google Workspace provider lives in src/auditex/google_workspace/ (about 5.5k lines, 10 collectors, 56 google.* rule IDs). Scope sets and the read-only pattern match the admin guide. It does not answer SCuBA GWS baselines; its findings map to internal 2SV, identity, Gmail, Drive, group and calendar controls. Tests were not run; syntax parse is clean.
changes: none (evidence written to .plan/work/INV-gws/notes.md)
verification: `python3 -I -c` ast.parse over 7 package modules and 4 tests: 11 parsed, 0 failed (pass). `rg` mutating-verb sweep over the package: no discovery write calls (pass). `rg` TODO/FIXME sweep: none (pass). `clean-development doctor`: first 40 lines ok, 5 WARN unexpected dot-folders in ~ (outside slice), lifecycle line not seen because output was truncated. Test suites: not run (brief).
risks: No executed test evidence for the Google suites (about 4.5k lines of tests). The SCuBA-to-Google mapping premise in the brief is unsupported by the repo. SessionStart hook reported a clean-development lifecycle registration failure; doctor did not show it in the part I read, so it still needs checking.
questions_for_g: Should the Google path be described as answering SCuBA GWS baselines, or as an internal control map? AGENTS.md currently says SCuBA answers come only from value_rules, which covers M365 only.

### Findings

1. exists
- src/auditex/google_workspace/__init__.py (11 lines)
- src/auditex/google_workspace/auth.py (180): DEFAULT_GOOGLE_SCOPES at L12-25 (13 scopes); POLICIES_SCOPE L31; ISOLATED_GOOGLE_SCOPES L32; GMAIL_SETTINGS_SCOPES L33-36; build_google_credentials L92; user_delegated_credentials L133
- src/auditex/google_workspace/client.py (419): read methods L169-390 (list_directory, list_report_activities, list_alerts, get_gmail_settings_for_user, list_drive_files, list_policies, list_devices, and others)
- src/auditex/google_workspace/collectors.py (923): 10 collector classes L164-850; STREAM_SAMPLE_LIMIT L26; MAILBOX_FANOUT_LIMIT L44; REGISTRY L894; PRESETS follow it
- src/auditex/google_workspace/normalize.py (761): build_google_normalized_snapshot L223
- src/auditex/google_workspace/findings.py (2280): 29 top-level functions; 56 distinct google.* rule IDs; _GOOGLE_BASELINE_CONTROLS L96; _SURFACE_LABELS L852
- src/auditex/google_workspace/run.py (972): GoogleRunConfig L70; scopes_for_collectors L109; build_google_toolchain_readiness L256; run_google_offline L463; run_google_live L585; google_doctor L671; run_google_probe L876
- Tests: tests/test_google_workspace.py (2311), tests/test_google_parity.py (1670, 68 tests), tests/test_google_collection_gaps.py (329), tests/test_google_device_posture.py (201)
- Docs: docs/guides/admin-permission-guide.md L186-214; docs/guides/setup-guide.md L124
- Outside references: src/auditex/cli.py, mcp_server.py, reporting.py, command_builders.py, mcp_registry.py, setup_guide.py, explorer.py, rules.py

2. works
- Syntax parse of 11 Google modules and tests (`python3 -I -c` ast.parse): pass
- Scope parity: docs/guides/admin-permission-guide.md:190 equals auth.py:12-25 plus auth.py:31 (14 scopes; manual comparison)
- Per-collector scopes at collectors.py L339, L376, L404, L526, L568, L599, L688, L734, L798 match docs L190 and L198 (manual comparison; the Directory list at L167 was only partly read)
- Gmail user token narrowed to gmail.settings.basic and .sharing: auth.py:33-36 matches admin-permission-guide.md:214
- Mailbox fanout cap 500: collectors.py:44 matches admin-permission-guide.md:209
- Read-only: rg for insert/update/patch/delete/batchUpdate/trash/move/set/modify/send/create/put/post( over the package matches only dict `.update(` (normalize.py:32, findings.py:630, run.py:58)

3. broken
- none found; no test run, no missing referenced file in the paths checked

4. dead candidates
- build_google_toolchain_readiness (run.py:256): rg matches only run.py; its call site is unconfirmed
- No TODO/FIXME/XXX/HACK/deprecated in the package (rg, empty)
- No stale directories seen

5. contradictions
- AGENTS.md says SCuBA answers come only from src/azure_tenant_audit/value_rules/ and configs/scuba-value-rules.json. No Google hits in value_rules, so the Google path sits outside that rule.
- No "GWS." SCuBA baseline ID in findings.py or configs/*.json (rg: 0). Inferred: the Google provider does not answer SCuBA GWS baselines.
- admin-permission-guide.md:193 says a missing policy scope yields a partial run with google.collector_issue and org policy reported as "unknown". Isolation is at auth.py:29-32 and collectors.py:568; collector_issue at findings.py:961-971. The "unknown" outcome was not traced.

6. open questions
- Who calls build_google_toolchain_readiness? `rg -n "build_google_toolchain_readiness" src/auditex/google_workspace/run.py`
- Do Directory scopes at collectors.py:167-185 equal DEFAULT_GOOGLE_SCOPES? `sed -n 167,185p src/auditex/google_workspace/collectors.py`
- Are SCuBA Google baselines claimed in docs or configs? `rg -n -i scuba docs/ configs/framework-catalog.json`
- Do the Google suites pass? Not run; needs your approval for a suite run in this slice.
- Does the 2SV "unknown" outcome hold? Trace findings.py L961-971 and collectors.py L565-595.
- Neighbouring area: cli.py, mcp_server.py and reporting.py carry Google wiring that this slice did not inventory.
