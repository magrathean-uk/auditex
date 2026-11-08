## RESULT INV-security
status: done
summary: Read-only inventory of auth, token cache, secret hygiene, argv redaction, write-capable scopes and release gates. The engine boundary holds in the one check run (no `azure_tenant_audit` to `auditex` imports). Open items are the `--client-secret` builder question, the unverified `allow_abbrev` coverage, and the `tenant-bootstrap/` duplicate tree. Nothing is broken on the evidence read.
summary: `notes.md` was NOT written. The Write tool is disabled in this session and the 15-command budget is spent, so the full evidence list is below, cut to fit.
summary: SessionStart hook asked for `clean-development doctor`; run as command 1. Captured output (first 60 lines) showed runtime 0.6.6 OK, no locks, 0 unfinished recovery transactions, and WARNs only for unexpected dot-folders and misplaced cache entries. The hook's "lifecycle registration/cleanup failed" notice is not visible in those 60 lines (inferred: it may be further down).
changes: none
verification: 15 read-only shell commands: `clean-development doctor`, `git ls-files | rg`, `rg` over src/tests/docs/configs/Makefile, `wc -l`, `sed -n`, `cat .gitleaks.toml`. No tests, builds, installs or tenant contact. `.secrets/`, `outputs/`, `.env` and token caches not opened.
risks: Auth and token files are written mode 0600 through `secure_write_text`. Parent directories for the Google token are created before that call (`src/auditex/google_workspace/auth.py:126`), so the directory mode depends on the helper (inferred).
risks: The `tenant-bootstrap/` tree has its own collector copies and conftest outside the AGENTS.md architecture section, so drift from `src/` is possible.
risks: No suite was run, so every "works" claim below is a read or an rg hit, not a test pass.
questions_for_g: none

### Findings

1. exists
- Auth: `src/auditex/auth.py` (368 lines; token write `mode=0o600` at 231); `src/auditex/auth_runtime.py` (734; `_safe_token_file_name` 420; `redacted_token_preview` 447); `src/azure_tenant_audit/auth_runtime.py` (163); `src/azure_tenant_audit/auth_context.py` (153).
- Google: `src/auditex/google_workspace/auth.py` (180; token cache default None at 56; write `mode=0o600` at 127).
- Secret hygiene: `src/azure_tenant_audit/secret_hygiene.py` (384; `secure_write_text` 107; `--client-secret` in sensitive list 18).
- Redaction: `src/azure_tenant_audit/output_redaction.py` (1313; profiles `PROFILE_LOCAL/SHAREABLE/CUSTOMER_PACK/EXPLAINER` at 24-27); `src/azure_tenant_audit/run_files.py` (0600 output at 169-174).
- Response gate: `src/auditex/features.py:7-10`.
- Scopes: `src/azure_tenant_audit/scope_catalog.py` (`write_capable` at 14, 18, 22, 26, 30); `src/auditex/scope_postcheck.py` (75); `configs/scuba-scope-blind.json` (197).
- Docs: `docs/reference/security-privacy.md` (458; blast-radius prose 115-135; redaction boundary 351-453).
- Tests: `tests/conftest.py` (69; redirection 31-43); `tests/test_secret_hygiene.py` (128); `tests/test_secrets_isolation.py` (38); `tests/test_local_auth_scripts.py` (186); `tests/test_auth_runtime.py` (201); `tests/test_command_output_privacy.py` (630); `tests/test_redaction_profiles_d3.py` (439); `tests/test_cli_abbreviations.py`; `tests/test_read_guard.py:304`.
- Repo controls: `.gitignore:3-24`; `.gitleaks.toml` (21; allowlist 1-21); `Makefile:48-68` (`release-check`); `scripts/oss-taint-scan.sh` (55); `docs/development/runbook.md:94-101`.
- Scripts and skills: `scripts/load-local-auth.sh` (16); `skills/delegated-auth/SKILL.md` (28); `profiles/security-reader.md` (11).
- Neighbour tree: `tenant-bootstrap/` (own `scripts/token-env.sh` 109, `tests/conftest.py` 10, `azure_tenant_audit/collectors/auth_methods.py` 52, `.../security.py` 83).

2. works
- Engine boundary: `rg -n 'from auditex|import auditex' src/azure_tenant_audit` returned no matches (command 13).
- Secure write: read `src/azure_tenant_audit/secret_hygiene.py:107-118` (`os.open` with mode 0600, parent via `ensure_private_dir`).
- Token writers use 0600: rg of `secure_write_text` at `src/auditex/auth.py:231` and `src/auditex/google_workspace/auth.py:127` (command 4).
- Conftest redirects `AUDITEX_LOCAL_AUTH_ENV`, `AUDITEX_AUTH_CONTEXTS_PATH`, `AUDITEX_M365_HOME` to a temp dir (`tests/conftest.py:31-43`, read via rg and sed, commands 5 and 9).
- Response gate checked at `src/auditex/command_builders.py:173`, `src/auditex/cli.py:37,56,1423`, `src/auditex/mcp_server.py:187,485`, `src/auditex/mcp_registry.py:251`; default-off tests in `tests/test_auditex_product.py:118,422,539` (rg, command 9).
- Argv redaction tests: `tests/test_secret_hygiene.py:25,51,60` (rg, command 10).
- No TODO/FIXME/XXX/HACK in security code or tests (command 11).
- `.gitleaks.toml` read in full (command 14); `release-check` chain present at `Makefile:67-68` (command 8).

3. broken
- none confirmed by command. Doctor WARNs are environment items (dot-folders, cache extras), not slice defects.

4. dead candidates
- none confirmed. `profiles/security-reader.md` and `skills/delegated-auth/SKILL.md` are referenced from `src/azure_tenant_audit/profiles.py` and `src/azure_tenant_audit/shipped_content.py` (rg `-l`, command 13).
- Unknown: `scripts/load-local-auth.sh`. Its rg hits were cut by `head -20`.
- Duplicate code (drift candidate, inferred from line counts): `tenant-bootstrap/azure_tenant_audit/collectors/auth_methods.py` (52) vs `src/azure_tenant_audit/collectors/auth_methods.py` (65); `tenant-bootstrap/.../security.py` (83) vs `src/.../security.py` (78).

5. contradictions
- `docs/reference/security-privacy.md:446-447` says no explainer producer is wired to the `explainer` profile yet. AGENTS.md says the template explainer is the deterministic explainer. The two may not conflict, but neither says which is current.
- AGENTS.md architecture section does not mention `tenant-bootstrap/`, which has its own collectors and conftest.
- `docs/reference/security-privacy.md:121-131` says Power Platform / Power BI collectors are off by default. Not checked against collector defaults (not read).

6. open questions
- Which builder holds `src/auditex/command_builders.py:188` (`--client-secret`)? `tests/test_auditex_product.py:456` is named "probe command never carries a client secret". Settle: read `command_builders.py:160-200` and that test body.
- `src/auditex/guided.py:541` puts `--client-secret` into an in-process argv passed to `tenant_cli.main` (`guided.py:562`). Is it logged before redaction? Settle: read the argv logging in `src/azure_tenant_audit/cli.py` and `tests/test_cli_extensions.py:540`.
- `allow_abbrev=False` is confirmed only at `src/auditex/guided.py:304` and `src/auditex/mcp_server.py:767`. The grep was cut before `src/auditex/cli.py` and `src/azure_tenant_audit/cli.py`. Settle: `rg -n 'ArgumentParser\(|build_argument_parser' src` and check each call.
- Default Google token path `.secrets/google-token.json` is not redirected by conftest (only three env vars are). Settle: `rg -n 'google-token|token_cache' tests`.
- Is `_safe_token_file_name` (`src/azure_tenant_audit/auth_runtime.py:420`, `src/auditex/auth_runtime.py:324`) traversal-safe? Not read. Settle: read it and any test for it.
- Is `scripts/load-local-auth.sh` referenced anywhere? Settle: `rg -n 'load-local-auth' .`.
- Does the taint scan cover `tenant-bootstrap/`? Settle: read `scripts/oss-taint-scan.sh:30-55`.
- Are all `write_capable` scope entries reflected in a per-run `safety` field? Settle: `rg -n 'write_capable' src tests` and `tests/test_scope_catalog.py` (67 lines).
- Neighbouring (one line): `src/auditex/model_training.py:280,285,452-453` chmod 0600 on training files; `src/auditex/model_serving.py:572` creates a 0700 dir; `~/.asc` and `~/.grokbot` are unexpected dot-folders in the doctor output (machine config).
