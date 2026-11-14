## RESULT CHK-M08-T01
status: done
summary: check: pass
checked: 785f613fdf82fd1406ece8aef73809b870ebda01
The verify line exited 0 (1692 tests passed, lint clean, contract smoke ran through). 40 independent guard cases (`.plan/work/CHK-M08-T01/chk_guards.py`) also passed, and the diff has no tenant write or content read.
changes: none (worktree untouched apart from a git-ignored `.venv` link; notes and evidence are in `.plan/work/CHK-M08-T01/`)
verification: verify line in the heavy slot, after queueing behind two other jobs: pass (exit 0, log in `.plan/work/CHK-M08-T01/verify.log`); `chk_guards.py` (40 cases, throwaway keys, mocked token endpoint, no network): pass
risks: none
questions_for_g: none

### Findings
1. Verify line: pass. The pytest part ran 1692 tests with no failures, `make lint` printed "All checks passed!", and `make contract-smoke` finished with exit 0.
2a. PEM, encrypted PEM and PFX each mint through msal with the password from an environment variable or a file; the assertion is signed and verified against the certificate. Only `client_credentials` grants are sent, the token is cached, and the password variable is removed from the environment once read.
2b. A certificate together with a secret, access token, `--interactive` or `--use-azure-cli-token` is refused in `AuthConfig`, in argv parsing and in `run_live`, before any request. No run folder was created and no secret value reached the output. An `AZURE_CLIENT_SECRET` set in the environment is ignored with a warning, not refused.
2c. The abbreviations `--certificate-pa`, `--cert`, `--certificate-th`, `--certificate-password-e`, `--certificate-password-f` and `--certificate-p` are refused in the engine, guided and `auditex` parsers. The supplied value was never echoed. Redaction: in end-to-end certificate runs (PEM, PFX with password variable, PEM with password file) the bundle command line records `***redacted***` for the path, thumbprint and password source. No key text, path, password, variable name or thumbprint appeared in any bundle file, log or stderr.
2d. Errors: a vendor exception and an OAuth error description carrying key text, a path and the password never reached an error, event or log. A wrong password, wrong thumbprint, missing password variable, missing file, group-readable key, key over 64 KiB and symlinked key were each refused with fixed text. The credential refuses repr, pickle and deepcopy.
2e. A secret-only end-to-end run recorded `teams_token_unavailable` and never requested the Teams scope. Delegated selection (interactive, azure_cli, access_token) drops `teams_policy`; an explicit `--collectors` still selects it.
2f. 14 source-in-output cases were refused before `AuditWriter` was built, with the folder listing and file bytes unchanged. They cover a key, password file or PFX inside the output folder; a key or password named `summary.json` in the resume folder; a hard link; a symlink; a symlinked `--out`; `..` and case spellings; and a relative `--out`. The control with the key beside the output folder passed the guard.
2g. An app-only certificate run made zero interactive token calls: no PublicClientApplication, device flow, browser or subprocess (az or m365), only `client_credentials` token calls (DEC-065). All HTTP in the run was GET, and the Graph and Teams scopes were minted from the certificate.
3. Diff read: `src/` adds no non-GET HTTP, no message or file content read and no file writes. The only new token call is msal `acquire_token_for_client`, which is allow-listed (DEC-062). The Teams reads are five GETs of policy settings.
