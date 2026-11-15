## RESULT CHK-M09-T02
status: done
summary:
check: pass
checked: cbfedfb244fe67dd5ce915c73cc3dadb926ac10c
Verify exit 0 on this head; `git status --porcelain` was empty afterwards. All 94 negative cases failed as they must, with sockets blocked and no network attempts. The repair-round-1 checks hold: the lab script's dry run redacts all four certificate options, and the script reads the repository `configs/`.
changes: none (git-ignored `outputs/` and a `.venv` link exist in the worktree; scratch folder removed; evidence at .plan/work/CHK-M09-T02/evidence.md)
verification:
- `make lint && .venv/bin/python -m pytest -q tests/test_certificate_auth.py tests/test_single_sign_in.py tests/test_cli.py tests/test_cli_abbreviations.py tests/test_secret_cli_matrix.py tests/test_secret_hygiene.py tests/test_probe.py tests/test_http_verb_allowlist.py && make contract-smoke && grep -qx 'engine-certificate-only: yes' .plan/work/M09-T02/result.md` (PYTHONPATH=worktree src): exit 0, pass
- Engine CLI with each removed flag in spaced, `=value`, abbreviated and malformed forms; missing client ID, tenant ID, certificate path or thumbprint; garbage, mode 644, missing and in-output keys; env secret with no certificate; offline with certificate; two password sources (27 cases): exit 2, no run folder, no value echoed, pass
- `tenant-bootstrap/scripts/run-audit-collector.sh` removed options (exit 1), missing arguments and two password sources (exit 2), unknown flag (exit 1) (11 cases): pass
- Lab script dry run with canary values (path, thumbprint, password env, password file): no canary printed, pass. A fake Python boundary showed the real values still reach the executed argv.
- Lab script through the real engine with a garbage key and a mode 644 key (exit 2, no `FileNotFoundError`), and a copy with a config removed (no `--config` printed): pass
- Python API refusals (31 cases): AuthConfig, GraphClient, probe (removed credentials and modes, key problems, two password sources) and response with a saved auth context: pass
- Teams, Exchange session and SharePoint admin collectors with no certificate, 0 requests (3 cases), and the SharePoint token-fit check refusing 6 bad tokens (delegated, secret-minted, Graph audience, empty, garbage): pass
- Exchange connect given a user principal name (3 cases) and argv redaction values for `--client-secret`, `--access-token` and the four certificate options (8 cases): pass
- One-edit mutations of the new tests in a `git archive` copy: 25 of 26 failed as they must (pytest exit 1); M07d was not caught, pytest exit 0 (see risks). The unmutated control over the same files exited 0.
- `tenant-bootstrap/tests/test_remaining_population_gaps.py` and `test_audit_cli_profiles.py`: exit 0. `git diff --check main...HEAD`: exit 0.
risks:
- No test covers the guard `certificate options apply only to live runs` (src/azure_tenant_audit/cli.py:1166). Deleting it passes every test I ran. Main has the same gap under the older wording. The real input is refused (exit 2), so I did not count this against the check.
- The linked `.venv` resolves `azure_tenant_audit` to the main checkout's source. I ran with `PYTHONPATH=<worktree>/src`; without it `make contract-smoke` would test main, not this head.
- The verify ran without a socket block (its tests are offline fixtures); only my negative cases ran with sockets blocked.
questions_for_g: none
### Findings
- C01-C08e removed flags, all forms: expected refusal naming the certificate way (or "invalid arguments" for abbreviations); actual exit 2, no folder, canary not echoed.
- C09-C13 missing client ID, tenant ID, certificate path, thumbprint or any credential: expected exit 2 before any folder; actual exit 2.
- C14, C15, C17, C18 garbage key, mode 644, missing file, key inside the output folder: expected fixed-text refusal; actual exit 2, no key path echoed.
- C19 env secret and token, no certificate: expected no sign-in; actual "Ignoring" warning and exit 2.
- C20 offline run with certificate options: expected refusal; actual "certificate options apply only to live runs", exit 2.
- C21 two password sources: expected refusal; actual exit 2 ("invalid arguments").
- L01-L08 lab script: removed options exit 1, missing arguments and two password sources exit 2, unknown flag exit 1; no output folder.
- D1-D3 lab dry run: all four canaries redacted; real values stay in the executed argv; `--config` and `--permission-hints` point at the repository `configs/`.
- W1-W3 lab wrapper: bad keys refused by the real engine, config path resolves, a missing config disables the full-audit branch.
- P01-P12 Python API: AuthConfig, GraphClient, probe and response refused as required. Probe blockers were `missing_app_credentials`, `certificate_key_unreadable`, `certificate_file_refused` and `certificate_source_in_output`; two password sources gave `certificate_password_unavailable`. No key path in any bundle, no folder for the removed credentials and modes.
- Q01-Q04 collectors: no certificate means skip with 0 requests; every non-certificate token refused.
- E01 Exchange connect with a user principal name: empty prelude or no `-UserPrincipalName`; R01 redaction: values hidden in spaced and `=` forms.
- M01-M19 mutations (26 edits incl. variants): 25 caught. Not caught: M07d. Output: `pytest_exit=0 | ACCEPTED-OR-ERROR` (all tests passed with the offline-certificate guard disabled).
