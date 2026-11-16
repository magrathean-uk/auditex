## RESULT M09-T02
status: done
summary: Repair round 1 (review-1.md). Item 1 fixed: run-audit-collector.sh now passes the repository-level configs/ paths, kept separate from the src/ engine root. The new test runs the real engine with a throwaway certificate and blocked sockets: it loads both configs, writes a run manifest with mode "app" and stops at sign-in.
Item 2 fixed: the dry run prints <redacted> for --certificate-path, --certificate-thumbprint, --certificate-password-env and --certificate-password-file, with a canary assertion for each. The real values reach only the executed argv, which the tests check through a fake Python boundary.
Item 3: resolved by the lead (DEC-109 addendum), no change. Item 4 fixed: removed the trailing blank line in tests/test_review_v3_run_level.py; git diff --check main...HEAD is clean.
All earlier criteria remain met (result.md, marker engine-certificate-only: yes).
changes: tenant-bootstrap/scripts/run-audit-collector.sh, tenant-bootstrap/tests/test_audit_cli_profiles.py, CHANGELOG.md, tests/test_review_v3_run_level.py, .plan/work/M09-T02/result.md (commits b96605a, d041187, e937a27, cbfedfb)
verification: verify line `make lint && .venv/bin/python -m pytest -q tests/test_certificate_auth.py ... tests/test_http_verb_allowlist.py && make contract-smoke && grep -qx 'engine-certificate-only: yes' .plan/work/M09-T02/result.md` on head cbfedfb with PYTHONPATH=worktree src: pass, exit 0 (log .plan/work/M09-T02/verify-2.log). It ran directly because hostload deferred it with both slots busy (exit 75); it is not a heavy command and took about a minute for the reviewer.
make lint: "All checks passed!". `.venv/bin/python -m pytest -q tenant-bootstrap/tests`: pass. `gitleaks git --log-opts=main..HEAD`: no leaks. `git diff --check main...HEAD`: clean.
Negative cases on the unfixed script: config test failed with "assert PosixPath('.../src/configs/collector-definitions.json') == .../configs/collector-definitions.json"; live test failed with "FileNotFoundError: [Errno 2] No such file or directory: '.../src/configs/collector-definitions.json'"; redaction test failed with "assert 'canary-key-path-q7' not in 'Audit dry r...'".
Taking each option out of the redaction list in turn fails its own canary: thumbprint "assert 'CCCC...7' not in", password env "assert 'CANARY_PASSWORD_ENV_Q7' not in", password file "assert 'canary-pass...-file-q7.txt' not in", path "assert 'canary-key-path-q7' not in".
risks: The live wrapper test needs the cryptography package (already an engine dependency) and runs the full engine to the sign-in boundary. The blocked sign-in retries add a few seconds, and every connection attempt is refused and asserted to be login.microsoftonline.com only.
The earlier risks still stand: 40 product tests fail until M09-T03, and D2 (the exchange collector still uses CLI for Microsoft 365) is deferred to T03 under DEC-109.
questions_for_g: none
### Findings
engine-certificate-only: yes
(lead: the repair-round RESULT block dropped the Findings section; the marker stands on REV-M09-T02 approve and CHK-M09-T02 pass at cbfedfb244fe)
