## RESULT REV-M04-T02
status: done
summary:
verdict: changes-required
reviewed: fab93a51dcefd1ce3ed3547450c3a436922c7b7f
All three original regressions fail on b7e3438 and pass on this head.
Current-source checks report no content reads or tenant writes; the 28-method Google pin is unchanged.
Three further fail-open cases require repair.
changes: none
verification: PASS `git diff --check main...HEAD`; PASS read-only Python harness: 640 direct test invocations and 27 planted cases. Three additional bypasses reproduced with empty violations, unresolved-input and untraceable-launch results.
Prescribed verify not runnable: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_read_guard_content_cmdlets.py`. Worktree `.venv` is absent; invoking the existing interpreter also fails because the sandbox provides no writable temporary directory.
risks: Full pytest verification remains outstanding. Required `clean-development doctor` failed on a dead/unverifiable lifecycle-lock owner; no repairs attempted.
questions_for_g: none
### Findings

1. tests/test_read_boundaries.py:1197 - Mutated keyword mappings are treated as complete literals. Planting `opts = {}; opts["cmd"] = "pwsh -Command Set-Mailbox x"` before `await asyncio.create_subprocess_shell(**opts)` passes silently. `opts.update(cmd=...)` also bypasses the scan.
Fix: track mapping mutations or mark affected mappings unresolved; add planted regressions for both forms.

2. tests/test_read_boundaries.py:1401 - Importer checks require positional arguments, while origin resolution at line 1126 also ignores keyword arguments. `builtins.__import__(name="subprocess").Popen(["pwsh", "-Command", "Set-Mailbox x"])` passes silently, as does `importlib.import_module(name="subprocess")`.
Fix: resolve the `name=` argument and keyword unpacking, or fail closed on unsupported importer arguments; add planted regressions.

3. tests/test_read_boundaries.py:1266 - The added standard-input scan discards byte literals at line 1299 while retaining complete resolution. `subprocess.run(["pwsh", "-Command", "-"], input=b"Set-Mailbox x")` therefore passes silently.
Fix: scan supported byte-script encodings or mark byte input unresolved; add a planted regression.
