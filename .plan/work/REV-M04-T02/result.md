## RESULT REV-M04-T02
status: done
summary:
verdict: changes-required
reviewed: 6e866b331a91d7f1c9537a95abc75c0827eaef9b
All three round-2 cases are fixed, with planted regressions.
All three new reviewed rows contain fixed read-only commands on main: no tenant writes or content reads.
Multiple literal assignments are scanned together, but omitted import bindings and callable-name shortcuts leave three silent bypasses.
changes: none
verification: PASS `git diff --check main...HEAD`; clean worktree.
PASS 757 direct test invocations using in-memory temporary files; all 757 still pass with the three bypasses planted through an in-memory source overlay.
PASS mocked execution confirms each bypass reaches a launcher with `Set-Mailbox x`; scanner violations, unresolved inputs and untraceable launches are all empty.
PASS runtime read guard for all 29 Exchange and 9 Purview command texts; relevant source files match main; Google 28-method pin unchanged.
NOT RUNNABLE `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_read_guard_content_cmdlets.py`: worktree interpreter absent; existing main interpreter fails because the sandbox has no writable temporary directory.
risks: Documented M04-T03 limits are non-blocking and remain for the privacy reference. Full pytest execution remains outstanding. Required `clean-development doctor` failed on a dead/unverifiable lifecycle-lock owner; no repair attempted.
questions_for_g: none
### Findings

1. tests/test_read_boundaries.py:560 - Read-only hand-off exemptions trust the callee name.
Plant `def info(argv): argv[2] = "Set-Mailbox x"`; pass a literal read-only argv to `info(argv)`, then `subprocess.run(argv)`. The mutation is silently ignored.
Fix: prove the exempt callable's identity or analyse its parameters; otherwise mark the hand-off unresolved. Add this regression.

2. tests/test_read_boundaries.py:972 - Transparent conversions also trust the callee name.
Plant `def list(x): return "pwsh -Command Set-Mailbox x"` followed by `os.system(list("pwsh -Command Get-Date"))`. The resolver scans the harmless argument instead of the actual return value.
Fix: establish the builtin/wrapper identity before treating a call as transparent; analyse shadowing functions or fail closed. Add this regression.

3. tests/test_read_boundaries.py:877 - Finding an assignment binding returns before considering import bindings.
Plant helper `DANGER = "pwsh -Command Set-Mailbox x"`; inside `f`, assign harmless literal `cmd`, then `from planted_helper import DANGER as cmd`, then `os.system(cmd)`. Only the harmless assignment is scanned.
Fix: include every applicable import binding in the union, or mark mixed import/assignment bindings unresolved. Add this regression before accepting “every binding proved literal”.
