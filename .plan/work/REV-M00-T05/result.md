## RESULT REV-M00-T05
status: done
summary:
verdict: changes-required
reviewed: 1d80d94bddd7f2d29ba4267473efdf9ab411f00b
The smoke script now covers wheel and sdist, and the reproducible-build check passes. The change breaks `tests/test_architecture_modules.py::test_release_smoke_script_covers_base_google_and_mcp_matrix`, and the smoke run itself was not run.
changes: none (evidence at .plan/work/REV-M00-T05/evidence.md)
verification:
- `.venv/bin/python scripts/check-reproducible-build.py`: pass. The two wheels are byte-identical and the two sdists have equal member lists and per-member hashes.
- `pytest tests/test_check_reproducible_build.py tests/test_architecture_modules.py`: FAIL, 1 failure (details below). The new test passes.
- `bash -n` and `shellcheck` on `scripts/release-smoke.sh`: pass (shellcheck raised only the SC1091 info note).
- `make dist && bash scripts/release-smoke.sh ...`: not run. The smoke script creates venvs and pip-installs, which needs network.
risks:
- The smoke script is unexecuted: the sdist `${artifact}[extra]` installs and the six-install matrix are untested, so `merge.sh --verify` is the real gate.
- The author's result.md reports status partial and says verification failed at `make dist`.
questions_for_g: none

### Findings
Criteria:
1. Smoke script installs wheel and sdist for base, google and mcp, with the existing checks on each. Met on reading, but not runnable here. `scripts/release-smoke.sh:37-73`.
2. Smoke default root is under `$TMPDIR`, not a fixed `/tmp`. Met. `scripts/release-smoke.sh:8`, with `mktemp -d` at line 22.
3. Reproducible-build check: two `git archive` exports under `$TMPDIR`, `SOURCE_DATE_EPOCH` set to the commit time, wheel sha256 compared, sdist member list and per-member hashes compared, names and hashes printed. Met. `scripts/check-reproducible-build.py:37-70`, and it ran green.
4. Verify command: the reproducible-build part passes; the smoke and `make dist` parts are not runnable (see risks).
5. Files line: all three changed paths match (`release-smoke.sh`, `check-reproducible-build.py`, `test_check_reproducible_build.py`). No scope creep.
6. DoD item "Wheel and sdist each pass the base, Google and MCP release smoke, and two clean builds ...": not yet closable. The smoke part is unverified.

Required changes:
1. `scripts/release-smoke.sh:55,69` (and the base install at line 39): the existing test `tests/test_architecture_modules.py:272,274` asserts the literal strings `"${WHEEL_PATH}[google]"` and `"${WHEEL_PATH}[mcp]"`. The script now writes `"${artifact}[google]"` and `"${artifact}[mcp]"`, so that test fails; it passes on main.
   - Fix: update `tests/test_architecture_modules.py:269-275` to assert the `${artifact}` forms plus a wheel and sdist loop. Add that file to the task's files line, or amend the brief, since it is currently outside scope.
   - Alternative: keep the literal `${WHEEL_PATH}[...]` strings in the script.
2. Re-run the full verify command, including the smoke script, in an environment with network. Record the result in result.md.

Suggestions (non-blocking):
- `docs/development/runbook.md:101` still shows `/tmp/auditex-release-smoke`. The second argument is now a parent directory, and each run leaves an uncleaned `run.XXXXXX` subdirectory.
- `scripts/check-reproducible-build.py:55`: `os.environ['TMPDIR']` raises KeyError when `TMPDIR` is unset. Fall back to `tempfile.gettempdir()`.
- `scripts/check-reproducible-build.py:41`: `tar.extractall(filter='data')` needs Python 3.11.4 or later, and the project floor is 3.11.
- `scripts/release-smoke.sh:37-76`: the loop body is not indented. Moving the per-install steps into a function would be cleaner.
- `tests/test_check_reproducible_build.py` only covers `sdist_members`, not the wheel comparison.
