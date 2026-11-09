## RESULT REV-M00-T05
status: done
summary:
verdict: approve
reviewed: 00afb73c95e7a1d18065c67a7372fc59dc90cd92
Both criteria met. Round 1's test regression is fixed at tests/test_architecture_modules.py:272-276. Repro check passes on two clean builds (wheel sha256 identical, sdist members identical). Focused tests pass (36). The release smoke could not run under the brief (needs network), so it relies on the author's green run.
changes: .plan/work/REV-M00-T05/evidence.md (round 2 section appended)
verification:
- `pytest tests/test_check_reproducible_build.py tests/test_architecture_modules.py`: pass, 36 passed
- `<main .venv python> scripts/check-reproducible-build.py`: pass, "reproducible build ok", wheel e062f926...92a3 both builds
- `bash -n scripts/release-smoke.sh`: pass
- `make dist`: not run, because it writes dist/ into the read-only worktree, which has no .venv. The repro script exercises the same build_meta path.
- `bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"`: not runnable here, because the venvs pip-install pip and the extras from the index (network). The author reports it green for wheel and sdist.
risks:
- Release smoke not run independently. `merge.sh --verify` is the gate for it.
- scripts/check-reproducible-build.py:41 uses `extractall(filter='data')`, which needs Python 3.11.4 or later; the project floor is 3.11.
- Every smoke run leaves a run.XXXXXX directory under the smoke parent. docs/development/runbook.md:101 still shows the fixed /tmp path.
questions_for_g: none
### Findings
Criteria:
- Wheel, plus sdist in separate fresh venvs, each for base, google and mcp, running the existing checks: met. See scripts/release-smoke.sh:16-22 and 37-74 (separate `${kind}-base/-google/-mcp` venvs, outputs per kind).
- Default smoke root under $TMPDIR, no fixed /tmp: met, scripts/release-smoke.sh:8 (`${TMPDIR:?}` then mktemp at :22).
- `git archive` of HEAD twice into fresh directories under $TMPDIR: met, scripts/check-reproducible-build.py:37-41 and :55-59.
- SOURCE_DATE_EPOCH set to the commit time: met, scripts/check-reproducible-build.py:54 and :45.
- Wheels byte-identical, sdists compared by sorted members with sha256 per member: met, scripts/check-reproducible-build.py:18-30 and :63-64.
- Prints artefact names and hashes: met, scripts/check-reproducible-build.py:61-62.
- DoD item "Wheel and sdist each pass the base, Google and MCP release smoke...": the repro half was verified here. The smoke half is untestable here (network), so tick it after `merge.sh --verify`.
- Security: no shell interpolation (list argv). The tar extraction uses the data filter. No new dependencies, no secrets. The new script's mode is 755. Clean.
- Scope: tests/test_architecture_modules.py is outside the files line. The change is the minimum needed to keep the existing smoke-matrix test passing, and round 1 asked for it. Explained, so accepted.
Required changes: none.
Non-blocking suggestions:
1. docs/development/runbook.md:101: change /tmp to $TMPDIR and note that the second argument is a parent directory (that file is owned by docs-content).
2. scripts/check-reproducible-build.py:41: guard `filter=` for Python below 3.11.4, or raise the floor.
3. scripts/release-smoke.sh:37-74: indent the loop body.
4. tests/test_check_reproducible_build.py: add a test for the wheel-mismatch path in main().
Full evidence: .plan/work/REV-M00-T05/evidence.md (Round 2)
