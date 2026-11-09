# PLAN-v3 evidence (committed; cited by the ticked M00 items)

Plan branch parent commit c3740c3. Outside `.plan/` the tree equals the 1.3.0 release commit: `git diff --stat v1.3.0 HEAD -- . ':!.plan'` prints nothing. All checks below ran in the plan worktree during revision round 1, with the main checkout's venv linked in (no install).

## M00 DoD item 5: secrets scan
`gitleaks dir . --no-banner --redact` over the final plan tree before the plan commit: exit 0, no leaks found (repeated at the reset commit 894f6fb in round 0 with the same result).

## M00 DoD item 6: taint scan on the tracked tree
`git archive HEAD | tar -x -C <scratch dir>`, then `bash scripts/oss-taint-scan.sh` there: exit 0.
In the worktree itself the scan exits 1 when `build/audit-deps/` exists (a vendored Pygments file under `build/audit-deps/tool/` trips a marker). That is the git-ignored output of `make audit-deps`, not tracked content, so item 6 stays ticked for the tracked tree and the defect is M00-T02's new criterion and DoD item 8 (unticked).

## M00 DoD item 7: dependency audit
`make audit-deps`: exit 0; "No known vulnerabilities found" for each resolved list (base and every declared extra, including the Linux aarch64 `model_train` list).

## M00 DoD item 9: ownership map
A map checker parses the rows under "## Module ownership map" in `.plan/ARCHITECTURE.md`, expands brace and `**` globs and matches every path from `git ls-tree -r --name-only HEAD` outside `.plan/`.
Result on the revised map: 901 files, 13 modules, 0 non-test files unmatched, 0 files in two modules, 199 `tests/test_*.py` files owned by the import convention. The revision adds only not-yet-existing paths (`scripts/compare-run-outputs.py`, `tests/test_compare_run_outputs.py`) to the packaging-release row.

## Not ticked, and why
- `make lint`, `make test`, `make contract-smoke`, `make release-check`: not run in the plan session (heavy suite, host load high); M00-T01 changes `make lint` and M00-T03 runs the chain after the M00 merges.
- M00 item 8: fails today (`!Review` in `pytest.ini`, `docs/taint` prune, build-output taint failure above).
- Replay kit: an inventory slice reported it with matching hashes, but the plan session did not re-locate it; M01-T02 re-locates and re-verifies all three files before any tick.
- Everything in M01-M06: new work.
