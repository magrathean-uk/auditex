## RESULT M00-T01
status: partial
summary:
- Gate suite not run. The load rule blocked it: 15:20 GMT load 13.43 on 12 cores (15:21: 13.23), and another project's `cargo test --lib terrain_cache` (pid 29063) is running. Per the brief I reported partial without running, and did not poll.
- Precondition holds: T02 bb50c0a, T03 b702d8a and T05 f0ae2a7 are ancestors of main 726feed, which is the worktree HEAD.
- Inventory done by reading only. No gate has pass, fail or pytest counts.
- Re-run once load is below 12 and no other heavy job is running. The gate chain is listed in notes.md.
changes: none tracked; appended a "Run 2" section to `.plan/work/M00-T01/notes.md` (the earlier HEAD 9f7b391 section is kept).
verification:
- `uptime`, `sysctl -n hw.ncpu`, anchored `pgrep`: load evidence, pass.
- `git merge-base --is-ancestor` for bb50c0a, b702d8a, f0ae2a7, 82d7ca5 against HEAD: all pass.
- `command -v uv gitleaks`: both present (uv 0.13.7, gitleaks 8.30.1).
- Not run (load rule): `make release-check`, `make audit-deps`, `make dist`, `scripts/release-smoke.sh`, `scripts/check-reproducible-build.py`.
- Not run (brief): `clean-development doctor`.
risks:
- The gate chain is unverified on 726feed; no evidence either way that it passes.
- `release-check` (Makefile:78-85) does not include dist, audit-deps, release-smoke or the reproducible-build check; the milestone verify line (.plan/milestones/M00-foundation.md:40) runs all of them.
- The SessionStart hook reports clean-development lifecycle registration/cleanup failed. The brief forbids `doctor`, so I did not run it; G to decide.
questions_for_g:
- none

### Findings
1. exists
- Makefile:48-49 `AUDIT_DEPS_DIR`, `AUDIT_DEPS_IGNORE`; Makefile:57-75 `audit-deps`.
- Makefile:78-85 `release-check` (lint, test, contract-smoke, release-archive, `generate-rule-packs.py --check`, `oss-taint-scan.sh`, gitleaks).
- Makefile:88-101 `release-archive`, TMPDIR-safe via `${TMPDIR:-/tmp}`; Makefile:104-118 `dist`.
- scripts/release-smoke.sh (76 lines by Read); scripts/check-reproducible-build.py (72 lines by Read).
- pyproject.toml:18-49 extras `mcp` (22), `test` (27), `google` (31), `model_train` (37), `dev` (48); pip-audit at pyproject.toml:49.
- .clean-development.json:6-12 (buildDirs build, dist; depDirs .venv); .gitignore:8-9 (build/, dist/).
- docs/development/runbook.md:98-102 documents the targets and scripts.
2. works
- Precondition commits are ancestors of HEAD (command in verification).
- release-check step order in Makefile:78-85 matches runbook.md:102 (read).
- release-smoke.sh and check-reproducible-build.py match the T05 description on reading: wheel and sdist in base, google and mcp venvs (release-smoke.sh:37-74); two builds with SOURCE_DATE_EPOCH, compared by wheel sha256 and sorted sdist members (check-reproducible-build.py:44, 55, 63-67).
- Extras declared (pyproject.toml, Grep of `name = [` lines) are exactly the five that Makefile:65 loops over, plus aarch64 at Makefile:66.
- uv and gitleaks are on PATH (command check above).
- Not verified by execution: any gate target.
3. broken
- none confirmed (nothing executed).
- Referenced but absent: scripts/audit-deps-ignore.json (named at Makefile:49). Makefile:69 tolerates absence, and the milestone only requires it if an advisory is accepted (.plan/milestones/M00-foundation.md:57). Benign by design.
4. dead candidates
- none identified. No repo-wide rg was run (brief limit). Slice scripts are referenced from Makefile and runbook.md:98-101.
5. contradictions
- none between runbook.md:98-102 and the Makefile.
- Scope gap, not a text contradiction: AGENTS.md's checks table says a release change needs `make release-check` (AGENTS.md, "Checks by changed surface"), while the milestone DoD lists dist, audit-deps, release-smoke and reproducible build separately (.plan/milestones/M00-foundation.md:18-22).
6. open questions
- Does the gate chain pass on 726feed? Settled by running it once load is below 12 and no other heavy job runs: `uptime`, then the five commands in order (lines 3-7 of notes.md).
- Does `make dist` need setuptools in the Makefile's `$(PYTHON)`? Settled by running `make dist` (Makefile:113-114 import setuptools.build_meta).
- Does release-smoke.sh find the right `python` on PATH? It calls bare `python` (release-smoke.sh:27, 30, 40). Settled by running the smoke script.
- Neighbouring area: the earlier notes section (HEAD 9f7b391) and other `.plan/work/M00-T01/` files (`job`, `job-1..3`, `raw.json`, `stderr.txt`) are from a previous attempt; not inspected further.
