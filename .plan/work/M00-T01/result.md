## RESULT M00-T01
status: partial
summary: Gate chain not executed because of the load rule (uptime 14:53, load 12.52/13.99/12.20 on 12 cores; porn, wgex and teslatlas run-jobs live). Worktree HEAD 9f7b391 equals main; T02, T03 and T05 are on main, so the precondition holds. Inventory done by reading and cheap commands only; no pass/fail counts exist yet.
changes: none tracked. Created git-ignored symlink .venv -> .venv in the worktree (per brief, no install). Wrote .plan/work/M00-T01/notes.md.
verification: none run. Shell commands used: clean-development doctor (FAIL on cleanup locks); uptime/pgrep/ps (load and heavy jobs); git log/status/worktree list; rg and sed on Makefile, pyproject.toml, .gitignore, .clean-development.json; ls; reads of scripts/check-reproducible-build.py and scripts/release-smoke.sh.
risks:
- clean-development doctor FAIL "cleanup locks: lifecycle: dead/unverifiable owner; explicit recovery required". Needs G's recovery decision; I did not touch it.
- release-smoke.sh and audit-deps fetch packages from the network; download size not measured.
- Gate chain will be a full test suite (make release-check) plus installs (audit-deps, release-smoke), which conflicts with the Task's "no installs, no full test suites" constraint.
### Findings
1. exists
- Makefile:48-49 AUDIT_DEPS_DIR=build/audit-deps, AUDIT_DEPS_IGNORE=scripts/audit-deps-ignore.json
- Makefile:57-76 audit-deps; Makefile:78-85 release-check; Makefile:88-102 release-archive; Makefile:104-118 dist
- pyproject.toml:46-49 dev extra with pip-audit>=2.9,<3
- scripts/release-smoke.sh (77 lines); scripts/check-reproducible-build.py (73 lines)
- .gitignore:8 build/, .gitignore:9 dist/; .clean-development.json:6-9 buildDirs ["build","dist"], depDirs [".venv"]
- tests/test_check_reproducible_build.py, tests/test_architecture_modules.py, docs/development/runbook.md (rg -l references)
2. works
- main has T02 (bb50c0a), T03 (b702d8a), T05 (f0ae2a7): `git log --oneline main`
- release-check order matches the Makefile:78-85 list (lint, test, contract-smoke, release-archive, rule-pack drift, oss-taint-scan, gitleaks): read
- dist copies wheel and sdist into dist/ after git archive HEAD (Makefile:104-118, esp. 117-118): read
- check-reproducible-build.py matches the T05 criteria on reading (lines 36, 44, 55, 63-67): read
- release-smoke.sh covers wheel and sdist across base, google and mcp venvs, with default parent under TMPDIR (lines 8, 37-74): read
3. broken
- none confirmed; nothing executed
- release-smoke.sh:27-40 uses bare python and python -m pip after venv activation; relies on PATH (inferred, unverified)
4. dead candidates
- none assessed (out of scope for a gate run)
5. contradictions
- none found on reading. AGENTS.md "Checks by changed surface" lists only make release-check for releases; audit-deps and dist are not mentioned (documentation gap)
6. open questions
- Does make audit-deps pass on current pins? Needs network for the advisory DB. Settled by running step 2.
- Are gitleaks and uv on PATH? `command -v gitleaks uv` not run. Settled by steps 1 and 2.
- Does .venv (symlink to a symlink) resolve in the worktree? Settled by step 5 or `.venv/bin/python -c 'import sys'`.
- Neighbouring area: doctor reports 6 repos without .clean-development.json (infra, pentest-local, pentest-local-public-staging, wattex, wgex, wgex-plan). Outside M00-T01.
questions_for_g:
- Approve the recovery for the doctor cleanup-lock FAIL, or should a worker handle it?
- Confirm the gate run may go ahead despite the Task's "no installs, no full test suites" line. The brief's gate list needs both. I have not run it.
- Re-dispatch M00-T01 when load is below 12 and no other project's heavy job is running? Recommendation: yes, run the five steps in order under run-job.
