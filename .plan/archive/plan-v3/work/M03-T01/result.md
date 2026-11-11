## RESULT M03-T01
status: partial
summary: Re-checked the 8 named candidates and the 25 tracked `tenant-bootstrap/azure_tenant_audit/` copies; the milestone verify command passes on the 33-path list. Nothing in the repo changed.
changes: none in the repo; wrote `.plan/work/M03-T01/removal-list.txt`, `result.md` and `notes.md`
verification: milestone verify (`grep`/`xargs git ls-files --error-unmatch`/forwarder exclusion) pass; `bash -n` pass on run-auditor.sh and tenant-audit-flow; `python3 -I` ast.parse pass on 3 Python files; rg reference searches (no hits outside .plan for the named candidates). Not run: wheel build, pytest, terra spot-check.
risks: Wheel check not done (brief forbids full builds). Terra spot-check of at least 10 percent not run. The clean-development SessionStart hook reported lifecycle registration/cleanup failed; I did not run `clean-development doctor` because this brief forbids it without explicit authorisation.
questions_for_g: Approve the 33-path list at the deletion gate, or name the subset to keep. Choose wording for `docs/legal/third-party-notices.md:65` if `requirements.txt` goes (proposed: "declared in `pyproject.toml`"). Confirm `scripts/tenant-audit-flow` and `benchmarks/` have no external operator use.

### Findings
1. exists
- `benchmarks/fake_graph_benchmark.py` (82 lines); `scripts/tenant-audit-flow` (13 lines); `assets/auditex-logo.png` (367,291 bytes); `requirements.txt` and `tenant-bootstrap/requirements.txt` (2 lines each, identical).
- `tenant-bootstrap/scripts/auth-lab-populator.py` (120), `create-lab-populator-app.py` (232), `run-auditor.sh` (238).
- `src/azure_tenant_audit/output_redaction.py:455` `REASON_OUTSIDE = "outside run"`.
- `tenant-bootstrap/azure_tenant_audit/`: 26 tracked files; the forwarder `__init__.py:1-14` is kept, 25 are candidates.
- No "M03 deletion gate" entry in `.plan/DECISIONS.md` (only DEC-001 at lines 4 and 12); `.plan/CLEANUP.md` exists.
2. works
- `bash -n tenant-bootstrap/scripts/run-auditor.sh` and `bash -n scripts/tenant-audit-flow`: pass.
- `python3 -I` ast.parse of `benchmarks/fake_graph_benchmark.py`, `auth-lab-populator.py`, `create-lab-populator-app.py`: pass (syntax only).
- `guided-run` exists at `src/auditex/cli.py:54` and `:1085`, which `run-auditor.sh` and `tenant-audit-flow` call.
- `scripts/load-local-auth.sh` and `src/azure_tenant_audit/perf_runtime.py` exist (ls); the benchmark imports the latter.
- Forwarder logic read at `tenant-bootstrap/azure_tenant_audit/__init__.py:1-14`; not executed.
3. broken
- none found; no referenced file is missing.
4. dead candidates (rg, excluding .git and .plan)
- `benchmarks/fake_graph_benchmark.py`: no refs. Doc mentions only at `docs/reference/security-privacy.md:195` and `.plan/ARCHITECTURE.md:26`.
- `scripts/tenant-audit-flow`: only `.plan/ARCHITECTURE.md:26`.
- `assets/auditex-logo.png`: no name refs; explorer uses `assets/auditex-logo-64.png` (`src/auditex/explorer.py:1169`); shipped via `pyproject.toml:75` and `src/azure_tenant_audit/shipped_content.py:20` (glob).
- `requirements.txt`: only `docs/legal/third-party-notices.md:65` (G-owned legal line).
- `tenant-bootstrap/requirements.txt`: no refs in tenant-bootstrap (non-vendor), .github, Makefile, scripts or tests.
- `auth-lab-populator.py`, `create-lab-populator-app.py`, `run-auditor.sh`: no refs beyond their own files.
- `REASON_OUTSIDE`: `rg -nw` finds only `output_redaction.py:455` (line-level removal; not in the path list).
- 25 copy files: 3 byte-identical to `src/` (`__main__.py`, `adapters/base.py`, `argument_parser.py`), 20 differ; referenced by `tenant-bootstrap/scripts/run-audit-collector.sh:152`, `tests/test_parser_error_privacy.py:715`, and imports at `tenant-bootstrap/scripts/replay-known-bad-fixtures.py:25` and two tenant-bootstrap tests.
5. contradictions
- Milestone calls the copies "divergent"; 3 of 23 modules are identical to `src/`.
- `.plan/ARCHITECTURE.md:26` says misc-scripts tests cover `tenant-audit-flow` and benchmarks; the named tests do not reference them.
- `tenant-bootstrap/tests/test_canonical_runtime_forwarders.py` already tests the forwarder; M03-T03 asks for a new test.
6. open questions
- Wheel contents for the 8 named paths: build into `$CLEAN_DEV_BUILDS` and `unzip -l`.
- Terra spot-check of at least 10 percent of claims: not run.
- Operator use outside the repo of `tenant-bootstrap/requirements.txt` and `scripts/tenant-audit-flow`: repo-side evidence only.
- Neighbouring area, not in slice: `tenant-bootstrap/scripts/*.ps1` and `seed-workload-az.py` (3,350 lines) are not candidates here.

Full evidence: `.plan/work/M03-T01/result.md` and `notes.md`.
