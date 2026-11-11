## RESULT INV4-delta
status: done
summary: Since v1.3.0, the model layer, the 25 drifted bootstrap modules, the benchmark, the flow script, requirements files and the logo are gone; `SOURCE_DATE_EPOCH` is set, `REASON_OUTSIDE` is removed and `auditex assess` exists. Still open: `make lint` now runs `ruff check .` but AGENTS.md says it is compileall only, the runbook's publication section still says 1.3.0, and `_is_privileged_user` is an uncalled function. The `.venv` is missing in this worktree, so no lint, test or collect was run.
changes: none
verification: `git log --oneline v1.3.0..v1.4.0`, `git tag --list 'v1.*'`, `wc -l` on plan and doc files, `git ls-files` checks for model, bootstrap and removed paths, `rg -c` for test count; Read of `.plan/work/assessment-v3.md`, `.plan/DECISIONS.md`, `.plan/RETRO.md`, `Makefile`, `pytest.ini`; Grep for removed symbols, stale references and test defs. All pass as reads. No build, install, pytest or make target run.
risks:
- Test count is inferred (grep of `def test_` lines gives about 4,204 across 269 files, not a collected count); no pytest collection ran.
- The SessionStart hook reported a clean-development lifecycle registration failure and suggested `clean-development doctor`. I did not run it because this brief does not authorise it; G should decide.
- `make lint` may fail on current code (ruff 0.17.0 `check .` against the tree); unverified.
questions_for_g: Should `_is_privileged_user` (src/azure_tenant_audit/output_redaction.py:323) be deleted, given DEC-001 chose all-user masking? Should `make lint` keep `ruff check .` (AGENTS.md says compileall only)?

### Findings

**1. exists**
- Makefile:9-20 `acceptance` (value replay, then four explainer chunks, twins and byte_identical); Makefile:38-44 `lint` (compileall, ruff pin equality check, `ruff check .`); Makefile:100-108 `release-check`; Makefile:110-124 `release-archive`; Makefile:126-143 `dist`; Makefile:145-165 `contract-smoke`.
- Makefile:135 sets `SOURCE_DATE_EPOCH` from HEAD commit time; Makefile:138 runs `check-reproducible-build.py --normalise-sdist`.
- pytest.ini:2-7: pythonpath `src`; addopts deselect `explainer_acceptance` and `value_rule_acceptance`; both markers declared. No `norecursedirs` line.
- pyproject.toml:10 `requires-python >=3.11`; :40-42 dev extra pins `ruff==0.17.0`; :50-53 ruff select `E4,E7,E9,F`, with F811 ignored for `tenant-bootstrap/scripts/seed-workload-az.py`.
- .pre-commit-config.yaml:16 `ruff-pre-commit v0.17.0`, equal to the pyproject pin.
- scripts/check-reproducible-build.py (111 lines): `normalise_sdist` :20, `sdist_members` :40, `differences` :71 compares wheel and sdist digests (:77-78).
- CHANGELOG.md:9 `## [1.4.0] - 2026-11-10`, matching DEC-011 (.plan/DECISIONS.md:98-105).
- src/auditex/cli.py:64 `assess` subcommand, dispatched at :992 to `rule_assessment.assess_run`.
- Tracked counts (git ls-files): 1,162 files; 302 `.py` under tests/; 20 `.py` under tenant-bootstrap/; 27 under scripts/; 25 files under tenant-bootstrap/scripts/.

**2. works**
- `git tag --list 'v1.*'` (v1.3.0, v1.4.0 present); `git log --oneline v1.3.0..v1.4.0`.
- Pin equality: pyproject.toml:42 and .pre-commit-config.yaml:16 both 0.17.0 (read). The Makefile:43 guard is consistent with that.
- Model layer removed: `git ls-files` finds no `src/auditex/model_*.py`, no `src/azure_tenant_audit/model_*.py`; `configs/model-sources.json`, `examples/model_development/`, `scripts/score-model-precheck.py` absent.
- Removed set absent: `benchmarks/fake_graph_benchmark.py`, `scripts/tenant-audit-flow`, `assets/auditex-logo.png`, `requirements.txt`, `tenant-bootstrap/requirements.txt` (all `test -e`).
- `tenant-bootstrap/azure_tenant_audit/` tracks only `__init__.py` (git ls-files); the 23 drifted copies are gone.
- Contract-smoke and projection demo now import `auditex.rule_assessment` and `auditex.scuba_projection` (Makefile:165); tests/test_model_serving.py:11-16 also imports them (read).
- `REASON_OUTSIDE` has no hits in the repo outside .plan/ (Grep).
- `pytest.ini` no longer contains the `norecursedirs = !Review` line flagged in assessment-v3.md:103.

**3. broken**
- `make lint` now runs `ruff check .` (Makefile:44) with ruff 0.17.0 and the `E4,E7,E9,F` rule set. Not run here; assessment-v3's "230 findings" is unverified against the current tree (inferred).
- No broken import found by grep: tests import only `auditex.*` or `azure_tenant_audit.*` modules that are tracked.
- docs/development/runbook.md:122 `Publication for 1.3.0 ... gh release create v1.3.0` is stale after 1.4.0 (read).

**4. dead candidates**
- src/azure_tenant_audit/output_redaction.py:323 `_is_privileged_user`: Grep for the name across the repo, excluding .plan/, finds only the definition.
- tests/test_model_serving.py, test_model_rules_only.py, test_model_precheck.py, test_composed_model_regressions.py: file names only; content now tests rule_assessment or the precheck. Several tests import `test_model_serving` helpers (tests/test_value_rules_s6.py:181, s8.py:149, s9.py:307, test_scope_postcheck.py:20). Names are stale, not dead.
- docs/guides/model-development.md:1 is a "(retired)" page still in the tree.

**5. contradictions**
- AGENTS.md:59 says `make lint` is "compileall only, not a style check"; Makefile:40-44 adds `ruff check .`.
- AGENTS.md command list (lines 57-63) omits `make acceptance` and `make dist`, which runbook.md:98-110 documents.
- docs/development/runbook.md:122 (1.3.0 publication) versus CHANGELOG.md:9 (1.4.0).
- assessment-v3.md statements now false: `SOURCE_DATE_EPOCH` unset (:26; Makefile:135 sets it); `make dist` not byte-reproducible (:26-27; check-reproducible-build now compares sdist bytes at :77); `REASON_OUTSIDE` unused (:41; removed); `Makefile:140` imports model_serving (:22; now rule_assessment); tenant-bootstrap module copies present (:8, :39; removed); `pytest.ini:4` norecursedirs (:63, :103; removed); DEC-004 model CLI wiring (:48; `model` subcommand gone, `assess` added).
- assessment-v3.md:55 `AUDITEX_TEST_VALUE_RULE_VECTORS` (docs/guides/model-development.md:148): not re-checked this round.

**6. open questions**
- Does `make lint` pass? Settle with `make install` then `make lint` in a worktree with `.venv` linked (not run; .venv missing here).
- Collected test count and markers: `.venv/bin/python -m pytest --collect-only -q` (not run).
- Does `_is_privileged_user` have a caller under a dynamic name? Settle with a full-repo rg including `getattr` strings (inferred none).
- Neighbouring area, one line: `.plan/work/` and `.plan/archive/` were skipped per the brief; the clean-development lifecycle failure reported by the SessionStart hook is outside this slice.
