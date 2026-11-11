## RESULT INV-tests
status: done
summary:
- Tests and gating are local only. There is no `.github/workflows/` (removed in `bdd0ab1`); `make release-check` is the only gate and is run by hand.
- Collection is clean: 20093 tests collected with `-o addopts=""`, 19961 with the default `pytest.ini` addopts (the 132 difference is inferred to be the acceptance-marked tests).
- Full suite and contract-smoke were not run: host load 22.70 on 12 cores, above the core count, so I waited per host rule.
- `clean-development doctor` (requested by the session hook): all checks ok except five unexpected dot-folders in `~` (`~/.agent-reach`, `~/.asc`, `~/.asc-web-session-locks`, `~/.claude-science`, `~/.grokbot`). The hook's "lifecycle registration/cleanup failed" is not shown in doctor output.
changes: `.plan/work/INV-tests/notes.md` (new, repo-relative notes only)
verification:
- `.venv/bin/python -m pytest --collect-only -p no:cacheprovider` (main checkout venv, PYTHONDONTWRITEBYTECODE=1): pass, 20093 collected.
- Existence check of every script and sample the Makefile names: pass, all present.
- `clean-development doctor`: ok with 5 WARN (dot-folders).
- `make test` / full pytest: not run (load).
- `make contract-smoke`: not run (load; it writes `outputs/` in the cwd).
- `make lint`, `make release-check`: not run.
risks:
- Acceptance-marked tests (`explainer_acceptance`, `value_rule_acceptance`, 17 marker lines) are excluded from `make test` (`pytest.ini:3`) and nothing in the repo runs them automatically; the pass/fail state of those is unknown.
- AGENTS.md "Parallel work" says merging into `main` "also runs make test", which reads as an automated gate; there is no CI, so it is a manual step (inferred).
- Full-suite result unknown; about 40 skip sites are env-gated (OPA, ScubaGear, value-rule vectors) or sandbox-gated, so skip counts will vary by host.
questions_for_g:
- Slice Hints allow one full pytest run and one contract-smoke, but the Constraints say no full suites. I read the Hints as permission and deferred only for load. Confirm that reading, or say to skip them entirely.
### Findings
1. exists
- `tests/`: 223 `test_*.py` files (git ls-files), `conftest.py` (`tests/conftest.py:1-70`), support modules `support.py`, `gate_support.py`, `graph_fakes.py`, `pim_support.py`, `scripted_collectors.py`, `sink_expansions.py`; dirs `explainer_checks/` (33 entries), `fixtures/` (78), `schemas/` (5).
- Static `def test_` count: 3980 (rg -c over `tests/test_*.py`).
- `pytest.ini:1-8`: `pythonpath = src`; addopts exclude both acceptance markers; `norecursedirs = !Review`.
- `Makefile:5-7` test; `:18-20` lint (compileall only); `:30-33` install; `:48-68` release-check; `:70-90` contract-smoke (9 offline sample runs plus projection demo).
- Scripts all present: `scripts/select-python.sh`, `check-archive-wheel.py`, `generate-rule-packs.py`, `oss-taint-scan.sh`, `tenant-audit-full`, `bootstrap-local-tools.sh`, `release-smoke.sh`.
- Sample inputs present: `examples/sample_audit_bundle/*.json` (the five used by contract-smoke), `examples/google_workspace_sample.json`, `examples/demo_tenant/demo_tenant.json`.
- `.pre-commit-config.yaml`: ruff-check v0.17.0, whitespace check, `gitleaks-local`.
- `.github/`: CONTRIBUTING.md, PULL_REQUEST_TEMPLATE.md, SECURITY.md, SUPPORT.md, ISSUE_TEMPLATE/, dependabot.yml.
2. works
- Collection of all tests: `pytest --collect-only` with main-checkout venv (20093; 19961 with default addopts). Imports resolve to worktree `src` via `pytest.ini` pythonpath (inferred).
- Every script and sample path in Makefile and runbook exists (`test -e` loop).
- Helper imports (rg): `support` 11 files, `gate_support` 7, `scripted_collectors` 3, `graph_fakes` 2, `pim_support` 1, `sink_expansions` 1; none dead.
- `.github/dependabot.yml:6-34`: pip (`/`, `/tenant-bootstrap`) and pre-commit ecosystems, weekly, 7-day cooldown; no github-actions entry, consistent with no workflows.
- Git: `bdd0ab1` removed GitHub Actions workflows; earlier `143cbb3`, `2b5cbe1` touched them.
3. broken
- none confirmed. Collection finished without collection errors.
- Not verified because not run: whether `make test`, `make lint`, `make contract-smoke`, `make release-check` pass.
4. dead candidates
- `pytest.ini:6` `norecursedirs = !Review`: the `!` looks like a no-op pattern (inferred; untested).
- `tests/test_dns_lookup_parsers.py:9` says "see TODO below"; rg for TODO under `tests/` showed no matching TODO (output capped at 40 lines, so not settled).
- Environment-gated skips (not dead): `tests/test_value_rules_contract.py:263-267` (needs `AUDITEX_TEST_VALUE_RULE_VECTORS` and `_CATALOGUE`); `tests/test_local_model_benchmark.py:43`, `:396`, `tests/test_model_serving.py:206`, `tests/test_teams_admin_rest.py:753` (sandbox loopback); `tests/test_mcp_guard_repair.py:228`, `:540` and `tests/test_mcp_manifest_guard.py:54`, `:95`, `:395` (FIFO and descriptor support).
- No stale directories found under `tests/`.
5. contradictions
- `AGENTS.md` (Parallel work): merging into `main` "also runs `make test`" and "no test gate on the push itself". `docs/development/runbook.md:101`: "There is no hosted CI; ... checks run locally." The AGENTS wording reads as automated; it is manual (inferred).
- `.github/CONTRIBUTING.md:33` and `Makefile:20`: `make lint` is compile-only, consistent. Ruff runs only in pre-commit (`.pre-commit-config.yaml`), not in `release-check`; a gap, not a contradiction.
6. open questions
- Who runs the acceptance markers (`explainer_acceptance` in `tests/explainer_checks/test_mutation.py` and `tests/test_explainer_integration.py`; `value_rule_acceptance` in `tests/test_value_rules_replay.py`)? Settle: `rg -n 'acceptance' docs/development/runbook.md` plus a `-m value_rule_acceptance` run.
- Full pass/fail/skip counts: run `make test` once when `uptime` load is under 12, with `-rs` for skip reasons.
- `contract-smoke` verification: run with outputs redirected to TMPDIR, or accept it writes `outputs/ci-contract` in the worktree (git-ignored).
- Is Ruff meant to gate anything beyond pre-commit? Settle: `rg -n ruff Makefile pyproject.toml`.
- Neighbouring area (one line): `src/` and `docs/` were not inspected; runbook and AGENTS claims about release-smoke, contract version and the 102-policy count are unverified.
