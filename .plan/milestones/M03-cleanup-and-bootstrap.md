---
id: M03
name: cleanup-and-bootstrap
weight: 10
status: planned
---
# M03 cleanup-and-bootstrap
Writers run after M02-T05 merges (shared test files, `docs/reference/security-privacy.md`, README and runbook). Every removal goes through the deletion gate: G approves the exact path list first, the approved paths become `.plan/CLEANUP.md` rows, and M03-T02 is the only task that deletes.

## Goal
The dead paths the v3 assessment confirmed and the divergent `tenant-bootstrap/azure_tenant_audit/` module copies (G, DEC-001: delete them, keep only the forwarder) are re-checked and removed through the deletion gate; a test proves the remaining `tenant-bootstrap/azure_tenant_audit/` package forwards to `src/`; `tenant-bootstrap/` is described in AGENTS.md.

## Definition of Done
- [x] Review: G approved the exact cleanup path list at the deletion gate (DECISIONS.md entry titled "M03 deletion gate", approver G) and every approved path is a `.plan/CLEANUP.md` row with that DEC id: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M03 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && grep -A8 "^## $d M03 deletion gate" .plan/DECISIONS.md | grep -q '^- approver: G'`
- [x] Every approved path is gone and nothing in the tree still names it: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M03 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && o=$(printf '%s\n' "$P" | xargs git ls-files --) && test -z "$o" && .venv/bin/python -m pytest tests/test_docs_paths.py tests/test_architecture_modules.py`
- [x] The cleanup ledger records each M03 removal with reason, evidence, approval and commit: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M03 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && ! awk -F'|' -v d="$d" '{gsub(/ /,"",$5)} $5==d && ($3 !~ /[a-z]/ || $4 !~ /[a-z]/ || $6 !~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/)' .plan/CLEANUP.md | grep -q .`
- [x] Only the forwarder is left in `tenant-bootstrap/azure_tenant_audit/`, and a test proves it resolves to `src/azure_tenant_audit` from the repository: `o=$(git ls-files -- tenant-bootstrap/azure_tenant_audit) && test "$o" = tenant-bootstrap/azure_tenant_audit/__init__.py && .venv/bin/python -m pytest tests/test_tenant_bootstrap_forwarder.py tests/test_tenant_bootstrap_config.py tests/test_tenant_bootstrap_wrapper.py`
- [ ] AGENTS.md has a tenant-bootstrap section: `grep -q -i '^## .*tenant-bootstrap' AGENTS.md`
- [x] Full suite and release archive pass after the cleanup: `make test && make release-archive`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass at milestone close: `make acceptance`

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M03-T01 | Re-check the dead candidates and write the cleanup list | luna | S | - | done |
| M03-T02 | Remove the approved dead paths and bootstrap copies | codex | M | mechanical | done |
| M03-T03 | Prove the tenant-bootstrap forwarder | codex | S | - | done |
| M03-T04 | Describe tenant-bootstrap in AGENTS.md and align its docs | terra | S | - | todo |
| M03-T05 | Record the M03 removals in the cleanup ledger | orchestrator | S | mechanical | done |

## Acceptance criteria
### M03-T01 Re-check the dead candidates and write the cleanup list
- Read-only; may run alongside M00. Re-checks on current `main`, with `rg` over the repository and the machine helper scripts, and against the contents of a freshly built wheel: `benchmarks/fake_graph_benchmark.py`, `scripts/tenant-audit-flow`, `assets/auditex-logo.png`, `requirements.txt`, `tenant-bootstrap/requirements.txt`, `tenant-bootstrap/scripts/{auth-lab-populator.py,create-lab-populator-app.py,run-auditor.sh}`, the unused `REASON_OUTSIDE` constant in `output_redaction.py`, and every tracked file under `tenant-bootstrap/azure_tenant_audit/` except the forwarder `__init__.py` (G ruled for deletion).
- Not candidates (settled by the v3 assessment): `src/azure_tenant_audit/catalog.py`, `scripts/build-value-rule-fixture.py`; the vendored `tenant-bootstrap/vendor/microsoft-skills/` tree stays (legal notices name it).
- `removal-list.txt` is a plain list of tracked paths, one per line; `result.md` gives each path's evidence and every file that refers to it. A path whose removal would make a G-owned legal file (`NOTICE`, `docs/legal/`) wrong is listed with the proposed legal text for G.
- terra spot-checks at least 10 percent of the claims before the list goes to G.
- verify: `L=.plan/work/M03-T01/removal-list.txt; grep -q '[^[:space:]]' "$L" && xargs git ls-files --error-unmatch -- < "$L" >/dev/null && ! grep -qx 'tenant-bootstrap/azure_tenant_audit/__init__.py' "$L"`
- files: `.plan/work/M03-T01/removal-list.txt`, `.plan/work/M03-T01/result.md` (no repository file changes)

### M03-T02 Remove the approved dead paths and bootstrap copies
- Precondition: the M03 deletion-gate rows are in `.plan/CLEANUP.md`; M02-T05 merged.
- `git rm` removes exactly the CLEANUP.md rows carrying the M03 gate's DEC id, including the divergent bootstrap module copies; the `REASON_OUTSIDE` definition goes if approved; each referring doc line is updated (including the benchmarks sentence in `docs/reference/security-privacy.md` and `.github/CONTRIBUTING.md`); `pyproject.toml` data-files and `shipped_content.py` stay in parity.
- `tests/test_vendored_cli_abbreviations.py` and the tenant-bootstrap cases in `tests/test_parser_error_privacy.py` stop testing the deleted copies and test the CLI that actually runs through the forwarder; no test is skipped.
- G-approved legal text, if any, is applied verbatim; no other legal edit.
- verify: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M03 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && o=$(printf '%s\n' "$P" | xargs git ls-files --) && test -z "$o" && make test && make release-archive`
- files: the approved M03 paths in `.plan/CLEANUP.md`, `src/azure_tenant_audit/output_redaction.py` (the `REASON_OUTSIDE` line only), `docs/reference/security-privacy.md` (benchmarks sentence only), `.github/CONTRIBUTING.md`, `pyproject.toml` (data-files only), `src/azure_tenant_audit/shipped_content.py`, `tests/test_vendored_cli_abbreviations.py`, `tests/test_parser_error_privacy.py`, the legal lines G approved, plus the tests, agent/tenant-audit-skill.json, .github/dependabot.yml and docs/legal/third-party-notices.md line 65 that reference removed paths (DEC-006)

### M03-T03 Prove the tenant-bootstrap forwarder
- Precondition: M03-T02 merged. Deletes nothing.
- New `tests/test_tenant_bootstrap_forwarder.py`: with `tenant-bootstrap` first on `sys.path` and the repository layout intact, `azure_tenant_audit.cli.__file__` and a second module resolve under `src/azure_tenant_audit/`; the test runs in a subprocess so it does not disturb other imports. `tenant-bootstrap/azure_tenant_audit/__init__.py` changes only if the test shows the forwarder fails.
- verify: `o=$(git ls-files -- tenant-bootstrap/azure_tenant_audit) && test "$o" = tenant-bootstrap/azure_tenant_audit/__init__.py && .venv/bin/python -m pytest tests/test_tenant_bootstrap_forwarder.py tests/test_vendored_cli_abbreviations.py tests/test_tenant_bootstrap_config.py tests/test_tenant_bootstrap_wrapper.py`
- files: `tests/test_tenant_bootstrap_forwarder.py`, `tenant-bootstrap/azure_tenant_audit/__init__.py`

### M03-T04 Describe tenant-bootstrap in AGENTS.md and align its docs
- Runs after M03-T03 and M02-T05 merge (M02-T05 edits `README.md`, `AGENTS.md` and the runbook).
- AGENTS.md gains a short tenant-bootstrap section: lab seeding and rehearsal only, writable against a lab tenant, never part of audit, report, export or MCP flows, the forwarder rule from M03-T03, its ignored run and secret folders.
- `README.md`, `docs/index.md` and the runbook tenant-bootstrap lines agree with that section.
- verify: `grep -q -i '^## .*tenant-bootstrap' AGENTS.md && .venv/bin/python -m pytest tests/test_docs_paths.py`
- files: `AGENTS.md`, `README.md`, `docs/index.md`, `docs/development/runbook.md` (tenant-bootstrap lines only)

### M03-T05 Record the M03 removals in the cleanup ledger
- At the deletion gate: one `.plan/CLEANUP.md` row per approved path with its reason and evidence from M03-T01's `result.md` and the gate's DEC id; after M03-T02 merges: the squash commit sha in each row's commit column.
- verify: `d=$(sed -n 's/^## \(DEC-[0-9]*\) M03 deletion gate.*/\1/p' .plan/DECISIONS.md) && test -n "$d" && P=$(awk -F'|' -v d="$d" '{gsub(/[ `]/,"",$2); gsub(/ /,"",$5)} $5==d {print $2}' .plan/CLEANUP.md) && test -n "$P" && ! awk -F'|' -v d="$d" '{gsub(/ /,"",$5)} $5==d && ($3 !~ /[a-z]/ || $4 !~ /[a-z]/ || $6 !~ /[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]/)' .plan/CLEANUP.md | grep -q .`
- files: `.plan/CLEANUP.md`, `.plan/DECISIONS.md` (the M03 deletion gate entry)
