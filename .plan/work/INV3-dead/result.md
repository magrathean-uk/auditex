## RESULT INV3-dead
status: done
summary: Re-checked 7 BACKLOG candidates on main 58084bb. Dead by repo reference: benchmarks/fake_graph_benchmark.py, scripts/tenant-audit-flow, assets/auditex-logo.png (inferred), requirements.txt, tenant-bootstrap/requirements.txt. Not dead: src/azure_tenant_audit/catalog.py (test-only use), scripts/build-value-rule-fixture.py (used by s4-s9 builders). Evidence and command log: .plan/work/INV3-dead/notes.md
changes: none
verification: git ls-files -s, wc -l, ls -l, git log -1 per path, cat of both requirements files, grep src/auditex/cli.py for guided-run (all pass); Grep/Glob/Read reference searches outside .plan/ (pass)
risks: Reference searches cover this repo only; external callers of scripts/tenant-audit-flow and the benchmark are unsearched. Whether the root requirements.txt is needed is unknown (see questions).
questions_for_g: none

### Findings

1. exists
- benchmarks/fake_graph_benchmark.py (82 lines, 100644)
- scripts/tenant-audit-flow (13 lines, 100755)
- src/azure_tenant_audit/catalog.py (75 lines)
- assets/auditex-logo.png (367,291 bytes)
- requirements.txt and tenant-bootstrap/requirements.txt (2 lines each, identical content: `requests>=2.34.2,<3`, `msal>=1.39.0,<2`)
- scripts/build-value-rule-fixture.py (157 lines)

2. works
- scripts/tenant-audit-flow:13 execs `auditex.cli guided-run`; that subcommand is defined at src/auditex/cli.py:54 and dispatched at :1085 (grep).
- scripts/tenant-audit-flow:5 sources scripts/load-local-auth.sh, which exists (Glob).
- Both requirements files are tracked and identical (git ls-files -s, cat).
- src/azure_tenant_audit/catalog.py:66 `load_catalog` is exercised by tests (see section 4).
- Nothing executed beyond these reads and greps; no tests or builds run.

3. broken
- none found in the checked paths.

4. dead candidates
- benchmarks/fake_graph_benchmark.py: no reference outside itself (rg `fake_graph_benchmark|fake-graph|benchmarks/`; not in Makefile, pyproject.toml or shipped_content.py). Only docs/reference/security-privacy.md:195 names the `benchmarks` directory. Verdict: dead.
- scripts/tenant-audit-flow: rg `tenant-audit-flow` finds no hit outside itself, including Makefile, pyproject.toml, docs, tests and CI. It is a thin alias for guided-run. Verdict: dead by repo reference.
- assets/auditex-logo.png: no literal reference (rg `auditex-logo\.png`). Code reads only assets/auditex-logo-64.png (src/auditex/explorer.py:1169). Ships via the assets/* glob. Verdict: dead, inferred.
- requirements.txt: no tool consumer (no hit in Makefile, pyproject.toml, .github, scripts or tests). Only docs/legal/third-party-notices.md:65 mentions it, descriptively. Verdict: dead, no consumer.
- tenant-bootstrap/requirements.txt: no consumer outside .plan/ and the vendor tree. The vendored evaluation.md:387,556 cites a different file, scripts/requirements.txt. Verdict: dead, no consumer found.

5. contradictions
- src/azure_tenant_audit/catalog.py: .plan/work/INV-dead/result.md, .plan/work/ASSESS-v2/result.md:20 and .plan/work/assessment.md:95-96 call it unreferenced. tests/test_architecture_modules.py:246 and tests/test_directory_relationships.py:6,118 import it. Not dead.
- scripts/build-value-rule-fixture.py: .plan/work/INV-layout/result.md:3 lists it as dead. Loaded by path from scripts/build-value-rule-fixture-s4.py:21, -s5.py:29, -s6.py:23, -s7.py:25, -s8.py:17, -s9.py:21. Not dead.
- .plan/work/CLEAN-01-verify/result.md:12 cites docs/reference/security-privacy.md:178 for the benchmarks sentence; it is at :195.
- docs/legal/third-party-notices.md:65 says dependencies are declared in `requirements.txt`, but no tool reads that file; pyproject.toml carries the same ranges.

6. open questions
- Does anything outside this repo (for example ~/dev/machine helpers or operator habits) call scripts/tenant-audit-flow or the benchmark? Settle by searching ~/dev/machine helpers; not searched here.
- Is the shipped assets/auditex-logo.png expected in the wheel (outside-repo consumers)? Settle by checking the release wheel contents and any packaging consumer.
- Is the root requirements.txt meant to be a supported install path, given pyproject.toml declares the same runtime deps? Settle by checking the CONTRIBUTING and install docs for `pip install -r`.
- Neighbouring area: scripts/load-local-auth.sh (sourced by the candidate wrapper) was confirmed to exist but its contents were not read.
