## RESULT CLEAN-01-verify
status: done
summary: 3 candidates checked against the five evidence classes. Counts: safe 0, likely safe 2, referenced 1, uncertain 0.
Only the benchmark has a doc hit; the other two have no hit in classes 1-4.
External consumers (class 5) cannot be checked from inside the repo, so nothing earns `safe`.
changes: none
verification: rg patterns: `fake_graph_benchmark`, `benchmarks`, `tenant-audit-flow`, `tenant_audit_flow`, `auditex-logo\b`, `auditex-logo\.png`, `logo\.png`, `guided-run`, `fake.graph|fake_graph`, `perf_runtime`, `scripts/\*|assets/\*|iterdir|\.glob\(`, plus `.github`, Makefile, pyproject.toml and `shipped_content.py` inspection. All rg searches ran. No build or test run: no cheap check, because these are not covered by any single-target build or test.
risks: Class 5 is unchecked for all three. Scripts outside the repo (for example ~/dev/machine helpers) were not searched. The logo ships in the wheel through the `assets/*` glob, so deleting it changes the package contents.
questions_for_g: Keep assets/auditex-logo.png (367 KB, only the 64 px copy is used by code)? Drop is low-risk but changes the shipped wheel.

### Findings
- benchmarks/fake_graph_benchmark.py - `referenced (docs/reference/security-privacy.md:178)`. The doc names the `benchmarks` directory as lab scripts outside the redaction guarantee. No code, Makefile, pyproject or CI hit. If deleted, that sentence needs editing in the same change. The script imports `azure_tenant_audit.perf_runtime`, but that module has other users (`output_writers.py`, `evidence_db.py`, collectors, tests), so it is not a new candidate. Last touch 0efc032.
- scripts/tenant-audit-flow - `likely safe (unchecked: external consumers)`. Zero hits for the name in code, Makefile, pyproject, CI, docs and tests. It is a 13-line wrapper around `auditex guided-run`, which is live (cli.py:1055, README.md:84). The README documents the `auditex guided-run` command, not this wrapper. It is tracked executable (100755) and sits beside `tenant-audit` and `tenant-audit-full`, so an operator or outside tool may call it. Last touch 4705f46.
- assets/auditex-logo.png - `likely safe (unchecked: external consumers)`. No literal reference anywhere. Code reads only `assets/auditex-logo-64.png` (src/auditex/explorer.py:1149). The file ships through `assets/*` (pyproject.toml:69, shipped_content.py:20), so the wheel contents would change. Docs and README do not mention it. Last touch 95a6a6f.

### Open points
- tenant-bootstrap/scripts is described in the same doc line (security-privacy.md:178) as a lab area, and I did not examine its contents.
- Not searched: ~/dev/machine helpers, which could call scripts/tenant-audit-flow or the benchmark.
