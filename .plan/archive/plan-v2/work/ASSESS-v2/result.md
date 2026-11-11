## RESULT ASSESS-v2
status: done
summary: I merged all 12 INV slice results (all status done and well-formed) into one assessment. Slices read only, so "works" claims rest on reading and rg, not on test runs. I checked 15 of about 70 claims and corrected 7. Several slice dead-code candidates turned out to be live.
changes: `.plan/work/assessment.md`
verification: read 12 INV-*/result.md files (pass); rg and ls spot-checks on 15 claims (pass, 7 corrections applied); `wc -l assessment.md` is 109, limit 150 (pass); no builds or tests run.
risks:
- Nothing on main is test-verified, including `make test`, contract-smoke and the rule-pack drift check.
- 195 worktrees and 88 `wt/*` branches may hold unique commits; any cleanup is a reserved action.
- The old plans named in the brief do not exist and `.plan/archive/` is absent; the records dir `~/dev/machine/records/auditex/` was not read in full.
questions_for_g:
- Does `examples/model_development/` count as held-out data under AGENTS.md? AGENTS.md forbids it; your 5 Nov answer says the public repo may carry anything.
- Keep or retire the parked model layer (about 2,500 lines, still CLI-wired and shipped)?

### Findings
Five facts a plan must respect:
1. No CI exists (workflows removed in `bdd0ab1`). `make release-check` is a manual gate whose pass state is unknown, and `Makefile:54` breaks if TMPDIR is unset.
2. The engine boundary and `allow_abbrev=False` hold on the evidence read (`src/azure_tenant_audit/argument_parser.py:119`, `src/auditex/cli.py:554-555`). Token POSTs at `graph.py:342,384` sit outside the Graph read guard.
3. Verified live, so not deletable: `src/auditex/scubagear_prune_proof.py`, `src/auditex/model_prompt.py`, `build_google_toolchain_readiness`, and the parked model layer.
4. Dead candidates:
   - Confirmed unreferenced: `benchmarks/fake_graph_benchmark.py`, `scripts/tenant-audit-flow`, `src/azure_tenant_audit/catalog.py`.
   - Unresolved: `scripts/build-value-rule-fixture.py`, and whether `tenant-bootstrap/azure_tenant_audit/` is a divergent copy or a forwarder to `src/` (forwarder tests exist).
5. The `.plan/` files are unfilled templates, and the live decision log (D1-D9) is outside the repo. The Google provider does not answer SCuBA GWS baselines; its findings are an internal control map.

Corrections applied: 7 (prune_proof, google readiness, model_prompt, build-value-rule-fixture, worktree count 195 not 207, engine `allow_abbrev` coverage, tenant-bootstrap divergence).

Open questions: the lifecycle failure from the SessionStart hook, still unexplained. Also unsettled:
- `--client-secret` at `command_builders.py:188`.
- Whether any drift or test suite passes in a venv.
- Which acceptance marker owner runs the 26,898-vector replay.
- Whether `docs/taint` and `tests/providers/m365` were ever real.

Longer material: none written to `.plan/work/ASSESS-v2/`.
