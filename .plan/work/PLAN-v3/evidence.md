# PLAN-v3 evidence

Reset commit 894f6fb (`chore(plan): reset to plan v3`) on task/PLAN-v3-plan-v3; plan v2 archived to `.plan/archive/plan-v2/`.
Outside `.plan/`, the tree at 894f6fb equals the 1.3.0 release commit d9f050f (`git diff --stat d9f050f main -- . ':!.plan'` is empty).

## Checks run at 894f6fb (M00 ticked items)
- `gitleaks dir . --no-banner --redact`: exit 0, about 19 MB scanned, no leaks found.
- `bash scripts/oss-taint-scan.sh`: exit 0.
- `make audit-deps` (linked main-checkout venv, no install): exit 0, "No known vulnerabilities found" for every list.

## Ownership map check (M00 DoD item 9)
Script: the plan v2 checker (`.plan/work/PLAN-v2/evidence.md`, section "Ownership map check"), changed to read `git ls-tree -r --name-only HEAD` and to parse only rows under "## Module ownership map".
Result at 894f6fb: 901 tracked non-`.plan` files; 13 modules; 0 non-test files unmatched; 0 files matched by two modules; 199 `tests/test_*.py` files owned by the import convention.
Changes from the v2 map: `model_precheck`, `model_prompt`, `model_serving` and the tests `test_model_serving`, `test_model_rules_only` moved from product-cli-reporting into the model-layer row (retiring in M02); product verification command no longer runs the model test; tenant-bootstrap owner codex.

## Not ticked, and why
- `make lint`, `make test`, `make contract-smoke`, `make release-check`: not run in the plan session (heavy suite); M00-T01 changes `make lint` and M00-T03 runs the chain after the M00 merges. The 1.3.0 release run on d9f050f (v2 DEC-017: 23,714 passed) predates the new lint gate.
- Replay kit location: INV3-acceptance reported the kit with matching hashes, but a bounded search in this session did not find it again, so M01-T02 re-locates and re-verifies it before any tick.
- Everything in M01-M06: new work.

## Inputs read
`.plan/work/PLAN-v3/answers.md`, `.plan/work/assessment-v3.md`, the eight INV3 result files, `.plan/work/PLAN-v2/product.md`, the archived plan v2 files.
