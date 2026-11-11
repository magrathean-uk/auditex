# PLAN-v4 evidence (cited by the ticked M00 items)

Plan branch `task/PLAN-v4-plan-v4`, cut from `main` at 775d5f7. Outside `.plan/` the tree equals the 1.4.0 release commit: `git diff --quiet v1.4.0 HEAD -- . ':!.plan'` exits 0. All checks below ran in the plan worktree on the final plan tree, before the plan commit.

## M00 items 1-3: release check, acceptance, reproducible build
Not re-run in the plan session. `.plan/archive/plan-v3/work/M06-T02/result.md` records all three passing on 5843f0b (= `v1.4.0`): release-check 22620 passed 0 failed, acceptance with 26901 vectors and no skips, two byte-identical builds. The code is unchanged since, so the evidence holds for the current tree.

## M00 item 4: secrets scan
`gitleaks dir . --no-banner --redact` over the working tree with the plan files: exit 0, "no leaks found". `gitleaks dir .plan` alone: exit 0.

## M00 item 5: taint scan on the tracked tree
Tracked plus new plan files copied to a scratch directory (`git ls-files -co --exclude-standard`), then `bash scripts/oss-taint-scan.sh` there: exit 0, "oss-taint-scan: clean". A grep for workstation path prefixes over the plan v4 files found none.

## M00 item 11: ownership map
A map checker parses the rows under "## Module ownership map" in `.plan/ARCHITECTURE.md`, expands brace and `**` globs (the airr-kit row is outside the repository and skipped) and matches every path from `git ls-tree -r --name-only HEAD` outside `.plan/`.
Result: 845 files, 13 modules, 0 non-test files unmatched, 0 files in two modules, 205 `tests/test_*.py` files owned by the import convention. Changes from the plan v3 map: the retired model-layer row is gone; its four surviving files (`src/auditex/{external_assessments,assessment_review,assessment_sources}.py`, `configs/assessment-sources.json`) join product-cli-reporting; the airr-kit row is added.

## Not ticked, and why
- `make audit-deps` (item 6): depends on the advisory database, not only the tree; M00-T04 runs it.
- Items 7-10: new work (M00-T01 to M00-T04).
- M01-M06: new work.
