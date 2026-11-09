## RESULT M00-T04-check
status: done
summary: Spot-check: PASS with 2 minor disputed rows (evidence below). Neither D5 core-touching branch is a 1.3.0 boundary fix.
summary: 11 rows checked: docs-rules-and-scan-limits, d5-k-material-stage1, d5-material-proof-v, collect-presets-1, d5-m-identity, ff-d5-root-cli, redact-key-guard, release-1.2.4, ff-d5-model-case, lead-20261107-b, ss-style stacking.
changes: none
verification: git log, git cherry, git diff --stat origin/main...<b>, git rev-list --count, merge-base --is-ancestor: all ran, pass
risks: Claimed patch-id rule "no row merged-equivalent" holds per whole branch, but two rows hide partial equivalence.
risks: redact-key-guard "superseded" is sound only by inference (see findings).
questions_for_g: none

### Findings
Answer: spot-check pass. Tips and ahead counts match for every row checked; classes hold. Two disputed rows, both minor:

1. wt/release-1.2.4 (d9a9f7c): row says "1 of 5 commits patch-equivalent". git cherry shows 6 ahead, 5 unmatched (+), 1 equivalent (-). The count should read "1 of 6". The superseded class is unaffected.
2. wt/lead-20261107-b (a88b74a): 86 ahead, but git cherry shows 64 unmatched and 22 patch-equivalent to main. The table gives no hint of this; the row says "alias-collision test; D5 file set (inferred)". Class (D5) may stand, but the 22 already-on-main commits mean "ahead 86" overstates the unmerged work. Settle by: git log --cherry-pick --right-only origin/main...wt/lead-20261107-b.

Rows that pass:
- docs-rules-and-scan-limits: tip fe78ee1, 1 ahead, README.md only (+8). Text is the 3/27/72 round 7l5 coverage split and is correctly framed as a historical lab estimate. M02-docs-accuracy.md:17,43 asks for a reconcile-then-land, so "needed-for-1.3.0, open" is right.
- collect-presets-1 (1 ahead, cherry +1), d5-m-identity (7, +7), ff-d5-root-cli (3, +3), ff-d5-model-case (10, +10; the diffstat is 11 files, with tests plus model-projection and provenance adapters): all match.
- redact-key-guard: 3 ahead, none patch-equivalent. wt/redact-key-guard-2 is an ancestor of origin/main, so the successor is merged. Supersession is inferred from names and subjects (guard private input paths); range-diff would prove it, as the table already notes.

D5 core-touching branches: both are D5, not a 1.3.0 boundary fix.
- wt/d5-material-proof-v-20261108-b (bb66370) is stacked on wt/d5-k-material-stage1-20261107-b (b8462ea is its ancestor in the log). Its 12 ahead = 9 stage1 + 3 own (+3278/-7, 8 files).
- Both touch the same 4 existing modules: bundle_integrity.py (+15), guarded_io.py (+152), private_io.py (+6), run_files.py (+394). Changes are additive; the only deletions are 7 lines, mostly docstring or conditional rewrites. The new work is redaction_material.py (949/963 lines) and its tests.
- The edits exist to exclude the new operator-inputs/redaction-material.json (and its temporaries) from bundle hashing and to refuse it as a copy destination. That behaviour belongs only to the new material feature, so no 1.3.0 behaviour on main needs it. This is inferred from the diffs; I did not run the tests.
- The table's "+3001/-7" is correct for stage1. It does not give proof-v's own size (+3278/-7); the number should be added if the row is kept.

Unknowns: whether D5-v2 later needs these module hooks (BACKLOG.md:9 context); the other 33 rows were not checked.
