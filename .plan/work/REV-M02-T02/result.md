## RESULT REV-M02-T02
status: done
summary:
verdict: changes-required
reviewed: ad6fd843782a
525 rows; 102/102 policies; 196/314 cells; 0 formal twins; 10 missed availability-gate matches.
Nearest-neighbour copying: decisive 225/525 (42.9%), full 208/525 (39.6%), policy majority 201/525 (38.3%).
Soundness: 0/3,871 conflicting keys; old recount reproduced exactly: 167/174/81 twins against train/combined/validation, 261 twin-free.
changes: none
verification: PASS: 12/12 hashes, engine pins, opa eval stdin replay 525/525, selftest.py 28/28, independent similarity probes, recount, focused conflict replay, checker-result replay, four original manifest falsifications rejected, four split-discovery/hash probes rejected. Native kit-check twins FAIL: temporary-directory setup.
risks: Full rebuild and temporary-copy suites skipped under read-only/high load; storage doctor failed lifecycle ownership and reported 34 GB free against 40 GB threshold.
questions_for_g: none
### Findings

1. closed - kit/20261111-airr-v4/heldout/build_heldout.py:745: Own-evidence replay reproduces 525/525 labels and outcomes; input hashes match 525/525.
2. closed - kit/20261111-airr-v4/heldout/heldout_lib.py:74: All 33/33 not-assessed labels reproduce from evaluated inputs, including 12 declared collection-error mappings; no post-evaluation masking remains.
3. open, blocking - kit/20261111-airr-v4/heldout/twin_definition.py:310: Missing-section matches are 11 raw, 0 required; predicate-key matches are 0. However, 10/525 rows share exact deciding availability inputs and identical Rego results with training, while all evade the key. Removing unread settings preserves all 10 results. Extend the key to availability gates and regenerate before scoring.
4. closed, coverage limit - kit/20261111-airr-v4/heldout/build_heldout.py:858: Focused replay reproduces seven conflict exclusions across three policies, zero reproducible-label conflicts and zero cells lost. Both formerly deleted cells return. Remaining gaps: 118/314 cells, including 85 not-assessed cells.
5. closed - kit/20261111-airr-v4/checks/twins.py:257: Rehashed incorrect verdict counts, missing cells, commit and comparison count are rejected individually, 4/4, and together.
6. closed - kit/20261111-airr-v4/heldout/heldout_lib.py:111: Six pinned sources cover 14,547 compared rows. Manifest-free prose, unlisted files, listed missing files and changed consumed bytes are rejected, 4/4.
7. new, limit - kit/20261111-airr-v4/checks/twins.py:266: Rehashed false rule hashes, coverage-reason values and seed-reference counts still pass, 3/3. Actual pins and seed disjointness independently match; this limits manifest assurance.
8. key-change check passed - kit/20261111-airr-v4/heldout/notes/twin-reconciliation.md:77: Restated recount matches its record exactly; previous figures remain available. Pack soundness has 0/3,433 conflicting keys across 5,260 rows.
