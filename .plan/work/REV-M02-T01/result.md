## RESULT REV-M02-T01
status: done
summary:
verdict: changes-required
reviewed: c117d998228d3757c4ef7e7692cf48f7035edd97
All 38 removal paths are appropriate after re-homing. The proposed contract preservation is sound, but the migration plan has gaps.
changes: none
verification: PASS - removal-list tracking check, HEAD equals main, clean worktree; completed source/reference tracing and simulated documentation-path check. Builds, installs and suites not run, as instructed.
risks: intermediate commits would fail required checks; retained export coverage could be lost
questions_for_g: none
### Findings
- P1 - `.plan/work/M02-T01/design.md:102`: moving the sink inventory entries conflicts with retaining the dry-run writer at line 74. That writer still calls `write_private_text` (`src/auditex/model_serving.py:492`), so `tests/test_writer_sinks_d3.py:158` would reject it as unclassified. Add the new entries in T03 and retain each old entry until its sink disappears; remove client/training entries and wildcard expansions in T04.
- P1 - `.plan/work/M02-T01/design.md:146`: the proposed T04 documentation fix misses `docs/development/runbook.md:157`, which names the deleted `scripts/build-lab-model-cases.py`. The simulated path check finds this additional failure. Include the runbook alongside provenance and the model guide in T04, and settle the sequencing explicitly.
- P2 - `.plan/work/M02-T01/design.md:132`: export-test migration needs more than removing client references and script flags. `tests/test_scubagear_export.py:65` builds sidecar, repair, redaction and salt tests through `_dry`, which requires the removed API and prompts file. Specify how these retained behaviours will be tested through `project_export`, `build_case` or normal assessment. Also replace the deleted-parser call at line 1546.
- P2 - `.plan/work/M02-T01/design.md:260`: expand T05's documentation scope. `docs/index.md:18` still advertises corpus assembly, evaluation and training; `docs/development/scubagear-export-adapter.md:3` and `:90` promise dry-run output and accepted legacy flags. Neither has a planned rewrite, leaving documentation describing removed behaviour.
