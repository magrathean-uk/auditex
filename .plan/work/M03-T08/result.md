## RESULT M03-T08
status: done
summary: Round 2 hardens kit checks/dataround.py before M03-T06's first job, with one test per fix.
  (1b) Every pilot-attempt file except the row files is checked for validation case ids, in its path and bytes. The row files are targets*.jsonl, pairs*.jsonl, judge/raw-pairs*.jsonl, headroom.json, filtered.jsonl and round-measures.json. headroom.json and the pairs and raw-target files are exempt because they must name case ids.
  (2) A new round-jobs.json is required in every attempt and the train folder. The jobs listed across the round folders must equal the jobs in runs/usage/<task>/jobs.json. (6) Added the subtest for a failing headroom target judged in one order only.
  (7b) teacher-config.json is now required, and its model, revision, generation and chat_template_kwargs must equal data/explainer/teacher-config.json's, read through its SHA256SUMS. (1a) The pass-rule.md text must appear in the runbook's data-round section when that section exists. The docstring says how the section is found and lists every file a round folder must hold.
changes: kit checks/dataround.py; kit checks/tests/test_check_dataround.py (fixture plus 7 tests); kit checks/SHA256SUMS (dataround.py line only). Also .plan/work/M03-T08/{notes.md, evidence.md, progress.md, scripts/mutate2.py, scripts/build_trial2.py}. No repository edits, no commits.
verification: verify command from the worktree: pass (exit 0). The two greps read a scratch copy of the Findings lines under TMPDIR; selftest PASS; score runs/base-comparison PASS with base-pick unchanged.
  kit tests `python -B -m unittest discover -s checks/tests`: 147 OK (140 before). checks/SHA256SUMS 7 of 7 OK; bin/SHA256SUMS all OK. judging/bar/tests and heldout-collected/tests not run (brief).
  Mutation check on a scratch kit with no held-out files: 7 of 7 caught. Real-scale trial from the ceiling probe, including its real judge log: PASS with unchanged figures. Tampering with the runbook rule or teacher top_p fails.
risks: Job logs and other non-row files must not name a validation case id; M03-T06's logs must name rows by count or index (the probe's real judge log has none).
  The pass rule is compared only once a "## ... data round ..." heading exists in runbook/README.md; with no such heading, kit-check prints that it was not compared and passes.
  round-jobs.json and teacher-config.json are taken as written. Which folder a job served cannot be proved offline; REV-M03-kit reads the job logs.
questions_for_g: none
### Findings
dataround-check: dataround
kit-tests: pass
repair: done
