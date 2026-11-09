## RESULT REV-M01-T03
status: done
summary:
verdict: changes-required
reviewed: ea02cbc1878b0cc6425e8c484d80a1d43a071d89
The replay can consume an unhashed input. Seven changed paths exceed the task’s explicit file scope.
changes: none
verification: PASS: make -n acceptance, git diff --check main...HEAD, documentation DoD predicate. Verify not runnable: .venv/bin/python -m pytest tests/test_value_rules_replay.py -k kit_hashes; first blocking line: “zsh:1: no such file or directory: .venv/bin/python”. Remaining chained verification commands did not run. Requested .venv symlink blocked by sandbox: “ln: .venv: Operation not permitted”. clean-development doctor completed with warnings.
risks: Runtime checks remain unverified; full acceptance and runbook sign-off remain with M01-T04. Storage ownership registration remains unconfirmed; no repairs performed.
questions_for_g: none
### Findings

- Met: M01-T01 prerequisite merge is an ancestor, commit 4d5f303; scheduling later writers remains the orchestrator’s responsibility (.plan/milestones/M01-build-and-acceptance.md:47).
- Met by inspection, runtime untestable: variable guards, serial suite execution and failure propagation (Makefile:13-20).
- Not met: hash verification does not necessarily cover the input replayed (tests/test_value_rules_replay.py:279). Eight behavioural hash cases exist at tests/test_value_rules_replay.py:247, but could not run.
- Met: acceptance documentation supplies the variable, three pins, command and milestone/release timing (docs/development/runbook.md:108); explainer README links the target (tests/explainer_checks/README.md:21).
- Met: guide uses the required variable (docs/guides/model-development.md:148).
- DoD documentation predicate passed (.plan/milestones/M01-build-and-acceptance.md:16). Hash assurance is not met; refusal behaviour is untestable here (same file:18-19). Main acceptance and recorded runbook sign-off remain outstanding for M01-T04.
- Security and maintainability: no added secrets, dependencies, file-mode changes, unsafe deserialisation or injection found. Hash tests assert success and failure behaviour; the input-binding gap below remains.
- Scope not met: seven paths below are absent from .plan/milestones/M01-build-and-acceptance.md:53. The author reports the renames, but no scope amendment was supplied.

1. tests/test_value_rules_replay.py:279: `check_kit_hashes(directory)` hashes sibling `vectors.jsonl`, while line 284 reads the environment-selected path. Selecting another filename beside a valid kit bypasses hashing of the replay input. Pass the selected path into the helper and hash it against the vectors pin, or reject alternate filenames. Add a regression proving a different selected file fails before replay.
2. tests/test_value_rules_s4.py:199: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
3. tests/test_value_rules_s5.py:444 and :487: out-of-scope variable renames. Revert or obtain an explicit files-line amendment.
4. tests/test_value_rules_s6.py:83: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
5. tests/test_value_rules_s7.py:90: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
6. tests/test_value_rules_s8.py:188: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
7. tests/test_value_rules_s9.py:207: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
8. tests/test_value_rules_vectors.py:418: out-of-scope variable rename. Revert or obtain an explicit files-line amendment.
