## RESULT REV-M01-T03
status: done
summary:
verdict: changes-required
reviewed: f2b6d2b27c37a8976f72265c54ac62aced77f3f0
The implementation fixes the binding. One new regression still passes when the defect is restored.
All seven rename-only files match the amended files line on main.
changes: none
verification: PASS: make -n acceptance; git diff --check 223fbaa..HEAD; stale-variable docs predicate; programmatic comparison confirming only authorised variable replacements.
Verification chain not runnable: `.venv/bin/python -m pytest tests/test_value_rules_replay.py -k kit_hashes` stops because `.venv` is absent. Main-interpreter attempt, including both regressions, stops before collection because no temporary directory is writable. Remaining chained checks were skipped.
Memory-only mutation check: the full-replay regression passes with both the correct selected-path binding and the incorrect sibling-file binding.
risks: Runtime verification remains outstanding.
questions_for_g: none
### Findings

- P2 - [test_value_rules_replay.py:280](test_value_rules_replay.py:280): `_fake_kit` returns synthetic pins, but this test discards them. The acceptance function uses production pins, so even sibling `vectors.jsonl` fails hashing. Restoring `check_kit_hashes(directory / "vectors.jsonl")` leaves this regression green, confirmed in memory. Supply matching synthetic pins to the helper used by the acceptance function, then require this mutation to fail.
- Confirmed by inspection: the selected file is hashed against the vectors pin at lines 233-239; all three checks finish at line 305 before parsing or replay.
- The helper-level selected-file regression correctly supplies synthetic pins and detects the original helper defect.
- Items 2-8 are resolved: the amended scope includes all seven files, whose changes contain only the variable-name replacements.
