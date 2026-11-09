## RESULT M01-T03
status: done
summary: Item 1 is fixed. `check_kit_hashes` now takes the selected vectors path, hashes that exact file against the `vectors.jsonl` pin, and resolves the A2 companions beside it. `test_full_v391_replay_acceptance` passes the selected path to it. Item 2 needed no change, and the stale-name renames are kept. The full criteria verify command passes on the new commit.
changes: tests/test_value_rules_replay.py (new commit "test(rules): hash the selected replay file against the vectors pin"; no amend, no rebase)
verification: the criteria verify chain, run on the final commit, passed (printed VERIFY_PASS). Its steps: `make -n acceptance`; `pytest -k kit_hashes` (9 passed); the docs grep; unset-variable and missing-file `make acceptance` runs, each non-zero with the variable named in its log. The two new tests are `test_kit_hashes_selected_file_is_the_one_hashed` and `test_full_replay_hashes_before_replaying`. The second sets the variable to a different file beside a valid kit and shows the full replay fails on the hash before `replay` is reached. `git status --porcelain` is empty.
risks: none
questions_for_g: none
