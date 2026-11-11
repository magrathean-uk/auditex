## RESULT M01-T03
status: done
summary: `check_kit_hashes` now reads its pins from the module-level `KIT_HASHES` at call time when `pins` is omitted. The acceptance test uses that default, so a test can substitute the pins. The weak regression is replaced by two tests: the fake kit's own `vectors.jsonl` passes hashing, and a different selected file beside a valid kit fails with "hash mismatch for vectors.jsonl". Production pins and behaviour are unchanged. Mutation check below.
changes: tests/test_value_rules_replay.py (commit 6c17cbd)
verification: Full M01-T03 verify command on 6c17cbd: pass. `pytest -k "kit_hashes or full_replay"`: 11 passed before the mutation. Mutation, run once and not committed: I restored the old sibling binding `check_kit_hashes(directory / "vectors.jsonl")`, and `test_full_replay_rejects_a_different_selected_file_beside_a_valid_kit` failed, as the review required. The file was then restored and the worktree is clean.
risks: none
questions_for_g: none

Review item 1 (line 280 regression too weak): fixed.
