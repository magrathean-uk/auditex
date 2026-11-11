## RESULT REV-M00-T02
status: done
summary:
verdict: approve
reviewed: ba64b7eb98810a52d1c8f3fc5d94ad39f882c075
Round-1 change 1 is fixed: the test now uses the kit's `cell-catalogue.json` as the independent reference and falls back to the shipped catalogue only when that file is missing. Round-1 change 2 is fixed: `result.md` names the kit file it found and says which branch each run takes. The new lines add no defects. Evidence: `.plan/work/REV-M00-T02/evidence.md` (Round 2 section).
changes: none (I added a git-ignored `.venv` link in the review worktree and appended the round-2 evidence to `.plan/work/REV-M00-T02/evidence.md`)
verification: `.venv/bin/python -m pytest tests/test_value_rules_contract.py -rs -q -p no:cacheprovider` passed in all three modes. With the variable set to the v391 kit it exited 0 with no skips. With the variable unset it exited 0 with one skip at :273 naming `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`. Pointed at a copy of `vectors.jsonl` alone in a `$TMPDIR` folder, it exited 0 with no skips, which exercises the fallback branch. I did not run `make acceptance`; the brief leaves it to the merge gate.
risks: (1) If the kit's catalogue ever uses another layout, for example wrapped under `policies`, the test fails with a KeyError rather than falling back. That is a loud failure, which is acceptable. (2) `make acceptance` has not run on this head.
questions_for_g: none
### Findings
Criteria checklist (diff-scoped):
- Reads `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`: met, tests/test_value_rules_contract.py:271.
- Shipped catalogue only when the kit has none, stated in `result.md` after checking the kit: met. The kit branch is at tests/test_value_rules_contract.py:275-277. `.plan/work/M00-T02/result.md` names `value-rules-v391/cell-catalogue.json` and says which branch each run takes.
- No longer needs `AUDITEX_TEST_VALUE_RULE_CATALOGUE`: met, tests/test_value_rules_contract.py:270-277.
- Passes with the variable set; skips naming the variable when unset: met, tests/test_value_rules_contract.py:272-273 (evidence.md, round 2).
- `make acceptance` runs it and the Makefile change is listed: met at Makefile:16, unchanged since round 1.
- Round-1 change 1 (the reference check always passed): fixed. `ref` comes from the kit when it carries a catalogue, so the key-set check at :278 compares two independent sources again.
- Round-1 change 2 (`result.md` did not record the kit check): fixed.
- Scope: commit ba64b7e changes only tests/test_value_rules_contract.py, which is on the files line. No scope creep.
- Security: no secrets, no dependencies, and no injection surface. The path comes from the environment and is only read.
Required changes: none.
Suggestions (non-blocking):
- tests/test_value_rules_contract.py:288 still reads `sections` from `shipped`, while the other per-cell values come from `ref`. That is deliberate, since it tests the shipped rendering against the kit's expectations; a short comment would make the intent clear.
