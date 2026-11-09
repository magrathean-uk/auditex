## RESULT M01-T02
status: done
summary: Kit at <4TB>/dev/auditex-data/development-kit/20261027-ship-plan/tree/run/model/value-rules-v391/ matches all three pins and line counts. Not copied to the machine records folder (read-only placement). The background search found no other copies outside the 4TB kit tree.
changes: .plan/work/M01-T02/notes.md (new; no tracked files changed)
verification: shasum -a 256 on the three kit files: pass. wc -l: pass (26898, 3, 190). printenv AUDITEX_TEST_VALUE_RULE_VECTORS_V391: unset, so the milestone verify fails as written here. Background search (bi6lf5v4g): exit 0. clean-development doctor: not run (brief forbids it).
risks: The kit sits on the unencrypted 4TB and must be copied to the internal records folder by a writer. Nine test skip-sites still read the stale variable name.
questions_for_g: none
### Findings
1. exists
- Kit dir: <4TB>/dev/auditex-data/development-kit/20261027-ship-plan/tree/run/model/value-rules-v391/ (vectors.jsonl, a2-vectors.jsonl, a2-label-overrides.jsonl, plus rule-eval-failed/ and working files).
- tests/test_value_rules_replay.py:9, :53, :220-240 (full replay).
- tests/test_value_rules_replay.py:157-165 (sample manifest pins).
- tests/fixtures/value-rules/vectors-v391-sample.jsonl.xz, manifest-v391-sample.json, label-overrides-a2-v391-sample.jsonl.
- scripts/build-value-rule-sample-v391.py:1.
- pytest.ini:3,7,8 (markers).
2. works
- Three kit files match pins: shasum -a 256 (vectors 3515b6fa..., a2-vectors 03512595..., overrides 74639d17...).
- Line counts 26898 / 3 / 190: wc -l. These match tests/test_value_rules_replay.py:229 and :238.
- Env var unset in this shell: printenv check.
3. broken
- Milestone verify (.plan/milestones/M01-build-and-acceptance.md:43) fails here because AUDITEX_TEST_VALUE_RULE_VECTORS_V391 is unset.
- No kit copy at the top level of ~/dev/machine/records/auditex (development-20261107/, 246 entries, not checked).
- Full replay test pins only vectors.jsonl (tests/test_value_rules_replay.py:227). The a2 files are not hash-checked there.
4. dead candidates
- No kit_hashes test exists in tests/ (rg). M01-T03 scope.
- Makefile has no acceptance target (rg). M01-T03 scope.
- Stale or other copies in the 4TB tree, with different hashes from the pin: value-rules/v1 and value-rules/vectors.jsonl, v3, v31-v39, value-rules-v37-aborted, v38-aborted, review-delta/copy/value-rules-v38, review-final/copy/value-rules-v39, and rule-eval-failed/vectors.jsonl (8df5597d...). Background search, bi6lf5v4g.output.
5. contradictions
- Milestone DoD (.plan/milestones/M01-build-and-acceptance.md:18) requires all three hashes verified by a kit_hashes test. The test file pins only the vectors hash (tests/test_value_rules_replay.py:227).
- Milestone DoD (line 16) bans the stale variable in docs only. The code still reads it: tests/test_value_rules_contract.py:266, test_value_rules_s4.py:199, s5.py:444,487, s6.py:83, s7.py:90, s8.py:188, s9.py:207, test_value_rules_vectors.py:418 (skip if unset).
- docs/guides/model-development.md:148 names the stale variable (milestone line 51 notes it).
- .plan/master-plan.md:26 says the kit stays in the machine records folder. The kit currently sits on the 4TB.
6. open questions
- Does a copy already exist in ~/dev/machine/records/auditex/development-20261107/? Check: rg -l vectors.jsonl there.
- Is NOTE-rule_evaluation_failed.md (5 Nov) a live concern or abandoned? Read it.
- Hook asked for clean-development doctor; the brief forbids it. Needs G to say whether to run it.
- Neighbouring area (M01-T03): docs/guides/model-development.md:148 is the only doc naming the stale variable.
