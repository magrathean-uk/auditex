## RESULT M04-T03
status: done
summary: Made only the two edit classes DEC-021 allows, in its five named files; no assertion changed. Class (iv) is commit 222355c: the fixtures that relabel a fresh assessment as the 2026-10-29 schema now carry `run-salted-sha256-v1`. Class (v) is commit 9f38936: the two pins in tests/test_scuba_projection_area_hook.py are refreshed and the keyless fixture now uses the seeded test key.
Pin difference: a dump made from the main tree reproduces both old pins exactly. Compared leaf by leaf, only `redaction.strategy` (both pins) and one pseudonym (`User a9f83672e67c32c3` to `User 2ece4e6269be8dcd`, the seeded key's value, redacted pin only) changed.
I rebased the branch onto main first; main had gained only `.plan/` commits, and there were no conflicts.
make test: 22912 passed, 0 failed. The 11 earlier failures are gone and nothing else fails.
The listings from last round are in result.md, unchanged: current-version assertions, and the rule (ii) and (iii) lines.
changes: tests/test_model_rules_only.py (head 243), tests/test_optional_collection_reason.py (head 229), tests/test_scope_postcheck.py (head 566-567), tests/test_value_rules_contract.py (head 257, 260-261), tests/test_scuba_projection_area_hook.py (head 8, 27-28, 30-31, 33). Each line's reason, the before-and-after pins and the probe scripts are in .plan/work/M04-T03/result.md (same text as evidence-r4.md) and .plan/work/M04-T03/pin-probe/.
verification: make lint pass ("All checks passed!").
Verify gates pass: seed strategy, forbidden paths, no added schema, both schema labels, no deleted historical literal.
19-file pytest list: pass, 2479 passed, 18 skipped (verify-r4.log).
make contract-smoke: pass, exit 0 (smoke-r4.log).
compare-run-outputs --digests: pass, "all 43 digests match" (digests-r4.log).
make test through hostload: pass, 22912 passed, 273 skipped, 34 xfailed, 0 failed (suite-r4.log). The slot was granted on the eighth `--wait 120` request; the first seven were deferred with exit 75.
Negative case: the area-hook test without the seeded key fails: "AssertionError: assert 'a7ec8a72e5c5...dcc59d782863f' == 'a31ea37b7e01...86255e4d5e32b'", FAILED test_empty_area_modules_leave_projection_unchanged[True].
Without the relabel lines, the class (iv) fixtures fail with "Invalid model assessment value at assessment.projection.redaction.strategy" (suite-r3.log, 9 parameters).
risks: In tests/test_model_rules_only.py the legacy label is set for every relabelled version (2026-10-27 to 2026-10-29), not just 2026-10-29, because all of those versions were written before 1.5.0. Only the 2026-10-29 schema pins the field.
Open for G (DEC-021, not blocking): on keyless runs the CSV gains one `pseudonym_notice` row and the JSON gains a top-level `pseudonym_notice` key.
questions_for_g: none
