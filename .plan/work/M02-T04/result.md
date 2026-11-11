## RESULT M02-T04
status: done
summary: Repair 2, CPU only. Prompt v3, the flag rule, items, pairs and raw judgements are byte-identical, and nothing was re-judged.
Check m: a paraphrase is now read only from a candidate step's text outside other required units' verbatim text, and each candidate step stands in for one template step only, so a sibling step can no longer satisfy a left-out step. Check v now reads two-letter keys (`Id`).
Over 4,313 training cases: unique-unit single omissions passing every check 0/5,348 (was 146), short-key crafted variants passing v 0/66 (was 8), template 4,313/4,313, results of S, a-e3 and p unchanged.
Checks tree re-frozen and calibration re-finalised. Only checks-sha256 changed, and every judge figure equals result-3. The kit READMEs now state exactly what m and v guarantee.
changes: kit/judging/checks/{explchk/chk_m.py,explchk/chk_v.py,README.md,SHA256SUMS}; kit/judging/tests/{test_checks_m_v.py,sweep_m_v.py} (new); kit/judging/README.md; kit/judging/calibration/{measures.json,SHA256SUMS} (rewritten by the unchanged finalise.py); kit/checks/SHA256SUMS unchanged (its modules unchanged); .plan/work/M02-T04/notes.md (repair round 2 appended)
verification: brief verify command (grep plus kit-check calibration) on a scratch copy of this block under $TMPDIR: pass; kit-check checks: pass (3241cf2c...); kit-check usage: pass (17.0378 GPU-hours, 9 attempts); kit judging/tests 17/17 OK (5 new; all 5 fail on the repair-1 tree); kit checks/tests 54/54 OK; review scripts r1-r4 and t1-t8 re-run on the kit: rc 0, counts in notes.md; kit/judging/tests/sweep_m_v.py: counts below
risks: Strict consistency is 92.6 per cent, but its band's lower edge is exactly 90.0. Inside fuller texts the judge misses about 1 defect in 8 (198/227), and its preference for a clean fuller text is weak (11/35 in both orders), so M02-T05 should count wins only in both orders. | M02-T05 may rely on m and v exactly as follows, and for nothing more. m fails a not_met output that leaves out a template step carrying a baseline unit that no kept step holds verbatim, and a not_assessed output that lacks either what-to-collect line. v fails a value bound by is, set to, = or : to a named evidence field that does not hold it, and several values in one sentence that no single record holds. Neither catches: an omitted step all of whose units are verbatim elsewhere (21) or that has no unit (185); step order; prose values without a binder; values that some record holds (6 flips); plain-words verdict reversals (26/32). Stricter m may raise M02-T03 drop counts. | kit/runbook/README.md section 9 still names the old tree hash, and the project-store copy of kit/judging/ still holds the old checks tree. Both are outside this files line; re-sync the copy before M02-T03 runs.
questions_for_g: none
### Findings
judge-calibration: pass
checks-sha256: 3241cf2ccd799aa49496417c3c484ba807daad106df40d22cd561d3d1f0be44e
judge-model: openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a
deterministic-catch: 611/611 (wrong-verdict 80/80, invented-value 158/158, wrong-policy 160/160, contradictory-step 80/80, missing-step 53/53, padding 80/80)
judge-detection: 192/195 (98.5 per cent; band 96.4-100.0)
judge-detection-pooled: 194/195 (99.5 per cent; band 98.5-100.0)
judge-swap-consistency: 213/230 (92.6 per cent; band 90.0-95.2)
judge-swap-consistency-pooled: 252/269 (93.7 per cent; band 91.5-95.9)
judge-good-controls: preferred in both orders 11/35, preferred on balance 23/35, consistent 21/35, flagged worse 2/35
judge-template-copy-even: 39/39
judge-wordings: dev 13 planted sentences, test 30, shared 0
judge-detection-fuller: 198/227 (wrong-verdict 33/35, invented-value 35/35, wrong-policy 34/35, contradictory-step 32/35, padding 28/35, missing-step 17/25, misbound-value 19/27; pooled 211/227; band 81.2-92.4)
judge-unparsed: 1
gpu-hours: judging 17.04
m-middle-step-omissions-passing: 0/5348
v-short-key-variants-passing: 0/66
template-all-checks: 4313/4313
Checks (repair 2, tree 3241cf2c...): m fails all 5,348 unique-unit single omissions (first 1,467, middle 2,599, last 1,282) and all 3,022 not_assessed omissions. v: flips 6/477 pass (one record holds the stated combination), swaps 0/2,410, numbers 0/296. Judged items through m's paraphrase rule: 0/552.
Sealed: runs/m02t04/sealed-test-partials on the project store; cal1 12+16, cal2 166, cal3 186 test rows moved, not opened (the mover read pair ids only).
Jobs (repair 1): 8316503 test half plus one rebuilt dev pair, normal queue, COMPLETED 2,581 s; 8316504 fuller measurement, normal queue, COMPLETED 2,505 s. Earlier jobs as recorded (7). Repair 2 ran no job.
Details: .plan/work/M02-T04/notes.md (repair round 2) and evidence.md.
