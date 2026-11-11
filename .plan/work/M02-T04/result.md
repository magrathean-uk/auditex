## RESULT M02-T04
status: done
summary: Repair 1 done; prompt v3 and the flag rule unchanged. The test half's judge items were rebuilt from a test-only wording pool written before any run, then re-judged (job 8316503). The test-half rows of cal1 to cal3 (380 judgements) are moved unopened to a sealed read-only folder on the project store.
Checks v (value bound to its own field) and m (no template step left out) added. The template passes all eleven checks on 4,313/4,313 training cases; the review's crafted misbound variants now all fail. Checks tree re-frozen.
Strict reporting fixed before the re-run: detection in both orders, consistency over pairs whose texts differ, pooled figures beside them, identical good controls dropped. The verifier recomputes all of these and checks that dev and test wordings are disjoint. Calibration passes on the strict figures.
Extra fuller-text measurement done (job 8316504). Both jobs ran on the normal queue, nothing is left running, and 17.04 of the 96 GPU-hours are used.
changes: kit/judging/checks/{explchk/chk_v.py,explchk/chk_m.py,explchk/__init__.py,explchk/driver.py,run_checks.py,README.md,SHA256SUMS}; kit/judging/calibration/{build_calibration.py,assemble_raw.py,finalise.py,items.jsonl,pairs.jsonl,fuller-items.jsonl,fuller-pairs.jsonl,raw-judgements.jsonl,fuller-raw-judgements.jsonl,runtime.json,measures.json,SHA256SUMS,superseded-run1/*}; kit/judging/tests/test_kitcheck_judging.py; kit/judging/README.md; kit/checks/calibration.py and its line in kit/checks/SHA256SUMS; kit/runs/usage/M02-T04/{accounting-judging-repair1.psv,jobs.json,SHA256SUMS}; kit/runbook/README.md section 9; .plan/work/M02-T04/{notes.md,evidence.md}
verification: brief verify command (grep plus kit-check calibration) against a scratch copy of the result under $TMPDIR: pass; kit-check checks and kit-check usage on that copy: pass (17.0378 GPU-hours, 9 attempts); kit/judging/tests 12/12 OK (3 new); kit/checks/tests 54/54 OK; template all checks on 4,313 training cases: pass; raw files sha256-equal on both sides
risks: Strict consistency is 92.6 per cent, but its band's lower edge is exactly 90.0. A re-run could fall below the threshold (re-run variation was 27 of 32 equal verdicts). | Inside fuller texts the judge misses about one defect in eight (detection 198/227, band 81.2-92.4; padding 28/35 weakest). Its preference for a clean fuller text is weak (11 of 35 in both orders). M02-T05 should count wins only in both orders and rely on checks m and v for missing steps and misbound values. | Checks v and m are strict, so they may raise M02-T03's drop counts. A plain-words verdict reversal on not_met still passes the checks (26/32 of the review's crafted cases) and is left to the judge.
questions_for_g: none
### Findings
judge-calibration: pass
checks-sha256: 5fd732ad996d15ecfccc42af2cb48a359cf8b3ee7c67fc50c2dd2522d0719a63
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
Sealed: runs/m02t04/sealed-test-partials on the project store; cal1 12+16, cal2 166, cal3 186 test rows moved, not opened (the mover read pair ids only).
Jobs (repair): 8316503 test half plus one rebuilt dev pair, normal queue, COMPLETED 2,581 s; 8316504 fuller measurement, normal queue, COMPLETED 2,505 s. Earlier jobs as recorded (7).
Details: .plan/work/M02-T04/notes.md and evidence.md.
