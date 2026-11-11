## RESULT M02-T04
status: done
summary: Harvested job 8313471 (prompt v3, frozen; 1,184 judgements, 0 unparsed). On the test half the judge flags 208/211 defects and agrees with itself under swap on 269/289 pairs, both above 90 per cent. The deterministic checks catch 480/480 of their defects.
Saved the raw judgements, measures and SHA256SUMS in the run folder. The checks tree is frozen with the hash below, the two subcommands and offline tests are in place, and the accounting export covers all 7 jobs (11.39 GPU-hours). Docs updated.
No job of this task is left on the system.
changes: kit/judging/calibration/{raw-judgements.jsonl,runtime.json,dev-check-v3/pairs.jsonl,dev-check-v3/raw.jsonl,measures.json,SHA256SUMS}; kit/judging/README.md (result section); kit/runbook/README.md (section 9); kit/runs/usage/M02-T04/{jobs.json,accounting-judging.psv,SHA256SUMS}; notes in .plan/work/M02-T04/notes.md
verification: brief verify command (grep plus kit-check calibration) on the real kit against a scratch copy of the result under $TMPDIR: pass; kit-check checks and usage --result: pass; judging/tests 9/9 OK; checks/tests 54/54 OK; run folder SHA256SUMS checked complete; kit-check all on a scratch results folder: fail, only because other tasks' runs were absent (M01-T04 result, M01-T05 run in progress), not M02-T04
risks: The judge's preference for a genuinely fuller candidate is weak and depends on position: good controls preferred 24/39, consistent 22/39, and 17 of the 20 inconsistent pairs are good controls. M02-T05's preference bar must allow for this. | Three of the four jobs that ran used the interactive reservation, billed higher than the raw 11.39 GPU-hours. | Earlier prompt versions' partial runs stay on the project store under runs/m02t04/{smoke1,cal1,cal2,cal3}.
questions_for_g: none
### Findings
judge-calibration: pass
checks-sha256: 24d546e3ab8edb890f14fa42fe574b916bb58b9828f74db79eec173aed38bbc4
judge-model: openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a
deterministic-catch: 480/480 (wrong-verdict 80/80, invented-value 80/80, wrong-policy 160/160, contradictory-step 80/80, padding 80/80)
judge-detection: 208/211 (98.6 per cent; band 96.8-100.0)
judge-swap-consistency: 269/289 (93.1 per cent; band 90.7-95.2)
judge-good-preferred: 24/39
judge-template-copy-even: 39/39
judge-unparsed: 0
gpu-hours: judging 11.39
Test-half per class, flagged and consistent: wrong-verdict, invented-value, wrong-policy and contradictory-step 39/39 and 39/39 each; padding 37/39 and 38/39; missing-step 15/16 and 14/16.
Jobs: 8309634, 8310705 and 8312316 cancelled before starting; 8310618 failed (142 s); 8311250 and 8312812 cancelled mid-run (1,677 s and 2,973 s); 8313471 completed (5,456 s).
