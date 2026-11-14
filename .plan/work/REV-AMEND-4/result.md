## RESULT REV-AMEND-4
status: done
summary: verdict: approve
  reviewed: bf19a3f6fe43c01071d0fac04afdca6f3be3411a
  All nine findings are fixed. The five bad inputs that passed before now fail, five more bad inputs also fail, and good input passes.
  The diff changes only 3 of the 4 permitted plan files and only the lines the findings need. master-plan.md is unchanged at 150 lines.
  Notes are in .plan/work/REV-AMEND-4/evidence-2.md.
changes: .plan/work/REV-AMEND-4/evidence-2.md, .plan/work/REV-AMEND-4/progress.md (review notes only)
verification: percent.py --repo . --check: pass (65%). The DoD at M03 line 17 and the M03-T04 verify at line 71 are byte-identical, and bash -n passes on both and on line 18. Scratch predicates: good input rc 0; 10 bad inputs rc 1. Each of the six reader lines found word for word in main's BACKLOG.md. Merge steps 3 to 5 run on a scratch copy of .plan: rc 0 each, weights sum to 100, result 65%.
risks: Merge step 4 writes `approver: G (<where and how G said it>)`. The build-pick DoD passes even if that placeholder is never filled in, so the orchestrator must replace it with G's words. | Merge step 3 needs PLAN_SCRIPTS set to the plan skill's scripts folder.
questions_for_g: none
### Findings
B1 closed: .plan/BACKLOG.md:16-22. The pointer to the ignored file is gone, and the six reader lines are back word for word, nested under the entry.
B2 closed: .plan/milestones/M03-explainer-training.md:68 and :71, .plan/BACKLOG.md:16. reopen-pins is checked against pilot-1's SHA256SUMS and the files themselves, and the kit task for a fresh round root is named. Altered pins fail and so does an unset AIRR_KIT.
B3 closed: M03-explainer-training.md:65 and :17/:71. finding-why is required, and each count is read from q3-judge, q5-headroom, pilot-loss-reasons and pilot-wins. A missing line fails, and so does "wins 19 of 190".
M1 closed: M03-explainer-training.md:17/:71. The lines are matched with grep -qxF, so "basecmp 235x67" now fails.
M2 closed: M03-explainer-training.md:17/:71. One identical command checks heldout-scores, the source ties and the bar from "(bar 0.729)". A missing heldout-scores line fails, and so does a source bar of 0.700.
M3 closed: M03-explainer-training.md:18. The check reads only the "Explainer build pick" entry and requires "- decision: none; model track parked" and "- status: approved". The "revisit... none parked" decision fails, a pending status fails, and an approved entry that follows a pending one does not leak into the check.
M4 closed: .plan/BACKLOG.md:16 and M03-explainer-training.md:68 say "the DEC-013 bar unchanged (0.729, byte-identical pass-rule.md)".
M5 closed: M03-explainer-training.md:34-39 lists 5 exact commands, with references at :53 and .plan/ARCHITECTURE.md:56. Steps 3 to 5 pass on scratch; step 2 appends cleanly because .gitignore ends with a newline.
M6 closed: .plan/BACKLOG.md:16 lists the `kit-check score builds` score kind among the things that come back on reopening.
New defects: none blocking. Fill in the approver placeholder by hand before committing merge step 4 (M03-explainer-training.md:38).
