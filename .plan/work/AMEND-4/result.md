## RESULT AMEND-4
status: done
summary: All nine review findings (B1 to B3, M1 to M6) are fixed in commit bf19a3f on task/AMEND-4-amend-4.
  The finding check is now one command, used both as the Definition of Done item and as the M03-T04 verify. It ties every score, reason count, hour figure and pin to the result line or kit file it comes from.
  On scratch files, good input passes. All 5 bad inputs the reviewer found passing now fail, and so do 10 more.
  Nothing the review passed was changed. master-plan.md is untouched at 150 lines.
changes: .plan/milestones/M03-explainer-training.md, .plan/BACKLOG.md, .plan/ARCHITECTURE.md
verification: percent.py --repo . --check: pass (65%), on the final commit. bash -n on all 15 Definition of Done and verify commands in M03: pass. Finding predicate on scratch: good rc 0, 11 bad inputs rc 1. Build-pick predicate: good rc 0, 4 bad inputs rc 1. Merge steps 2 to 5 on scratch copies: pass. Six reader lines diffed against main: identical. Details in .plan/work/AMEND-4/evidence-repair.md.
risks: The pin check needs AIRR_KIT set and `shasum` available; without either it fails rather than passes. | Merge step 4 leaves `<where and how G said it>` for the orchestrator to fill with G's own words.
questions_for_g: none
### Findings
B1: BACKLOG.md Later entry: the pointer to the ignored result-1.md is gone. The six reader lines are restored word for word from main, nested under the entry.
B2: M03-T04 now requires a `reopen-pins:` line with the sha256 of pilot-1's pass-rule.md, headroom.py, headroom.json and judge-config.json. The verify reads each value from pilot-1's SHA256SUMS, checks it against the file and checks the literal line. M03-T04 and the BACKLOG entry both say reopening first needs a kit task for a fresh round root, because the frozen dataround check refuses a third attempt.
B3: `finding-why: probe-real-faults 75 of 82 judge-errors 5 attempt2-misread 21 of 25 wins 18 of 190 needed 139` is now required. Each count is read from EXP-m03-losses `q3-judge:` and `q5-headroom:`, and from M03-T06 `pilot-loss-reasons:` and `pilot-wins:`.
M1: the spend, scores, reasons and pins lines are now matched with `grep -qxF`, so a dot is no longer a regex wildcard.
M2: the Definition of Done item and the M03-T04 verify are the same command. It includes `heldout-scores: none`, the probe and pilot source ties, and the bar taken from `(bar 0.729)` in M03-T06.
M3: the build-pick check reads only the "Explainer build pick" entry, stopping at the next heading. It requires `^- decision: none; model track parked`, `^- status: approved` and `^- approver: G`.
M4: "as it stands" is now "the DEC-013 bar unchanged (0.729, byte-identical pass-rule.md)" in BACKLOG.md and M03-T04.
M5: M03 has a new "Merge steps (DEC-046)" section with five exact commands for the orchestrator: the git mv of the probe file, the .gitignore line, the weights plus percent.py --write and --check, a separate "Explainer build pick" DEC, and the STATE.md re-baseline line added at the end of the list. M03-T02 points to step 1, and ARCHITECTURE.md line 56 now lists probe-result.md as tracked. I ran none of them in the repository.
M6: the "on reopening" list now says a judged build's held-out scoring needs its own score kind (`kit-check score builds`) before any build task, since M03-T05 covers validation runs only (DEC-032).
