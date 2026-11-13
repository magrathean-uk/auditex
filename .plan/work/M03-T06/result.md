## RESULT M03-T06
status: done
summary: Attempt 2 (the one revision, the last attempt) ran and missed, so the final verdict is pilot: fail and no third attempt runs. M03-T07, M03-T02's training and M03-T03 do not run; the question goes back to G (DEC-037, DEC-013).
  The revision reason was written to runbook section 15 and pilot-2/revision-reason.md before any job. Pass rule, headroom script and list, judge config, generate.py and round.py are byte copies of pilot-1; pilot-1 is unchanged (its SHA256SUMS still verifies).
  Teacher 8409220 waited 4 minutes on the normal queue and was cancelled before it started. Teacher 8409329 and judge 8409695 then ran on the interactive reservation and completed (272 judgements, 0 unparsed).
  Template copies fell from 47 to 3 and wins rose from 6 to 18, but frozen-check passes fell and unfiltered losses rose from 42 to 73. The main cause is misread field values in the added sentences.
changes: kit runs/data-round/pilot-2/** (25 files incl. revision-reason.md, prompt, targets, judgements, round-measures.json, round-jobs.json, SHA256SUMS); kit runs/usage/M03-T06/{accounting-dataround-pilot2.psv (new), jobs.json (+3 jobs), SHA256SUMS}; kit runbook/README.md section 15 only; .plan/work/M03-T06/{notes.md, evidence.md, progress.md}. No repository edits.
verification: the full verify command (REV-M03-T08 approve grep, pilot line, heldout-reads, kit-check dataround) against a scratch copy of the result lines under $TMPDIR: pass (pass rule matches the runbook; 5.5667 GPU-hours recomputed over 7 jobs)
  kit-check usage --results .plan/work: pass; sha256 checked on the system, in staging and in place: pass; targets, checks and pairs rebuilt on the workstation are byte-identical; name, path and case-id scan of the kit outputs: clean
risks: A stray kit/runs/data-round/pilot-1/__pycache__/headroom.cpython-315.pyc came from my count script (run without -B). kit-check ignores it and the storage rules bar me from deleting it; it can go to Trash on G's yes.
  The cancelled job's "by <numeric user id>" was cut from its State cell in the export (the parser reads only the first word; pilot-1's export has the same form). This is recorded in the runbook.
  The docs bill the reservation at 1.5 times: about 8.35 GPU-hour equivalents against 5.57 raw.
questions_for_g: none
### Findings
pilot: fail
pilot-attempts: 2
pilot-wins: 18 of 190
pilot-preference: 0.5337 band 0.5187-0.5487
pilot-unfiltered: win 18 loss 73 tie 176
heldout-reads: 0
round-gpu-hours: dataround 5.57
pilot-compare-wins: attempt 1 6 of 190; attempt 2 18 of 190
pilot-compare-filtered: attempt 1 0.5112 band 0.5037-0.5206; attempt 2 0.5337 band 0.5187-0.5487 (bar 0.729)
pilot-compare-unfiltered: attempt 1 win 6 loss 42 tie 219, pref 0.4326 band 0.4082-0.4569; attempt 2 win 18 loss 73 tie 176, pref 0.3970 band 0.3633-0.4307
pilot-compare-frozen-checks: attempt 1 235 of 267 (158 of 190 headroom); attempt 2 213 of 267 (136 of 190); failures in attempt 2: a 22, m 18, b 16, e 12, e3 11, S 10, v 9, d 7, c 6, e2 6, p 4; 4 did not parse
pilot-compare-template-copies: attempt 1 47 of 190 (met 26, not_assessed 18, not_applicable 2, not_met 1); attempt 2 3 (not_assessed 3)
pilot-compare-by-state: met unfiltered 0.4776 to 0.4478, filtered 0.5149 to 0.5672, wins 2 to 9 of 67; not_met 0.3171 to 0.2378, 0.5244 to 0.5183, 4 to 3 of 82; not_assessed 0.4861 to 0.5000, 0.5000 to 0.5231, 0 to 5 of 31; not_applicable 0.5000 to 0.2500, 0.5000 to 0.5500, 0 to 1 of 10
pilot-compare-gpu-hours: attempt 1 2.6944; attempt 2 2.8722; round 5.5667
pilot-loss-reasons: attempt 2 has 51 losing judgements (19 pairs lost in both orders, 13 single). Keyword counts: R3 42, R1 6, R4 6, R5 5, R2 0, unmatched 4. Read sample of 25 of 51: 21 misread or unsupported tenant claims (8 scope or negation words, 3 null stated for an empty list), 1 step typo, 1 filler, 2 dropped the link from the evidence to not_met
pilot-jobs: 8409220 teacher, normal queue, cancelled before start; 8409329 teacher, 702 s; 8409695 judge, 1,883 s; both four GPUs on the interactive reservation; nothing left on the system
details: .plan/work/M03-T06/evidence.md and notes.md (round 2 sections); kit runbook section 15
