## RESULT M03-T06
status: partial
summary: Pilot attempt 1 ran and missed (cause of partial: by instruction, no second attempt this round; the orchestrator decides the prompt revision).
  Runbook section 15 (data round, headroom rule and script, pass rule as one fenced block) and pilot-1/pass-rule.md were written before any job; the headroom list matches q5 (190 of 267); prompt v2 is the M02-T03 prompt plus R1-R5, with no row examples.
  Jobs 8408182 and 8408183 stayed pending on the normal queue (no free node) and were cancelled before they started. Teacher 8408244 and judge 8408389 then ran on the interactive reservation and completed (316 judgements, 0 unparsed). Nothing is left on the system.
  Of 158 judged pairs: 6 win in both orders, 10 lose in both, 103 tie in both (47 template copies), 36 split by order, 3 inconsistent. The pilot: fail line below is attempt 1's recomputed figure, not a final verdict.
changes: kit runs/data-round/pilot-1/** (24 files incl. SHA256SUMS, round-measures.json, filtered.jsonl, by-state.json, loss-reasons.json, scripts, job logs); kit runs/usage/M03-T06/{accounting-dataround.psv, jobs.json, SHA256SUMS}; kit runbook/README.md section 15 only; .plan/work/M03-T06/{notes.md, evidence.md, progress.md}. No repository edits.
verification: kit-check dataround --result on a scratch copy under $TMPDIR: pass (pass rule matches the runbook section; 2.6945 GPU-hours recomputed, 4 jobs)
  the brief's verify greps (REV-M03-T08 approve, pilot line, heldout-reads) on the same scratch copy: pass; kit-check usage --results .plan/work: pass
  sha256 checked on the system, in staging and in place: pass; targets, checks record and pairs rebuilt on the workstation are byte-identical to the system's; path, name and case-id scan of kit outputs and logs: clean
risks: The loss-reason counts by rule come from keyword matching, not reading; checked against the EXP reading on the probe, they over-count R3 and R5.
  The reservation is billed at 1.5x by the docs (about 4.04 GPU-hour equivalents against 2.69 raw).
  A revision reaching 139 of 190 both-order wins is unlikely (inferred): only 6 of the 111 judged texts that differ from the template won.
questions_for_g: none
### Findings
pilot: fail
pilot-attempts: 1
pilot-wins: 6 of 190
pilot-preference: 0.5112 band 0.5037-0.5206
pilot-unfiltered: win 6 loss 42 tie 219
heldout-reads: 0
round-gpu-hours: dataround 2.70
pilot-frozen-checks: 235 of 267 pass (77 of 77 template copies, 158 of 190 headroom); failures by check: m 19 (72 template step units missing), b 10, a 9, e2 6, e 5, e3 5, S 4, d 4, c 3, v 3, p 2; 2 targets did not parse
pilot-template-copies: 47 of 190 headroom targets equal their template (met 26, not_assessed 18, not_applicable 2, not_met 1)
pilot-unfiltered-preference: 0.4326 band 0.4082-0.4569
pilot-by-state: met unfiltered 0.4776, filtered 0.5149, wins 2 of 67; not_met 0.3171, 0.5244, 4 of 82; not_assessed 0.4861, 0.5000, 0 of 31; not_applicable 0.5000, 0.5000, 0 of 10
pilot-loss-reasons: 37 losing judgements (10 pairs lost in both orders, 17 single); keyword mapping: R3 33, R4 3, R5 3, R1 2, R2 0, unmatched 2
pilot-jobs: 8408182 and 8408183 cancelled before start (normal queue); 8408244 teacher, 525 s; 8408389 judge, 1,900 s; both four GPUs on the interactive reservation; 2.6944 GPU-hours
prompt-change-1: require at least two added sentences per row, each naming a field (from an evidence item other than e0) that the template does not name, with its exact INPUT value. Why: 47 copies can only tie, and the 56 differing ties added about 11 words, which the judge called equal.
prompt-change-2: keep the template steps word for word and split only at "; " inside a step, each part exactly as written; never swap a template step for an approved line. Why: 19 check-m failures, and 8 of the 10 both-order losses changed steps.
prompt-change-3: keep R1-R5 and add "a value you state is the value of the field you name in the same evidence item". Why: misreads (R3) still lead the losses, mostly not_met (34 of 42 unfiltered losses).
details: .plan/work/M03-T06/evidence.md and notes.md; kit runbook section 15
