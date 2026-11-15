## RESULT M03-T10
status: done
summary: Pilot 3 (prompt v3, the one attempt, option 2) ran and misses: 11 of 190 headroom rows won in both orders, and the filtered preference band 0.5094-0.5337 lies far below 0.729. That is `pilot: fail`. Track B stops under Amendment 8, with no revision and no fourth attempt. Two jobs, both completed first time, 2.7689 GPU-hours, nothing left on the system. Details and the three-attempt table are in kit runbook section 15, "Attempt 3", and in `.plan/work/M03-T10/notes.md`.
changes: kit only (`kit/20261111-airr-v4/`): `runs/data-round/pilot-3/**` (scripts, targets, judgements, measures, logs, SHA256SUMS), `runs/usage/M03-T10/**`, `runbook/README.md` (section 15, appended). No repository change.
verification: grep for `^pilot: (pass|fail)$` and `heldout-reads: 0` plus `kit-check dataround --result` on a scratch `M03-T10/result.md` under `$TMPDIR`: pass. Targets, checks and pairs rerun on the workstation: byte-identical to the collected files. Both SHA256SUMS verify, the privacy scan is clean, and `kit-check dataround` for M03-T06 and M03-T09 still passes.
risks: (1) `kit-check usage --result` refuses M03-T10 (no budget-table stage; dataround tasks claim via `round-gpu-hours`), while `usage --results` passes. (2) Attempt 3 `round.py` differs from pilot-2's by one token (`task` M03-T10). (3) Keyword loss mapping over-counts R3 and R5, as noted for attempt 1.
questions_for_g: none
### Findings
pilot: fail
pilot-attempts: 3
pilot-wins: 11 of 190
pilot-preference: 0.5206 band 0.5094-0.5337
pilot-unfiltered: win 11 loss 43 tie 213
heldout-reads: 0
round-gpu-hours: dataround 2.7689
pilot-compare-wins: attempt 1 6 of 190; attempt 2 18 of 190; attempt 3 11 of 190
pilot-compare-filtered: attempt 1 0.5112 band 0.5037-0.5206; attempt 2 0.5337 band 0.5187-0.5487; attempt 3 0.5206 band 0.5094-0.5337 (bar 0.729)
pilot-compare-unfiltered: attempt 3 win 11 loss 43 tie 213, pref 0.4401 band 0.4139-0.4663
pilot-compare-frozen-checks: attempt 3 238 of 267 (161 of 190 headroom); 10 did not parse; failures: m 17, e 15, b 14, S 13, a 13, c 11, e3 11, d 10, e2 10, p 10, v 10
pilot-compare-template-copies: attempt 3 5 of 190
pilot-compare-by-state: attempt 3 met filtered 0.5373, wins 5 of 67; not_met 0.5366, 6 of 82; not_assessed 0.5000, 0 of 31; not_applicable 0.5000, 0 of 10
pilot-loss-reasons: attempt 3 has 37 losing judgements (14 pairs lost in both orders). Keyword counts: R3 26, R4 9, R5 4, R1 0, R2 0, unmatched 3
pilot-jobs: 8463535 teacher, 942 s; 8463545 judge, 1,550 s; both four GPUs, normal queue, completed on first submission; none cancelled or retried; nothing left on the system
details: .plan/work/M03-T10/notes.md; kit runbook section 15
