## RESULT M03-T12
status: done
summary: Pilot 4 (Qwen3.8-Flash-Next writer, four candidates per row, first passing kept, prompt v3, the one attempt) ran and misses: 38 of 190 headroom rows won in both orders and the filtered preference band 0.5506-0.5918 lies far below 0.729, so `pilot: fail` and the same-job line closes (DEC-102). Check failures fell to 3 of 190 (attempt 3: 29), but the judge still ties or splits most pairs. 102 jobs (95 writer shards of two rows, six first submissions failed on a Triton cache race and were resubmitted, plus the judge), 439.9112 GPU-hours, nothing left on the system. Notes in `.plan/work/M03-T12/notes.md`; kit runbook section 15, "Attempt 4".
changes: kit only (`kit/20261111-airr-v4/`): `runs/data-round/pilot-4/**` (scripts, shards, joined and scored files, measures, logs, SHA256SUMS), `runs/usage/M03-T12/**`, `runbook/README.md` (section 15, attempt 4 appended). No repository change.
verification: the verify line on a scratch copy of this block under `$TMPDIR` (grep for `pilot: fail` and `heldout-reads: 0`, then `kit-check dataround --result`), pass; shards rejoined and targets rebuilt on the workstation, byte-identical to the collected files, pass; `kit-check dataround` for M03-T09, M03-T10 and M03-T11, pass; both SHA256SUMS verify and the privacy scan is clean, pass.
risks: (1) candidates are seeded per batch, so a rerun with another shard layout is not reproducible (the raw rows are kept). (2) A row whose four candidates all fail is scored as a loss unfiltered and the template filtered; the M03-T16 verifier agrees (3 rows). (3) The keyword loss mapping is coarse (5 losing judgements only).
questions_for_g: none
### Findings
pilot: fail
pilot-attempts: 4
pilot-wins: 38 of 190
pilot-preference: 0.5712 band 0.5506-0.5918
pilot-unfiltered: win 38 loss 3 tie 226
heldout-reads: 0
round-gpu-hours: dataround 439.9112
pilot-compare-wins: attempt 1 6 of 190; attempt 2 18 of 190; attempt 3 11 of 190; attempt 4 38 of 190
pilot-compare-filtered: attempt 1 0.5112 band 0.5037-0.5206; attempt 2 0.5337 band 0.5187-0.5487; attempt 3 0.5206 band 0.5094-0.5337; attempt 4 0.5712 band 0.5506-0.5918 (bar 0.729)
pilot-compare-unfiltered: attempt 4 win 38 loss 3 tie 226, pref 0.5655 band 0.5431-0.5880
pilot-compare-frozen-checks: attempt 4 264 of 267 (187 of 190 headroom); 0 did not parse; failures: S 3
pilot-compare-template-copies: attempt 4 0 of 190 targets equal to the template; 152 of 190 rows filtered to their template
pilot-candidates: 760 written, 712 pass every frozen check; 187 of 190 rows keep a target (sample 0 in 177, sample 1 in 9, sample 2 in 1); 3 rows have no passing candidate; none reached the token cap
pilot-compare-by-state: attempt 4 met filtered 0.6045, wins 14 of 67; not_met 0.6037, 17 of 82; not_assessed 0.5278, 6 of 31; not_applicable 0.5500, 1 of 10
pilot-loss-reasons: attempt 4 has 5 losing judgements (0 pairs lost in both orders). Keyword counts: R5 3, R1 1, R3 1, R2 0, R4 0, unmatched 1
pilot-jobs: 95 writer shard jobs (89 completed first time; shards 4, 23, 69, 80, 88 and 90 failed in their first batch and were resubmitted, then completed) and judge 1,894 s; four GPUs each, normal queue; 6 failed jobs cost 2.4478 GPU-hours; nothing left on the system
details: .plan/work/M03-T12/notes.md; kit runbook section 15
