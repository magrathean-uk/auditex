## RESULT EXP-m03-losses
status: done
summary: The judge is right about the added text (classified by reading): 75 of 82 probe losing judgements name a real fault, mostly misread evidence (c, 50 judgements) or purpose and product claims (b, 22). Only 5 are judge errors on supported text, and the judge misses a real fault in 19 of 55 winning judgements.
  A data round can reach the bar only arithmetically (inferred unlikely from fault removal alone): 190 of 267 rows have headroom and 139 both-order wins with no losses are needed, against 13 today. It must drop purpose sentences, limit tenant claims to field = value copied from the input, keep every template line while splitting steps into their approved lines, judge-filter targets to both-order wins, copy the template where there is no headroom, and pass a validation-only pilot (2.5-13.2 GPU-hours) before training.
changes: .plan/work/EXP-m03-losses/{evidence.md, notes.md, progress.md, cls.tsv, tally.json, headroom.json, probe-outcomes.json, m03t01-sample.json, scripts/*.py} (all new); no kit or repository edits
verification: scripts/probe_sets.py reproduces probe-measures.json (win 13, loss 26, one-order 49, same position 5, judged ties 105): pass; scripts/m03t01_sets.py reproduces the EXP-m03-ties pooled outcomes (167/141/2,127/668/91/2): pass; scripts/bar_arith.py uses the checks/bar.py bootstrap unchanged: pass; scan of the work folder for absolute paths and names: clean (hits only in brief, dispatch and job-1, which this task did not write)
risks: One reader with no second reader; about 6 cases sit on the b/c or a/c boundary. | The tie sample (12 of 105) and the M03-T01 sample (40 of 417) give shares with wide error. | Training reach and budget are inferred from validation shares and measured rates; no training row was judged.
questions_for_g: none
### Findings
q1-set: measured. Probe: 56 losing pairs, 82 losing judgements (26 both-order = 52, 25 one-order, 5 same position), all read. M03-T01, 12 selected checkpoints: 417 losing pairs, 558 losing judgements (141 both-order = 282, 185 one-order, 91 same position), plus 8 check failures that were never judged. Stratified sample: 40 pairs, 53 losing judgements; strata are state x (both-order or one-order/same position): met 2/9, not_met 11/17, not_applicable 0/1; fixed seed.
q2-classes: classified by reading. Probe losing pairs by worst class present: c 32, b 16, a 6, d 2 (judgements c 50, b 22, a 8, d 2). By state: met 12 (c 8, b 2, a 2); not_met 33 (c 21, b 10, a 2); not_assessed 11 (b 4, c 3, a 2, d 2); not_applicable 0. By family: AAD 43 (c 26, b 12, a 5); SECURITYSUITE 4 (all c); EXO 4 (b 3, a 1); TEAMS 2 (both c); POWERBI 2 (b 1, d 1); POWERPLATFORM 1 (d). M03-T01 sample: c 25, b 12, a 3. By state: met 11 (b 6, c 4, a 1); not_met 28 (c 20, b 6, a 2); not_applicable 1 (c). By family: AAD 32, SECURITYSUITE 4, EXO 2, POWERBI 1, TEAMS 1.
q3-judge: classified by reading. Of 82 probe losing judgements, 75 give a real fault as the reason. In 2 the stated reason is wrong but the text has another real fault. 5 are judge errors, all supported a-class text called unsupported (7 judgements in total call supported text unsupported). The 52 both-order judgements split 48/2/2 the same way. The judge misses a real fault in 19 of 55 winning judgements (c 13, b 6). M03-T01 sample: 50 of 53 losing judgements name a real fault and 3 are judge errors; 7 of the 9 winning halves of same-position pairs missed a fault.
q4-winners: classified by reading. 42 winning pairs, 55 winning judgements: a 25 (32), c 10 (13), b 5 (6), d 2 (4). Both-order wins: a 7, d 2, c 3, b 1. Winners add field names with their values copied exactly, named rules or policies with state and mode, and facts linked across evidence sections. 36 of 42 winners have no purpose sentence (losers: 35 of 56) and 32 of 42 have no misread (losers: 24 of 56). 24 winners split a template step into its approved lines, and 19 of 55 winning reasons cite the steps (measured); 2 both-order wins rest on the split alone. In the tie sample, 7 of 12 ties are clean a-class texts.
q5-headroom: measured with a mechanical rule. Validation rows whose input holds material the template does not use: met 67/67, not_met 82/82, not_applicable 10/10 (environment value only), not_assessed 31/108 (0 of the 63 section_not_collected rows); 190 of 267 in all. If all 190 won in both orders and the rest tied, preference would be 0.856 (band 0.828-0.882), so 0.729 is reachable. The band clears the bar with 139 wins and no losses (73% of headroom rows), 152 wins with 10 losses, or 172 wins with the probe's 26 losses.
q6-teacher-rules: from reading tags, counted in probe judgements as losing judgements it addresses (pairs it fixes on its own), then winning texts it would change.
  R1, no purpose or risk sentence (also delete the prompt's "what the requirement protects against"): 30 (15); changes 7 of 55 winning texts.
  R2, no general product, licence or environment remark: 7 (4); changes 5.
  R3, tenant claims only as field = value copied from the input; no negation or "all"/"only" unless the field shows it; never re-explain the rule reason: 50 (29); changes 13.
  R4, keep every template sentence and step; split a step only into its approved lines; never merge, drop or repeat: 13 (4); changes 1, and keeps the 33 split-step winning judgements.
  R5, no filler: 1 (1); changes 0.
  Together the rules address 77 of 82 losing judgements; the other 5 are judge errors.
q7-training-reach: inferred from validation shares per state. Of 2,738 training targets:
  - 2,143 (78.3%) have no losing judgement, including 654 template copies.
  - 595 (21.7%) lose and need regenerating or dropping.
  - 408 (14.9%) have a winning judgement and 142 (5.2%) win in both orders.
  - To aim at the bar, about 1,944 headroom rows (71.0%) need regenerating; 652 rows (23.8%) have no headroom and stay template copies.
q8-budget: measured inputs:
  - Teacher: Mistral-Small-4-119B (open weights, bf16), run on the cluster with greedy decoding; 13.01 GPU-hours for about 3,973 candidates (2.9-3.3 per 1,000).
  - Judge: 18.9-25.3 GPU-seconds per judgement (19.1 across M03-T01).
  - Gemma 4 31B: 2.27-2.32 GPU-hours to train one seed; 4.58-4.96 for the whole prep job including generation at 5 checkpoints; about 0.42 to generate validation outputs at one checkpoint.
  Design figures, GPU-hours low-high:
  - Regenerate the 2,276 headroom targets (train and validation): 6.6-30.0.
  - Judge-filter them in both orders: 23.9-96.0.
  - Retrain three seeds: 6.8-14.9.
  - Score three seeds at one or two checkpoints each: 7.2-25.0.
  - Total 45-166, plus the validation pilot at 2.5-13.2.
