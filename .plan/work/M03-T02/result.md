## RESULT M03-T02
status: partial
summary: Round 1 was the probe only (DEC-034): no training job, no sweep and no selection rule, so the status is partial.
  Of 267 validation rows, 198 targets differ from the template and 69 are identical; all 267 pass the frozen checks. The judge, judge config and prompt v3 were unchanged and judged the 198 in both orders (396 judgements, one four-GPU job, 8388014, COMPLETED, 2,501 s).
  The teacher targets do not beat the template: preference 0.4757 (band 0.455-0.498), so training on this data cannot reach the bar of 0.729. This is the DEC-034 case: G chooses the next step before any large-sweep job.
  Collected and hashed under kit/runs/large-ceiling-probe. Usage is in kit/runs/usage/M03-T02. Runbook section 14 is added. The queue on the system is empty.
changes: kit runs/large-ceiling-probe/{scripts/probe.py, scripts/probe.sbatch, pairs-targets.jsonl, targets-checks.jsonl, judge/raw-pairs-targets.jsonl, runtime.json, job-8388014.log, probe-measures.json, SHA256SUMS}; kit runs/usage/M03-T02/{accounting-large-probe.psv, jobs.json, SHA256SUMS}; kit runbook/README.md section 14; .plan/work/M03-T02/{notes.md, progress.md}. No repository edits.
verification: kit-check usage against a scratch copy of the result lines under $TMPDIR: pass (2.7789 GPU-hours, 1 attempt).
  sha256 of the copied artefacts matched on the system, in staging and in place; both SHA256SUMS files rechecked: pass. Path and name scan of the kit outputs: clean.
  The brief's verify command against the same scratch copy fails, as expected this round: by instruction there is no heldout-reads line, and runs/large does not exist yet.
risks: The measures file is named probe-measures.json, not measures.json, because kit-check all reads every measures.json under runs/ as a scored run; the probe folder is evidence only.
  Until runs/large exists, kit-check all will report M03-T02 as having a result file but no verified run.
  The 69 identical rows were counted as ties without being judged, as the brief sets; the ties in M02-T05 support this (template copies tied 39 of 39).
questions_for_g: The training data's own ceiling on this judge is 0.476 (0.470 on the held-out mix), against the bar of 0.729. Under DEC-034 and DEC-013, choose one: new training data aimed at what the judge rewards (judge-filtered targets or a preference stage); revisiting rule 2 of the bar; or parking Track B. My recommendation: park Track B unless you want to fund a data round. In the losing judgements the judge gives faithfulness to the template 48 times out of 52, so fuller text is read as unsupported.
### Findings
ceiling-probe: complete
target-preference: 0.4757 (wins 13, losses 26, ties 174 of 267)
target-preference-by-state: met 0.4701 (wins 3, losses 7, ties 44 of 67); not_met 0.4634 (wins 9, losses 15, ties 25 of 82); not_assessed 0.4861 (wins 1, losses 4, ties 95 of 108); not_applicable 0.5000 (ties 10 of 10)
target-preference-heldout-mix: 0.4695
gpu-hours: large 2.78
target-count: 198 of 267 differ from the template (met 65, not_met 82, not_assessed 44, not_applicable 7); 69 identical, counted as ties; 267 of 267 pass the frozen checks
target-outcomes: one-order 49 (met 12, not_met 29, not_assessed 8), same position in both orders 5 (met 1, not_met 4), unparsed 0, tie in both orders among judged pairs 105
target-flagged-share: 0.1910 overall; met 0.1642, not_met 0.3537, not_assessed 0.1019, not_applicable 0.0000
target-band: 0.4551-0.4981 (bar.py bootstrap); floor holds; win_pass false
heldout-mix-source: counts only, from the M02-T06 result lines (met 86, not_met 110, not_applicable 15, not_assessed 10); no held-out row opened
probe-job: 8388014 COMPLETED, normal queue, 2,501 s on four GPUs, 2.7789 GPU-hours; nothing left running or pending
details: .plan/work/M03-T02/notes.md and kit runbook section 14
