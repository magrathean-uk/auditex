## RESULT M03-T15
status: done
summary: The one validation pilot ran on all 231 questions (writer: four candidates each, first passing the hard checks kept; judge: both orders) and the pass rule gives `qa-pilot: fail`.
Hard-check rate 0.9015 (833 of 924), below 0.95; preference 0.5281 (band 0.5065-0.5519), below 0.729. Wins 21, ties 202, losses 8 (eight what-changed questions with no passing candidate).
Nine whole-assessment questions ran out of GPU memory at batch size two. They were rerun at batch size one through two new files with their own hashes; the frozen files are unchanged.
Jobs: array 8480999 plus repairs 8481235, 8481581 and 8481853. Total 240 jobs (nine failed, all inventoried), 275.7845 GPU-hours. Nothing is left running or queued; jobs 8481194 and 8481195 under the same user belong to another task and were not touched.
Kit-check qa passes on a scratch copy of the result under $TMPDIR. Notes: .plan/work/M03-T15/notes.md, evidence.md.
changes: kit/runs/qa/pilot-1/ (frozen before the first job: writer_prompt.py, generate.py, writer-config.json, judge_prompt.py, judge.py, judge-config.json, pilot-config.json, pass-rule.md, shard.sbatch, sums kept as frozen-SHA256SUMS; repair: writer-config-batch1.json, shard-batch1.sbatch, repair-SHA256SUMS; results: answers.jsonl, judge/raw-pairs.jsonl, selection.jsonl, writer/raw-candidates.jsonl, results.json, logs/, join.py, README.md, SHA256SUMS); kit/runs/usage/M03-T15/ (accounting-qa.psv, jobs.json, SHA256SUMS); kit/runbook/README.md (section 16 pilot paragraph only); .plan/work/M03-T15/ notes.md, evidence.md, progress.md. No repository edits or commits.
verification: verify command (grep qa-pilot, grep heldout-reads, kit-check qa --result) on a scratch result copy under $TMPDIR, pass; kit-check qa without --result, pass; frozen files re-hashed before the join, pass; 240 of 240 job logs show held-out folder absent and heldout-reads 0, pass; scan for paths, host, project and user names in the pilot and usage folders, pass
risks: The batch-one repair is a change made after the first job, which the brief froze. It changes batching and sampling seeds for nine questions only; the model, prompt, decoding and checks are the same. It does not change the verdict, because the hard-check rate and the preference both miss. Separately, the pass-rule block in runbook section 16 is an older text than the pinned runs/qa/baseline/pass-rule.md, so `kit-check qa --set` would likely fail its runbook-verbatim check; this predates the task, was left untouched and is a follow-up for M03-T14's owner.
questions_for_g: none
### Findings
qa-pilot: fail
qa-hardcheck-pass-rate: 0.9015 (833/924)
qa-pilot-preference: 0.5281 band 0.5065-0.5519
heldout-reads: 0
round-gpu-hours: qa 275.7845
qa-pilot-wins: 21
qa-pilot-ties: 202
