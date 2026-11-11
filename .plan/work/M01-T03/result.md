## RESULT M01-T03
status: done
summary: Review items 1 and 3: every row that describes one job and one start must agree on elapsed time, allocation and node count. This covers open, REQUEUED and terminal rows, in one export or across several. Terminal rows must also agree on state. A mismatch fails and names both rows, so no larger figure is dropped.
summary: Review item 2: a generic GPU count that contradicts the typed GPU counts now fails before the CPU or GPU declaration is applied. Generic 1 with typed 4 fails, and so does generic 0 with typed 4 on a CPU job.
summary: Review item 4: kit/20261111-airr-v4/bin/README.md now names what the check cannot see. It also says every stage total, and their sum, is compared with the awards portal's used figure at milestone close, and that selection.json holds resolved paths and is kept private or stripped.
summary: Review item 5: three new test cases and one sub-case gave 10 failures on the round 3 code. Two existing tests now use RUNNING rows that agree with the finished record. Round notes: .plan/work/M01-T03/notes.md (Round 4).
changes: kit/20261111-airr-v4/checks/usage.py; kit/20261111-airr-v4/checks/tests/test_check_usage.py; kit/20261111-airr-v4/bin/README.md; kit/20261111-airr-v4/bin/SHA256SUMS (regenerated); .plan/work/M01-T03/notes.md (round 4 appended); no repository edits
verification: `"$AIRR_KIT/bin/kit-check" selftest --result <scratch copy at $TMPDIR/m01t03-r4/M01-T03/result.md holding the Findings lines below>` - pass (exit 0), run on the final files
verification: checks/tests 54 tests - pass; the new tests against the round 3 code - fail as intended (10 sub-failures); trainer/tests 17 - pass
verification: `kit-check usage --results .plan/work` and `kit-check all --results .plan/work` (repository) - pass (M01-T02 bringup 0.0192, M02-T01 heldout 0)
risks: The check now fails any export taken while a job runs, because its open row cannot match the terminal record. Run tasks must take exports only after the jobs end.
risks: Node count is compared only where both rows have the NNodes column; the required columns are unchanged so the export layout stays the same. Rows with no start keep the round 3 rule.
risks: Still open from earlier rounds: later tasks' files: lines need checks/SHA256SUMS, and run tasks that submit CPU-only jobs must declare "allocation": "cpu".
questions_for_g: none
### Findings
trainer-selftest: pass
auditex-imports: 0
v10-recipe-source: kit/20261104-*-pull/adapter/results-round5-adapter-ministral3-8b-20261030T0250Z.tar round4-ministral3-8b-20261030T0250Z/{adapter/training_args.bin,adapter/adapter_config.json,auditex-training-input.json,auditex-training-run.json,trainer_state.json}
v10-recipe: lora r16 alpha32 dropout0.05 all-linear; lr 5e-05 cosine warmup 0.05; epochs 1; batch 1 x accum 2 x 4 ranks; max_length 4096; save/eval 50; load_best_model_at_end false; seed 42
eval-loss-selection: off (not overridable; validated in pack and SFTConfig)
pins: equal to the old environment file (torch 2.14.1, transformers 5.20.1, trl 1.16.0, peft 0.21.2, accelerate 1.15.0, datasets 5.1.0)
kit-check-interface: frozen (bin/SHA256SUMS regenerated for round 4; added check modules go in checks/SHA256SUMS)
review-REV-KIT-01-round3: items 14, 15 and the general fail-closed rule fixed with offline tests that fail before the change; blind spots, portal comparison and selection.json handling named in bin/README.md
