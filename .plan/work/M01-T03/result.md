## RESULT M01-T03
status: done
summary: Item 1: `usage` now checks that every start it sees has a finished record. A RUNNING requeue at a new start fails even when an earlier attempt finished. A pending row with no start needs a later finished attempt. Start must be a timestamp, Unknown or None, and an attempt with no start may not show elapsed time.
summary: Item 11: AllocTRES is now checked item by item (`<tres>=<count>`, no repeats), and any attempt that ran must show `cpu=<n>`. Any GPU-like item it does not recognise fails. A job counts as a GPU job unless `jobs.json` sets `"allocation": "cpu"`. A GPU job that ran with an empty, missing, zero or unknown GPU count fails, and a job declared CPU that shows a GPU also fails.
summary: Item 12: `all --results` and `usage --results` now fail (exit 1) on a missing or unreadable folder before discovery. A result file that cannot be read now fails instead of being skipped.
summary: The v10 recipe source is unchanged from round 1 (see the Findings line). Known limits are written in kit/20261111-airr-v4/bin/README.md, and round 3 notes are in .plan/work/M01-T03/notes.md.
changes: kit/20261111-airr-v4/bin/{kitcheck.py,README.md,SHA256SUMS}; kit/20261111-airr-v4/checks/usage.py; kit/20261111-airr-v4/checks/tests/{test_check_usage.py,_support.py}; .plan/work/M01-T03/notes.md (round 3 appended); no repository edits
verification: `"$AIRR_KIT/bin/kit-check" selftest --result <scratch file under $TMPDIR/m01t03-verify/M01-T03/result.md holding the two Findings lines below>` - pass (exit 0), run on the final files
verification: checks/tests 51 tests - pass (7 new usage cases covering items 1, 11 and 12); trainer/tests 17 - pass; started at load average 11.4
verification: `kit-check all --results .plan/work` (repository) - pass, 2 checks (M01-T02, M02-T01); `kit-check all --results /nonexistent-folder` and `usage --results /nonexistent-folder` - fail as intended (exit 1)
risks: `usage` only trusts the exports it is given. A job missing from both `jobs.json` and every export cannot be seen offline, so the milestone reviewer must compare the inventory with the scheduler on the system.
risks: Start times are compared as `sacct` prints them, so all exports for one task must come from one cluster. `gres/gpumem` and `gres/gpuutil` are treated as usage measures, not GPU counts. The other risks from round 2 still stand: `checks/SHA256SUMS` must be added to later tasks' `files:` lines, and `selection.json` paths must be stripped or that file kept private.
risks: The new `"allocation": "cpu"` field in `jobs.json` is an interface change. Run tasks that submit CPU-only jobs must declare it.
questions_for_g: none
### Findings
trainer-selftest: pass
auditex-imports: 0
v10-recipe-source: kit/20261104-*-pull/adapter/results-round5-adapter-ministral3-8b-20261030T0250Z.tar round4-ministral3-8b-20261030T0250Z/{adapter/training_args.bin,adapter/adapter_config.json,auditex-training-input.json,auditex-training-run.json,trainer_state.json}
v10-recipe: lora r16 alpha32 dropout0.05 all-linear; lr 5e-05 cosine warmup 0.05; epochs 1; batch 1 x accum 2 x 4 ranks; max_length 4096; save/eval 50; load_best_model_at_end false; seed 42
eval-loss-selection: off (not overridable; validated in pack and SFTConfig)
pins: equal to the old environment file (torch 2.14.1, transformers 5.20.1, trl 1.16.0, peft 0.21.2, accelerate 1.15.0, datasets 5.1.0)
kit-check-interface: frozen (bin/SHA256SUMS regenerated for round 3; added check modules go in checks/SHA256SUMS)
review-REV-KIT-01-round2: items 1, 11, 12 fixed; same-class sweep closed unreadable result files and start/elapsed coherence; remaining limits named in bin/README.md
