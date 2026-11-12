## RESULT CHK-M04-T03
status: partial
summary:
check: fail
checked: 9f38936ce973ccb5ff34210cb4bf7649a1480431
verify deferred: heavy slot busy (exit 75 after 120s); neither the verify nor any negative case ran.
changes: none (evidence written to .plan/work/CHK-M04-T03/evidence.md and progress.md)
verification:
- hostload.sh run --strict --wait 120 -- verify command: exit 75, deferred, fail
- negative cases: 0 of 0 run
risks: the check is unfinished and needs a rerun when a heavy slot is free; git status --porcelain is clean (the .venv link I added was removed)
questions_for_g: none

### Findings
- Verify: not run. Both slots were held, one by a job under the `porn` project's records and one by M03-T13. Output is in .plan/work/CHK-M04-T03/evidence.md.
- Negative cases: none run. The diff adds many checks (the pseudonym key refusals, `prepare-key` exit 2, the lock-error handling and the Makefile smoke assertion), and each needs a negative case on rerun.
