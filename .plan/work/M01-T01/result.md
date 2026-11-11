## RESULT M01-T01
status: done
summary: Created the AIRR kit folder with a README (purpose, plan v4 task ids, `AIRR_KIT` convention) and `runbook/README.md`.
summary: The runbook maps all nine porting items to a runbook step. None is marked not needed, because item 1's module and billing calls are replaced, not dropped.
summary: Every PASS-airr and INV4-bases fact is tagged `[unverified]` until M01-T02 checks it.
summary: It covers G's login as a named step, base snapshots fetched onto project storage only, held-out and sealed rows kept off public storage, and the scheduler accounting export for `kit-check usage`.
changes: `kit/20261111-airr-v4/README.md` and `kit/20261111-airr-v4/runbook/README.md` (new)
verification: `grep -qx 'runbook: written'` on a scratch copy of the result lines, plus `test -s` on `kit/20261111-airr-v4/runbook/README.md`: pass. A scan of both documents for credentials and workstation paths found only old kit file names.
risks: 1) The accounting export fields and command are my proposal (`sacct`-style parsable output, with a budget balance report at stage start and end), to be fixed in M01-T02. 2) The runbook does not name the login command, because the kit may not carry host or account names. 3) The runbook says the 17 GB base snapshot size is told to G first, which conflicts with G's 11 Nov "no download size gate" note; I recorded both.
questions_for_g: none

### Findings
runbook: written
porting-items: 9/9 mapped to runbook steps
unverified-facts: tagged in runbook section 3, to be checked by M01-T02
login-step: named (step 1), with the worker route recorded in M01-T02
no-gpu-no-login-no-download: confirmed
