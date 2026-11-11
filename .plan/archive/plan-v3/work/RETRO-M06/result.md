## RESULT RETRO-M06
status: done
summary: Appended "## M06" to .plan/RETRO.md with Spend, Failures and retries, Proposed brief fixes and Keep. Ledger: 13 runs, $1.6385 recorded cost (codex2 costs blank), 8624 s, 1 non-zero exit. Failures: 7 rows, with 5 extra attempts or fix tasks. Ledger gaps were noted, not guessed.
changes: .plan/RETRO.md (46 additions, 0 deletions); .plan/work/RETRO-M06/evidence.md
verification: ledger selection and spend totals computed with python3 csv (13 rows, 0 malformed): pass; `git diff --numstat .plan/RETRO.md` shows additions only: pass
risks: Codex2 spend is unrecorded, so total cost is understated. The M06-T02 attempt 1 cause is not in the ledger or result.md.
questions_for_g: none
### Findings
- terra-verify.md (M06-T02): run release gates under `run-job` and wait on `.done`; the first release-check hit the 10-minute harness limit.
- terra-implement.md (M06-T01 to T01b): add `make lint` to the verify command so unused imports fail before review.
- terra-implement.md (M06-T01 to T01c): do not write a release date into a heading; the tagging step sets it.
- astra-validate.md (M06-T03): if the candidate SHA changes, rerun the gate and validation and record both on the new SHA.
- codex-review.md (REV-M06-T01, REV-M06-T01b): link `.venv` before verify; if blocked, report verify not run and do not approve. Recurs from M05.

Note: the SessionStart hook reported a clean-development lifecycle registration failure and asked for `clean-development doctor`. This brief forbids running it, so I did not run it. G should decide whether to run it.
