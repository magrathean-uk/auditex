## RESULT RETRO-M02
status: done
summary: Appended "## M02" to .plan/RETRO.md (Spend, Failures and retries, Proposed brief fixes, Keep). 42 runs (41 M02/REV-M02 rows plus REV-M03-T04, which names M02-T05), $24.9944 recorded cost, 9229 s as recorded, 4 non-zero exits. 21 codex/codex2 rows have blank cost, so the total is a floor. The 4 failures are 2 codex2 partials on M02-T05 and 2 sol claude-5 exit-5 failures on M02-T03 and M02-T04. Causes are recorded only for M02-T04 (SIGTERM when the launching shell stopped).
changes: .plan/RETRO.md (appended only, 49 additions, 0 deletions); .plan/work/RETRO-M02/evidence.md
verification: git diff --numstat -- .plan/RETRO.md: 49 additions, 0 deletions (pass); no em dashes in RETRO.md (pass)
risks: The exit-5 causes for M02-T03 and the exit-1 causes for M02-T05 are not recorded in the ledger or result.md. The 8 Nov batch was re-run on 9 Nov with no supersede marker. M02-T02b and M02-T07 are not in the milestone Tasks table.
questions_for_g: none
### Findings
- Shared footer (_footer.md): launch long jobs detached (nohup or run-job) so a stopped shell cannot SIGTERM them (M02-T04, exit 143 at 65 percent, $4.69 lost).
- codex-implement.md: after two non-zero exits from one codex launcher within about 90 s, switch to terra-implement (M02-T05, codex2 exit 1 at 79 s and 34 s; repeats the unapplied M01-T07 proposal).
- codex-review.md and sol-review.md: link .venv from the main checkout first, and report "verification not runnable" if blocked (REV-M02-T03, T04, T05; repeats the unapplied M01 proposal).
