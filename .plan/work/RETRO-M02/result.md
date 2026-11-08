## RESULT RETRO-M02
status: done
summary: 16 ledger rows selected (M02-T01 to T07, their reviews, and M00-T04 because its result names M02-T02). Total runs 16; recorded cost 1.5164 USD (Claude rows only; the 7 Codex rows have no cost, so Codex spend is unknown). Failure count 2: both M02-T05 attempts exited 1 and ended partial, then a review-driven fix round approved.
changes: .plan/RETRO.md (appended "## M02" with Spend, Failures and retries, Proposed brief fixes, Keep; 57 additions, 0 deletions); .plan/work/RETRO-M02/notes.md; .plan/work/RETRO-M02/evidence.md
verification: `git diff --numstat -- .plan/RETRO.md` pass (57 added, 0 deleted); no em dashes in the appended section pass; ledger parse, all rows 12 columns pass
risks: 1) M02-T05 ledger and result say partial while the milestone table says done; not reconciled. 2) `clean-development doctor` exit 1 (cleanup lock has a dead or unverifiable owner and needs explicit recovery; GUI DEVCACHE unset; ownership not confirmed registered); not remediated. 3) Brief-to-role mapping is inferred from ledger role and launcher; dispatch.txt not read.
questions_for_g: none
### Findings
- terra-implement.md, codex-implement.md, terra-verify.md, codex-review.md: link the main checkout's `.venv` into the worktree before verify (`.venv` missing in 9 M02 task and review worktrees).
- _footer.md: tell workers not to run `clean-development doctor` (exit 1 in M02-T05 and 5 reviews; already in the 8 Nov Reset section).
- terra-implement.md, codex-implement.md: emit exactly one `summary:` and one `risks:` line in result.md (M02-T02 and M02-T05 repeated them).
