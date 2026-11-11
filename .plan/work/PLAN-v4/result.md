## RESULT PLAN-v4
status: done
summary: I fixed the check's three defects in commit c33d6e8 on task/PLAN-v4-plan-v4 and changed nothing else.
- M04-T03 no longer lists mcp_server.py as an allowed file. The MCP notice now goes through redact_payload, and the verify fails if mcp_server.py changes.
- M00-T06 can now change cli.py to dispatch, validate and forward the `--as-of` date to the offline run handlers, not only add the parser option.
- The M00-T06 criterion, its verify and the M00 DoD item now require one shared date, written out as a fixed date on each offline invocation in the contract smoke.
The reset commit from the first round still stands. Repair notes are under "Amendment 1 repair" in .plan/work/PLAN-v4/notes.md. Percentage: 12% before and 12% after the repair. current: 12%
changes: .plan/milestones/M00-foundation.md, .plan/milestones/M04-d5-keyed-pseudonyms.md (plus notes.md in the work folder). STATE.md and DECISIONS.md were not touched.
verification:
- PASS: percent.py --repo . --check on c33d6e8 (exit 0)
- PASS: git diff --check 8749be5 HEAD
- PASS: shell syntax check of the new M00 commands in sh, bash and zsh, and of the M04-T03 verify in bash
- PASS: date predicate probe in sh, bash and zsh. The same fixed date on all eight offline runs exits 0; a computed date exits 1. The current tree, two different dates, seven of eight runs and eight other bad forms also exit 1.
- PASS: no workstation paths in either milestone file
- Not run: percent.py --write, which the brief forbids. The master-plan table still shows M00 at 58 until the orchestrator's checkpoint.
risks: The predicate expects the space form `--as-of YYYY-MM-DD` on each recipe line and does not accept a Makefile variable. M00-T06's criterion says so, so the implementer knows.
questions_for_g: none
### Findings
| id | name | weight | DoD items | ticked |
|---|---|---|---|---|
| M00 | foundation | 8 | 11 | 6 |
| M01 | airr-bring-up | 15 | see file | 38% |
| M02 | explainer-data-and-judging | 15 | see file | 0% |
| M03 | explainer-training | 17 | see file | 0% |
| M04 | d5-keyed-pseudonyms | 18 | see file | 13% |
| M05 | scanners-and-hygiene | 12 | see file | 0% |
| M06 | release-1-5-0 | 15 | see file | 0% |
Honest current percentage: 12% (M00 54%). Revision notes: .plan/work/PLAN-v4/notes.md
