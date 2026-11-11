## RESULT RETRO-M00
status: done
summary: M00 retro appended to `.plan/RETRO.md`. 40 runs (38 M00/REV-M00 rows plus VAL-v2), $4.2483 recorded cost (16 rows blank, so a floor), 14792 s as recorded, 18 non-zero exits, all on M00-T01 (12), M00-T02 (4), M00-T03 (1), M00-T05 (1). The release-check gate on main is red (1 failed test) and is recorded as an outcome, not a task failure.
changes: .plan/RETRO.md (append only); .plan/work/RETRO-M00/evidence.md
verification: ledger parse, all 40 rows with 12 columns, no malformed rows: pass; `git diff --numstat .plan/RETRO.md` shows 50 additions, 0 deletions: pass
risks: Ledger ids are reused across plan versions (8 Nov branches differ from the current M00 table), so spend mixes two plans. Blank cost_usd on codex and codex2 rows means the cost total is a floor. The SessionStart hook asked for `clean-development doctor`; I did not run it because this brief forbids it, so G or the orchestrator needs to decide.
questions_for_g: none
### Findings
- `codex-implement.md`, Done when: require result.md to carry the criteria's evidence even when status is partial (REV-M00-T02 result-1.md was changes-required for missing counts).
- `codex-implement.md`, Constraints: on a sandbox-denied verify step, report partial and have the orchestrator re-run that command outside the sandbox (M00-T02 and REV-M00-T01 both stopped before verify ran).
- Dispatch, not a brief file: route owner=codex tasks such as M00-T01 to codex-implement, not luna-explore (luna ran M00-T01 in 10 of 14 rows, 9 non-zero).
