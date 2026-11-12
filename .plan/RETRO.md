# Retro
<!-- Rolling lessons, pruned. luna-retro appends a section at each milestone end; the orchestrator prunes what no longer applies. -->

## Keep
- Reviewer scripts as the acceptance test: when a re-check finds a narrow, measurable gap, a new author fixes it and the orchestrator re-runs the reviewer's own scripts; no third review round (M02-T04).
- Evidence fetched once by the orchestrator (scheduler accounting, remote hashes) lets a sandboxed other-provider reviewer close an on-system milestone offline (REV-M01-kit).
- Set the reading rule before the next score exists (DEC-009), then take the outcome to G (DEC-011).
- A worker that finds a needed change outside its files stops and asks; the orchestrator widens the files line in one edit (M00-T06).
- Merge gate chained to the review record: a waiter merges only when the review file approves the exact head.

## Change
- Review loops: one independent review and one repair, then change the approach or bring G a choice. On 11 Nov the kit verifier, the held-out set, the tenant content scripts and kit round 7p each ran three or more rounds.
- New features do not ride in a gated kit round: the shared sign-in cost two gate rounds and was cut (DEC-010).
- Decisions that change an acceptance bar or a G-approved item go to G, not into the log as auto (DEC-003, DEC-007, DEC-009).
- Cluster work: three-hour workers waiting on queues timed out with jobs still running. Workers submit, record job ids and exit; a short worker collects.
- Heavy runs: a four-hour mock run by day died on its time limit under other projects' load; long runs go overnight with a longer limit, behind a sustained-load gate, and point their repository check at a detached worktree (checkpoints in the main checkout trip it).
- Full suite once per merged batch; per-task merges verify with the focused tests, lint and the contract smoke.
- Check quota reset dates in the morning: both Codex accounts ran close to their weekly limit by the evening, which forced an author and reviewer lane swap (DEC-012).
- Tools: run reviewer scripts with the project's Python environment; the done-item tick helper mis-reads commands quoted in double backticks; result files must carry repo-relative paths.

## M00

Scope: 65 ledger rows: all `M00-` and `REV-M00-` rows (this includes `M00-T07` and `REV-M00-T07`, which are not in the milestone table and have no result.md), plus the 5 `PLAN-v4` rows, because its result.md names M00-T06. Excluded: `REV-PLAN-v4` and `VAL-v4` (they cite the milestone file, not a task) and the two earlier `RETRO-M00` rows. No malformed rows; seconds as recorded.

### Spend

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 14 | 19.1007 | 6433 | 0 |
| claude-5 | 13 | 14.2802 | 10495 | 2 |
| claude-3 | 4 | 4.6550 | 11843 | 2 |
| claude-4 | 7 | 1.5688 | 602 | 0 |
| claude-2 | 11 | 0.2639 | 5026 | 9 |
| codex | 3 | not recorded | 216 | 1 |
| codex2 | 13 | not recorded | 1174 | 7 |
| **total** | **65** | **39.8686** | **35789** | **21** |

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| sol | 19 | 35.5791 | 20019 | 3 |
| terra | 16 | 3.9374 | 2524 | 0 |
| luna | 14 | 0.3521 | 11856 | 10 |
| codex | 16 | not recorded | 1390 | 8 |

Spend caveats: all 16 codex-launcher rows have a blank cost_usd, so the total excludes them. Two timeout rows (exit 124, claude-2 luna and claude-5 sol) also have a blank cost. Sol accounts for 89% of the recorded cost.

### Failures and retries

| task | rows | non-zero exits | final status | cause |
|---|---|---|---|---|
| M00-T01 | 16 | 13 | done (sol claude-3, `task/M00-T01-ruff-wider`), approved by codex2 and sol | Not recorded. Nine luna exits (one timeout at 900 s), two codex2 exits (blocked, partial), a sol timeout at 1802 s and a sol partial at 8412 s. The wide scope (899 findings) is the likely technical cause; the ledger does not confirm it. |
| M00-T02 | 7 | 4 | done (terra claude-1, third run) | Not recorded. Two earlier attempts ran under other branch names (`tmpdir-safe-make`, `test-hygiene`) that do not match the milestone title. Design: the id was reused for another scope. |
| M00-T06 | 4 | 1 | done (sol claude-5, `as-of-date`) | Not recorded. The blocked run (737 s, cost 3.9342) was the costliest attempt. The earlier row used `wheel-resources-test`. The first review required a change, fixed in one repair. |
| M00-T03 | 5 | 1 | done (terra claude-5, `agents-gate-lines`) | Not recorded. The codex2 partial run (35 s) came first; the branch changed from `audit-deps`. |
| M00-T04 | 3 | 1 | done on f9a272c | Not recorded. The luna blocked run (39 s) was followed by a passing run (3234 s). |
| M00-T05 | 4 | 1 | done | Not recorded. The first codex partial run (76 s). |

Ledger-level issues:
- Two timeouts (exit 124) and all 16 codex rows have no cost_usd.
- `M00-T07` and `REV-M00-T07` ran with no milestone task and no result.md.
- Result-file breaches: `M00-T06` result.md repeats `summary:` three times and `risks:` twice; `REV-M00-T06` repeats `risks:`. The rule at `~/.claude/skills/plan/briefs/_footer.md:23` already covers this, so no brief change is proposed.
- REV-M00-T06 found that a linked `.venv` made contract-smoke import main's code; it failed until PYTHONPATH pointed at the worktree.

### Proposed brief fixes

- `codex-implement.md` and `terra-implement.md`: a re-scoped attempt takes a new branch name and the milestone title; never reuse a task id for another scope. Backed by the branch changes on M00-T02, M00-T03 and M00-T06.
- `codex-implement.md` and `terra-implement.md`: with a linked `.venv`, export `PYTHONPATH=<worktree>/src` before any test or smoke run. Backed by the REV-M00-T06 finding; neither brief contains this rule today.
- Routing (plan skill, not a brief): do not launch luna on implementation tasks. M00-T01 has owner codex, size M and tag cross-cutting, and luna took nine exits before a sol run passed.

### Keep

- Reviewer-led repair in one round: M00-T06 (second review approved), M00-T02 (REV-M00-T02 approved on round two), M00-T05 (review item fixed, then approved).
- Evidence in files, result.md kept short: M00-T01 (`unsafe-fixes.md`, all 70 entries) and M00-T06 (`evidence.md`).
- Gate chain on main with per-step logs and exit codes: M00-T04 (six steps exit 0, logs in `.plan/work/M00-T04/gate/`).
- Terra on mechanical tasks: 16 runs, no non-zero exit, 3.9374 total cost (M00-T03 final pass 25 s).
- Reviews checked from the frozen commit: REV-M00-T01 checked 27 of 70 unsafe-fix justifications; REV-M00-T06 re-ran probes at the date bounds.
