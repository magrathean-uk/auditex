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
