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

## M02

Scope: 61 ledger rows: `M02-` and `REV-M02-` rows from the PLAN-v4 run onward, plus rows of other ids whose result.md names an M02 task. Earlier `M02-` rows from superseded plan versions are excluded because the ids were reused. Evidence: `.plan/work/RETRO-M02/evidence.md`.

### Spend

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 20 | 75.4005 | 29177 | 3 |
| claude-3 | 15 | 47.2308 | 15816 | 0 |
| claude-4 | 3 | 6.4037 | 1101 | 0 |
| claude-5 | 9 | 32.9857 | 23961 | 2 |
| codex2 | 14 | no cost recorded | 4766 | 2 |
| **total** | **61** | **162.0207** | **74821** | **7** |

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| sol | 40 | 158.4124 | 67641 | 4 |
| terra | 5 | 3.5296 | 2142 | 1 |
| luna | 2 | 0.0787 | 272 | 0 |
| astra | 1 | no cost recorded | 452 | 0 |
| codex | 13 | no cost recorded | 4314 | 2 |

Cost covers 46 rows. The 15 blank-cost rows are the 14 codex2 runs and the M02-T04 timeout row. The ledger header names 12 columns; rows from the PLAN-v4 run onward carry a 13th value (`plan_version`) that the header does not name. Not malformed, but the header is stale.

### Failures and retries

| task | attempts | non-zero exits (launcher, seconds) | final | cause |
|---|---|---|---|---|
| M02-T04 | 4 | timeout, exit 124 (claude-5, 10801) | done, then 2 more done runs | mechanical: run hit its time limit |
| M02-T03 | 4 | blocked, exit 2 (claude-5, 6375) | done, then 2 more done runs | not recorded |
| M02-T06 | 3 | blocked, exit 2 twice (claude-1, 703 and 1749) | done (692 s) | not recorded |
| M02-T01 | 4 | partial, exit 1 (claude-1, 677) | done, then 2 more done runs | not recorded |
| REV-M01-kit | 2 | partial, exit 1 (codex2, 641) | done (40 s) | not recorded |
| REV-M02-kit | 4 | blocked, exit 2 (codex2, 23) | done, 3 done rows across 2 commits | not recorded |

Seven non-zero exits, all recovered by a later exit-0 row for the same task. Six have no cause in the ledger, and the result.md files name only the final run. Repair rounds with exit 0 are not counted as failures: M02-T01, M02-T02, M02-T03 and M02-T04 each have three done rows; REV-M02-T02 has three, REV-M02-T04 two.

Design gap, not a run failure: M02-T03 left `MS.EXO.2.2v3 not_met` without a row (71 candidates, check a failed 68 of them). Closing it needs a decision on the prompt or the check.

### Proposed brief fixes

- `~/.claude/skills/plan/briefs/_footer.md`: add "A run expected to exceed about two hours: submit it with `run-job`, record the job ids in progress.md and exit; a short worker collects." Problem: M02-T04's attempt ran 10801 s and exited 124. Backed by the M00 Change note on the same pattern.
- Not a brief change: the orchestrator should keep each partial or blocked summary (for example `.plan/work/<task>/attempt-<n>.md`) before a retry overwrites it. Six of seven failures have no recorded cause, and the footer already requires the cause in the summary.

### Keep

- Repairs that re-score nothing: M02-T04 repair 2 changed no prompt, items, pairs or raw judgements, and ran CPU only (judge calibration still pass).
- Other-provider review closed the milestone: CHK-M02-kit reran the rules (221/221 agree), then REV-M02-kit (codex2) approved after one blocked attempt.
- Frozen checks shared by hash: `checks-sha256` 3241cf2c matches in M02-T03 and M02-T04.
- Acceptance bar validated on CPU from saved judgements with no GPU job: M02-T05, one attempt.
- Long jobs submitted, then collected by a separate step: M02-T03 job 8357551 collected with 12 of 12 runs at exit 0; M02-T04 repair 1 ran on the normal queue.

## M05

Scope: 36 ledger rows (M05-*, REV-M05-*, REV2-M05-T03, PASS-critic, INV4-d5, EXP-peakbase). The RETRO-M05 row is excluded. Figures are as recorded.

### Spend

| Launcher | Runs | Cost USD | Seconds | Non-zero exits |
|---|---|---|---|---|
| claude-1 | 6 | 11.1066 | 2987 | 0 |
| claude-3 | 6 | 9.2572 | 2813 | 0 |
| claude-4 | 5 | 5.2718 | 3331 | 0 |
| claude-5 | 8 | 9.2252 | 2244 | 0 |
| codex2 | 11 | not recorded | 1567 | 0 |
| **Total** | **36** | **34.8608** | **12942** | **0** |

| Role | Runs | Cost USD | Seconds |
|---|---|---|---|
| sol | 14 | 31.7726 | 8102 |
| terra | 10 | 3.0460 | 3123 |
| codex | 11 | not recorded | 1567 |
| luna | 1 | 0.0422 | 150 |

Codex rows have a blank cost, so the total understates spend. Before 11 Nov UTC: 21 runs, 22.9277 USD. From 11 Nov: 15 runs, 11.9331 USD.

### Failures and retries

No row has a non-zero exit or a status other than done. The events below are rework or blocked verification.

| Task | Attempts | Final status | Cause |
|---|---|---|---|
| M05-T01 (plan v4) | sol branch run, REV x2 | done | Mechanical and design: first review's one required change was the author's provider. Resolved by DEC-012 (Opus author, Codex review). |
| M05-T03 (plan v4) | terra low, REV, sol xhigh repair, REV | done | Technical: the review found the named-limit rows missing (security-privacy.md:226-233). Fixed at 9a82562 and approved. |
| M05-T04 (plan v4) | terra medium 2451s, terra low 104s, REV | done | Cause not recorded. The second run kept the first run's findings in result-1.md. |
| REV-M05-T01 | xhigh, medium | approve | Mechanical: `.venv` absent, so verify could not run. The result also records a failed `clean-development doctor`. |
| REV-M05-T02 | xhigh | approve | Mechanical: `.venv` absent and the read-only sandbox blocked linking it. Verify pending. |
| REV-M05-T04 | medium | approve | Mechanical: sandbox blocked verify, so the final-head checks are unverified. |
| REV-M05-T03-privacy, REV2-M05-T03 | 2 and 1 runs | no result.md | Mechanical: ledger rows exist but no result.md is in `.plan/work/`. INV4-d5 cites both. |
| Plan v3 era, M05-T02, M05-T03, M05-T04 (9-10 Nov) | 2, 3 plus 4 reviews, 3 | done | Cause not recorded: result files were overwritten by later runs. Reviewer error noted by INV4-d5 at REV-M05-T03-privacy:10 (middle initials). |

Ids M05-T01 to M05-T05 were reused by plan v4, so plan v3 rows share ids with plan v4 rows. Only 3 of 36 rows carry `plan_version`.

### Proposed brief fixes

Each fix is backed by a row listed above.

- `~/.claude/skills/plan/briefs/codex-review.md` and `sol-review.md`: when verify cannot run (no `.venv`, read-only sandbox), record it as "pending: orchestrator runs", not "untestable". Backed by REV-M05-T01, REV-M05-T02, REV-M05-T04.
- Same two review briefs: state that reviewers must not run `clean-development doctor`. Backed by REV-M05-T01 (doctor run recorded as failed).
- Same two review briefs: write a new `result-N.md` per review and never overwrite an earlier review's result. Backed by the missing REV-M05-T03-privacy and REV2-M05-T03 results.
- Dispatch record (no brief file names it): write `plan_version` on every row and treat the M05 ids as plan-scoped. Backed by the id reuse across plan v3 and v4.

### Keep

- Planted-case merge bar fixed in the milestone before work: M05-T01 (62 planted cases fail before, pass after) and M05-T02 (21 fail before). Evidence in `.plan/work/M05-T01/evidence.md`.
- Repair with saved probes: M05-T03 `probe.py` and `probe-output.txt`, then REV-M05-T03 approve at 9a82562.
- Keep first-run findings when rerunning (M05-T04 `result-1.md`): full suite 23112 passed and digests all match.
- Cheap focused re-reviews: REV-M05-T01 (medium, 62s) and REV-M05-T04 (71s).
- Terra for doc-only and read-only work: M05-T05 (0.3794 USD, no changes) and EXP-peakbase (0.1752 USD).
- Opus sol carried the 14 hard runs at 31.7726 USD, about 91% of recorded cost.

### Findings

- Review briefs (`codex-review.md`, `sol-review.md`): record verify as "pending: orchestrator runs" when `.venv` or sandbox blocks it.
- Review briefs: forbid `clean-development doctor` for reviewers.
- Review briefs: one `result-N.md` per review; never overwrite.
- Dispatch record: set `plan_version` on every row; plan v3 and v4 reused the M05 ids.

## M04

Scope: 65 ledger rows: `M04-` and `REV-M04-` ids, plus 16 rows of other ids whose result.md names an M04 task (CHK-M04-T03, CHK-M04-T04, EXP-m04-t06, EXP-peakbase, INV4-scanners, M06-T01, REV-M05-T04, VAL-v4). Not selected: PLAN-v3 and PLAN-v4 (they name the milestone, not a task), RETRO-M04 and GATE-M02-M04 (no result.md), and CHK-M04-T06 (ledger row present, no result.md). Evidence: `.plan/work/RETRO-M04/notes.md`.

### Spend

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 10 | 54.5677 | 12600 | 3 |
| claude-3 | 7 | 20.0163 | 3910 | 1 |
| claude-4 | 12 | 40.1253 | 10848 | 1 |
| claude-5 | 11 | 25.7349 | 7279 | 1 |
| codex2 | 25 | no cost recorded | 6911 | 2 |
| **total** | **65** | **140.4442** | **41548** | **8** |

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| sol | 33 | 137.3911 | 33730 | 4 |
| terra | 7 | 3.0531 | 907 | 2 |
| codex | 25 | no cost recorded | 6911 | 2 |

With the 16 other-id rows: 81 runs, cost_usd 144.9195, 51727 seconds, 11 non-zero exits. All 25 codex2 rows have a blank cost_usd, so every cost figure excludes codex2.

### Failures and retries

| task | attempts (launcher, outcome) | final ledger status | cause |
|---|---|---|---|
| M04-T02 | terra claude-3 blocked (exit 2); terra claude-1 done | done | not recorded; the retry overwrote the result |
| REV-M04-T02 | terra claude-5 partial (exit 1); six codex2 runs, last done | result.md partial, ledger done | mechanical: heavy slot busy (exit 75); contract-smoke and digest check never ran |
| M04-T03 | sol claude-1 partial (exit 1), done, blocked (exit 2), partial (exit 1), done; sol claude-5 done | done | not recorded for the three non-zero attempts |
| M04-T04 | codex2 partial (exit 1) twice, then done | done | not recorded |
| M04-T06 | sol claude-4 done twice, then partial (exit 1) | partial; milestone marks dropped | mechanical: verify deferred twice, heavy slot held by trackex-boot-test and CHK-M04-T06 |

Other selected ids with non-zero exits: CHK-M04-T03 (terra claude-1 partial, terra claude-3 malformed exit 3, then done; the result records its first launch killed by its own 10-minute background limit, mechanical); M06-T01 (terra claude-4 partial, exit 1; cause not stated). CHK-M04-T06 partial (exit 1, no result.md) also held the heavy slot.

Not counted as run failures: M04-T01 ran three design rounds after REV-M04-T01 returned changes-required (design revision 3). Cause: design. All its runs exited 0.

Failure count: 8 non-zero attempts in the 65-row set, 11 across the 81 selected rows. Causes in the 65-row set: 2 mechanical (REV-M04-T02, M04-T06), 6 not recorded (M04-T02, M04-T03, M04-T04), 0 technical, 0 design.

### Proposed brief fixes

- `~/.claude/skills/plan/briefs/_footer.md`: when verify is deferred (exit 75), record the exact deferred command and the slot holder's label in the summary so the rerun starts there. Problem: REV-M04-T02 and M04-T06 ended partial with verify never run.
- `~/.claude/skills/plan/briefs/terra-check.md`: run any check expected to exceed about 10 minutes through `run-job` and collect it, not in the foreground. Problem: CHK-M04-T03's first launch was killed by the 10-minute background limit and restarted.
- Not a brief change: keep each failed attempt's summary (for example `.plan/work/<task>/attempt-<n>.md`) before a retry overwrites `result.md`. Problem: six non-zero attempts (M04-T02, M04-T03, M04-T04) have no recorded cause.

### Keep

- Privacy-specific review after each masking change: REV-M04-T03-privacy, REV-M04-T04-privacy (approve, after the B1 and B2 fixes recorded in M04-T04).
- Design rework to a pass: REV-M04-T01 changes-required, answered in design revision 3 by M04-T01 with exit 0 throughout.
- Other-provider (codex2) review on M04-T01, T03, T04 and T06. M04-T05 was reviewed on Claude (sol) only.
- Honest partial reporting: M04-T06 and REV-M04-T02 say partial and name the deferred verify, rather than claiming a pass.
- Small docs task at low cost: M04-T05 by terra (low, 49 seconds), reviewed by sol (97 seconds, exit 0).
- Baseline re-record with the profile stated: M04-T02 records the peak, `unmasked_name_hits` 0 and an unchanged `workload_sha256`.
