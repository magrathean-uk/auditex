# Retro
<!-- Rolling lessons, pruned. luna-retro appends a section at each milestone end; the orchestrator prunes what no longer applies. -->

## Keep
- none yet

## Change
- none yet

## M00
Source: `.plan/work/ledger.tsv` (40 rows: 38 `M00-*`/`REV-M00-*` plus `VAL-v2`) and result.md files. Detail in `.plan/work/RETRO-M00/evidence.md`.

### Spend
Totals: 40 runs, $4.2483 recorded cost (24 rows with a cost; 16 rows blank, codex and codex2 runs and timeouts, so the total is a floor), 14792 s as recorded, 18 non-zero exits.

By launcher:

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 5 | 1.5951 | 326 | 0 |
| claude-2 | 11 | 0.2639 | 5026 | 9 |
| claude-4 | 7 | 1.5688 | 602 | 0 |
| claude-5 | 3 | 0.8205 | 7553 | 1 |
| codex | 3 | blank | 216 | 1 |
| codex2 | 11 | blank | 1069 | 7 |

By role:

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| astra | 1 | blank | 370 | 0 |
| codex | 13 | blank | 915 | 8 |
| luna | 12 | 0.2965 | 8583 | 9 |
| sol | 4 | 1.8605 | 4165 | 1 |
| terra | 10 | 2.0913 | 759 | 0 |

Ids reused: the 8 Nov rows (first batch) carry branches (tmpdir-safe-make, audit-deps, sdist-repro, wheel-resources-test, smoke-python) that the current M00 table does not list. The ledger rows for `M00-T04` to `M00-T07` have no result.md and no milestone entry, so they affect spend only.

### Failures and retries
Non-zero exits: 18 rows (M00-T01 12, M00-T02 4, M00-T03 1, M00-T05 1). Gate outcome below is separate.

| task | attempts (ledger rows) | final status | cause |
|---|---|---|---|
| M00-T01 | 14 rows: 1 timeout 900 s (luna), 7 partial exit 1 (luna), 1 blocked exit 3 (luna), 1 blocked exit 2 and 1 partial exit 1 (codex2), 1 timeout 1802 s (sol); 2 done | done, sol, 2194 s; REV-M00-T01 approve | timeouts mechanical; luna on an implementation task (design); other causes not recorded |
| M00-T02 (test-hygiene) | 2 non-zero rows in the second batch (blocked exit 2, partial exit 1) plus 2 earlier-branch partials in the first batch | partial, then evidence added by orchestrator at dad12f3; REV-M00-T02 changes-required then approve | sandbox-denied uv cache write (technical); result.md lacked criteria evidence (brief design) |
| M00-T03 | 1 done (luna, 3557 s) on main e6531a3 | done, but gate red: release-check 1 failed test | not a task failure: `test_parser_error_privacy.py` on main (technical); first release-check run stopped by harness at about 65% (mechanical) |
| M00-T05 (earlier branch) | 1 partial (codex), then terra done | done | not recorded |

### Proposed brief fixes
- `~/.claude/skills/plan/briefs/codex-implement.md`, Done when: require result.md to carry the criteria's evidence even when status is partial, because REV-M00-T02 (result-1.md) returned changes-required for missing before/after counts.
- `~/.claude/skills/plan/briefs/codex-implement.md`, Constraints: when a verify step is sandbox-denied, the worker reports partial with the exact command and the orchestrator re-runs that command outside the sandbox at review, because M00-T02 and REV-M00-T01 both stopped before verify ran.
- Dispatch rule (not a brief file): route M00-T01 and other owner=codex tasks to codex-implement, not luna-explore, because luna (read-only) ran M00-T01 in 10 of 14 rows, 9 of them non-zero.

### Keep
- Fallback to terra after a codex partial: M00-T03 (row 52 to row 58) and M00-T05 (row 53 to row 63) each finished on the first terra run.
- Independent review on a frozen commit, criterion by criterion with file:line citations: REV-M00-T01 (reviewed 917344e), REV-M00-T02 (reviewed dad12f3), REV-M00-T05 (sol).
- Reviews that caught missing evidence rather than passing on code alone: REV-M00-T02 result-1.md, then re-review after the evidence was filed.
- Honest red gate: M00-T03 reported the failing test with its path and line and made no fixes, as its criteria required.
- Orchestrator decision on the RETRO-M00 proposals: not applied to the skill source. Proposals 1 and 2 concern `codex-implement`, which this repository no longer uses for implementation (Claude implements, Codex reviews, since its sandbox cannot run the suite). Proposal 3, routing, is already how v3 dispatches. Lessons applied in v3 instead: merge verifies export `PYTHONPATH="$PWD/src"`, run `make test` (or `make release-check`) once per merge batch with `PLAN_VERIFY_TIMEOUT=4500`, and long runs go under run-job.

## M01
Source: `.plan/work/ledger.tsv` (73 rows: 69 `M01-*`/`REV-M01-*` plus `VAL-v3` and `REV-PLAN-v2`, the two other results that name an M01 task) and result.md files. Detail in `.plan/work/RETRO-M01/evidence.md`.

### Spend
Totals: 73 runs, $24.3623 recorded cost (37 rows with a cost; 36 blank, all codex and codex2 launches, so the total is a floor), 11987 s as recorded, 7 non-zero exits (5 partial, 2 blocked).

By launcher:

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 8 | 4.4426 | 2071 | 1 |
| claude-2 | 2 | 0.0514 | 471 | 0 |
| claude-3 | 2 | 0.5644 | 65 | 0 |
| claude-4 | 19 | 16.4411 | 3784 | 1 |
| claude-5 | 6 | 2.8628 | 941 | 0 |
| codex | 7 | blank | 964 | 1 |
| codex2 | 29 | blank | 3691 | 4 |

By role:

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| codex | 35 | blank | 4178 | 5 |
| sol | 11 | 17.4456 | 4290 | 0 |
| terra | 24 | 6.8653 | 2571 | 2 |
| luna | 2 | 0.0514 | 471 | 0 |
| astra | 1 | blank | 477 | 0 |

Id reuse: the current milestone lists M01-T01 to M01-T04 only. Ledger rows for M01-T05 to M01-T12, M01-FU and the earlier M01-T01, T03 and T04 runs belong to the earlier boundary-proof plan (branches such as `task/M01-T07-gmail-fields-masks`), so the spend above mixes two plans.

### Failures and retries
Non-zero exits: 7 rows (M01-T01 1, M01-T03 1, M01-T07 2, M01-T09 1, M01-T11 1, M01-T12 1). Causes are not recorded in the ledger; the earlier-plan tasks have no result.md.

| task | attempts | final status | cause |
|---|---|---|---|
| M01-T01 (earlier) | 1: codex exit 1 (376 s) | partial | not recorded |
| M01-T03 (earlier) | 4: codex2 exit 1, then sol, sol, sol | done | not recorded; VAL-v3 later found its verify returned 0 with the target absent |
| M01-T07 (earlier) | 5: codex2 exit 2 twice (22 s, 31 s), then terra done 3 times | done | launcher-level: the same launcher failed twice in under 35 s; not recorded |
| M01-T09 (earlier) | 3: terra done, exit 1 (45 s), terra done | done | transient; not recorded |
| M01-T11 (earlier) | 2: terra exit 1 (72 s), terra done | done | not recorded |
| M01-T12 (earlier) | 3: codex done, codex2 exit 1, sol done (787 s) | done | not recorded; re-run on the same branch |
| M01-T02 (current) | 6 done runs (luna, terra, sol), then T02b | done after T02b | mechanical: verify needs `AUDITEX_TEST_VALUE_RULE_VECTORS_V391`, unset; kit on the 4TB only, not in records |
| M01-T04 (earlier) | 3 done runs (sol) | done | no failure recorded; repeat runs |
| M01-T10 (earlier) | 3 done runs (terra, terra, sol) | done | no failure recorded; repeat runs |
| REV-M01-T01 | 2 reviews | approve, verify not runnable | mechanical: no `.venv` in the reviewer worktree |
| REV-M01-T03 | repeat reviews | approve, chain not runnable | mechanical: no `.venv`; read-only sandbox blocked the link |

### Proposed brief fixes
- `codex-implement.md`: after a launch that exits 2 within about 30 s, do not relaunch the same launcher with the same brief; fall back to `terra-implement` on a Claude launcher. Backed by M01-T07 (two codex2 exit-2 runs, then terra done).
- `terra-implement.md` or `luna-explore.md`: when a verify command reads an env var, the brief exports it or names the records path where the input is copied. Backed by M01-T02 (verify fails as written with the variable unset) and M01-T02b (fixed by copying the kit to records).
- `sol-review.md` and `codex-review.md`: first step links `.venv` from the main checkout; if the link is blocked, the review states "verification not runnable" and names the run that covers it. Backed by REV-M01-T01 and REV-M01-T03.

### Keep
- Independent review on a frozen commit, re-run after a fix: REV-M01-T03 (approve on 6c17cbd); M01-T03 fixed review item 1 and ran a mutation check.
- Hash-pinned kit checks with a records copy and README: M01-T02, M01-T02b, M01-T04 (0 skips in the replay and explainer acceptance).
- Honest "not runnable" in reviews, with no pass claimed: REV-M01-T01, REV-M01-T03.
- Fallback to a Claude launcher after a Codex failure: M01-T07 (terra done after codex2 blocked), M01-T12 (sol done after codex2 exit 1).
- Load gate before a heavy run under run-job: M01-T04 (waited from load 14.8 to 10.4, then `make acceptance` exit 0).

## M02
Source: `.plan/work/ledger.tsv` (42 rows: 41 `M02-*`/`REV-M02-*` rows plus `REV-M03-T04`, whose result names M02-T05) and result.md files. Detail in `.plan/work/RETRO-M02/evidence.md`. The 8 Nov batch (ledger lines 26-79) and the 9 Nov batch (lines 170-251) both carry M02 ids; the ledger does not say the earlier batch was superseded.

### Spend
Totals: 42 runs, $24.9944 recorded cost (21 rows blank, all codex and codex2 launches, so the total is a floor), 9229 s as recorded, 4 non-zero exits (2 partial, 2 failed).

By launcher:

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-5 | 10 | 15.7164 | 5506 | 2 |
| claude-4 | 7 | 5.9321 | 1206 | 0 |
| claude-3 | 2 | 2.9410 | 364 | 0 |
| claude-1 | 2 | 0.4049 | 50 | 0 |
| codex2 | 17 | blank | 1820 | 2 |
| codex | 4 | blank | 283 | 0 |

By role:

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| sol | 7 | 21.0995 | 6190 | 2 |
| terra | 14 | 3.8949 | 936 | 0 |
| codex | 21 | blank | 2103 | 2 |

### Failures and retries
Non-zero exits: 4 rows. Three reviews (REV-M02-T03, REV-M02-T04, REV-M02-T05) finished `done` but could not run the verify chain; they are not counted as failures.

| task | attempts | final status | cause |
|---|---|---|---|
| M02-T04 | sol claude-5: exit 5 at 687 s ($4.69), then done at 2493 s ($3.99) | done | mechanical: the first run-job attempt died with 143 (SIGTERM) when its launching shell stopped, at 65 percent. The ledger records exit 5; result.md records 143 |
| M02-T03 | sol claude-5: exit 5 at 1728 s ($4.64); sol claude-4 done (344 s); REV-M02-T03 x4 (codex2); terra claude-5 done (95 s) | done | exit 5 cause not recorded. Repair was technical: review item 1, a star import left in the shim |
| M02-T05 | codex2 partial exit 1 at 79 s and 34 s (8 Nov); REV-M02-T05 by terra claude-4 (8 Nov); terra claude-5 done x3 (9 Nov), each with a codex2 review | done after 2 repair rounds | exit 1 cause not recorded. Repairs technical: doc claims that did not match the code (result.md, round 2) |
| M02-T01 | sol: claude-4 513 s, claude-3 337 s, claude-4 88 s; REV-M02-T01 codex2 x3, approve on 52c0de3 | done | design: review findings on T03 sequencing. result.md says the two repair rounds are now used up, so a further failed round needs re-scoping |

The 8 Nov rows for M02-T01, T02, T03, T04 and T06 were all `done` and were re-run on 9 Nov; the ledger gives no reason. They are not counted as failures.

### Proposed brief fixes
- Shared footer (`_footer.md`): launch long jobs detached (`nohup` or `run-job`) so a stopped launching shell cannot SIGTERM them. Backed by M02-T04 attempt 1 (exit 143 at 65 percent, $4.69 lost).
- `codex-implement.md`: after two non-zero exits from the same codex launcher within about 90 s, relaunch on `terra-implement` rather than repeat the brief. Backed by M02-T05 (codex2 exit 1 at 79 s and 34 s). Repeats the M01-T07 proposal, which is not yet applied.
- `codex-review.md` and `sol-review.md`: link `.venv` from the main checkout first; if blocked, report "verification not runnable" and name the run that covers it. Backed by REV-M02-T03, REV-M02-T04 and REV-M02-T05. Repeats the M01 proposal; neither brief mentions `.venv` yet.

### Keep
- Other-provider review on frozen commits, repeated after each repair: REV-M02-T02, T03, T04 and T05 (codex2 reviewing Claude-authored work).
- Design review before any deletion: M02-T01 went through three review rounds and approved on 52c0de3; the removal list stayed at 38 paths.
- Relaunch under nohup after a death: M02-T04 attempt 2 passed (make test, contract-smoke, digests, audit-deps).
- Checking doc claims against code: M02-T05 round 2, approved by REV-M02-T05.
- Honest "UNTESTABLE" and "not runnable" in reviews, with no pass claimed: REV-M02-T04, REV-M02-T03, REV-M02-T05.

## M03

### Spend

Runs 31, cost_usd 3.2724 (10 codex2 rows have blank cost), seconds 6576, non-zero exits 6.

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-4 | 9 | 2.7263 | 1032 | 2 |
| claude-2 | 7 | 0.1133 | 2004 | 3 |
| claude-5 | 3 | 0.4158 | 178 | 0 |
| claude-1 | 2 | 0.0170 | 1858 | 1 |
| codex2 | 10 | blank | 1504 | 0 |

| role | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| terra | 11 | 3.0731 | 2766 | 2 |
| luna | 10 | 0.1993 | 2306 | 4 |
| codex | 7 | blank | 588 | 0 |
| astra | 3 | blank | 916 | 0 |

### Failures and retries

Six non-zero exits across four tasks. Ledger causes are blank throughout; the result.md files give causes only for the final attempts.

| task | attempts | final status | cause |
|---|---|---|---|
| M03-T01 | terra x4 and REV x3 (review repair loop); luna partial (exit 1, 147 s); terra check (done, 94 s) | done via check, partial result for the luna run | design: brief forbids a build, but the milestone verify needs a wheel check; not run, and the 10 percent spot-check was not run |
| M03-T02 | luna exit 2 (21 s); luna done (1204 s); luna exit 2 (551 s); terra exit 124 timeout (1801 s); REV x2 | timeout; commit 4513bdd reviewed approve | mechanical: timeout with no RESULT block; the exit 2 causes are not recorded |
| M03-T03 | luna exit 2 (23 s); luna done (83 s); terra done (25 s); REV | done | exit 2 cause not recorded |
| M03-T05 | terra exit 2 (65 s, xhigh); terra done (198 s) | done | exit 2 cause not recorded |

M03-T04 ran twice on the first launcher (both exit 0) and once more on a second launcher. It is a re-run with no recorded cause, not a failure.
REV-M03-T03 and REV-M03-T04 could not run their verify command: `.venv` was not linked, so `.venv/bin/python` was missing. Both reported UNTESTABLE rather than pass.

### Proposed brief fixes

- `terra-implement.md`: write the RESULT block before any long verify step, or run verify under `run-job`. Backed by M03-T02 (timeout at 1801 s, exit 124, no RESULT block).
- The brief used for M03-T01 (the ledger does not record which luna brief): if a milestone verify needs a build, say so in the brief or drop that step from the milestone. Backed by the partial M03-T01 run, where the wheel check was skipped under the brief.
- `_footer.md`: on any non-zero exit, write the stderr cause line into result.md. Backed by four exit-2 rows and one exit-1 row with no recorded cause (M03-T02, M03-T03, M03-T05, M03-T01).
- `codex-review.md`: link `.venv` from the main checkout before verify; if still blocked, report "verification not runnable" and name the run that covers it. Backed by REV-M03-T03 and REV-M03-T04. Repeats the RETRO-M02 proposal.

### Keep

- Deletion gate before removal: M03-T02 deleted exactly the 30 paths approved in DEC-006, and REV-M03-T02 checked the 30 deletions against the CLEANUP rows.
- Other-provider review on every writer task: REV-M03-T02, REV-M03-T03 and REV-M03-T04 (codex2) each returned approve.
- Recovery by diff check, not a rerun: after M03-T02's timeout, the orchestrator compared the worker's commit with the approved list before review.
- Documentation claims checked against the tree: M03-T04, with every claim MET in REV-M03-T04.
- Honest UNTESTABLE reviews: REV-M03-T03 and REV-M03-T04 claimed no pass they had not run.
- Forwarder proof as a subprocess test: M03-T03, approved in REV-M03-T03 with no required changes.

## M04

Scope: 16 ledger rows (`M04-*` and `REV-M04-*`). No other ledger id names an M04 task in its result.md; GATE-M02-M04 and PLAN-v3 do, but they are not M04 task rows and are excluded. Rows are in `.plan/work/RETRO-M04/evidence.md`.

### Spend

| launcher | role (model) | runs | cost_usd recorded | seconds | non-zero exits |
|---|---|---|---|---|---|
| claude-4 | sol (opus-5-5) x3, terra (sonnet-5-5) x1 | 4 | 15.6577 | 4079 | 0 |
| claude-5 | sol (opus-5-5) x2, terra (sonnet-5-5) x1 | 3 | 9.1220 | 1980 | 0 |
| codex2 | codex (gpt-6.1-sol) reviews | 9 | blank on all 9 rows | 1442 | 0 |
| **total** | | **16** | **24.7797 (lower bound)** | **7501** | **0** |

By role: sol 5 runs, $24.2991, 5974 s; terra 2 runs, $0.4806, 85 s; codex 9 runs, cost not recorded, 1442 s.

The 9 review rows have blank cost_usd, so the recorded total excludes them. Their true spend is unknown, not zero. Seconds are as recorded.

### Failures and retries

No non-zero exits. Four tasks needed more than one attempt or left a gap.

| task | attempts | final status | cause |
|---|---|---|---|
| M04-T02 | sol x4 (claude-5, claude-4, claude-4, claude-5); REV-M04-T02 x6 | done; reviewed approve at 9655dfb | technical: review repair-3 found that global and nonlocal names did not join their scope's binding union. Causes for repair-1 and repair-2 are not recorded in the ledger or result.md. |
| REV-M04-T02 | codex x6 | approve | technical: the last pass could not run its pytest command, blocked by sandbox-denied temporary writes; it replayed the functions in memory. Verdicts of the earlier five review runs are not in the ledger. |
| M04-T03 | terra x2 (claude-4 60 s, claude-5 25 s) | done; changes none | cause of the second run not recorded. Its result says the doc was already approved at 4329812, so it made no edit. |
| REV-M04-T01 | codex x1 | approve; verify UNTESTABLE | mechanical: `.venv` not linked in the worktree, so `.venv/bin/python` was missing. Pytest was not run. |

Out of scope, noted as a risk: REV-M04-T01, REV-M04-T02 and REV-M04-T03 each report that `clean-development doctor` fails on a dead or unverifiable lifecycle-lock owner. None ran it, per the brief.

### Proposed brief fixes

- `codex-review.md`: link `.venv` from the main checkout before verify; if still missing, report "verification not runnable" with the path. Backed by REV-M04-T01. Repeats the RETRO-M03 proposal, now seen again.
- `codex-review.md`: when sandbox-denied temp writes block pytest, record that as the cause and run verify with a basetemp under `$TMPDIR`. Backed by REV-M04-T02.
- Writer brief for the sol role (the ledger does not name it; likely `sol-architect.md`): list every binding form a scanner must cover (global, nonlocal, import, def, class, except, match, walrus, with) in the acceptance criteria before the first write. Backed by M04-T02, where repair-3 surfaced a gap that repair rounds found one at a time.
- `_footer.md`: when a task is re-run, write the reason in result.md, since the ledger has no cause column. Backed by M04-T03 (second run, no cause) and M04-T02 (repair causes not recorded).

### Keep

- Repair loop converged: M04-T02 reached approve after three repairs, each with named regression tests. The result reports 20 of 20 new tests failing on the prior scanner copy and passing now.
- Fail-closed design: M04-T01 treats an unprovable receiver as UNRESOLVED, which fails the suite. REV-M04-T01 approved this with no blocking findings.
- Other-provider review on every writer task: REV-M04-T01, REV-M04-T02 and REV-M04-T03 (codex2) each returned approve.
- Honest UNTESTABLE reviews: REV-M04-T01 reported verify as not run rather than as a pass. REV-M04-T02 named its sandbox blocker.
- Cheap doc task on terra: M04-T03 cost $0.18 to $0.30 per run, and its result checks each test name with grep.

## M05
Source: `.plan/work/ledger.tsv` (19 rows: `M05-*`, `REV-M05-*`, and `REV2-M05-T03`) and result.md files. Detail in `.plan/work/RETRO-M05/evidence.md`.

### Spend
Costs are as recorded. Seconds are as recorded.

| launcher | runs | cost_usd | seconds | non-zero exits |
|---|---|---|---|---|
| claude-1 | 3 | 5.8787 | 1378 | 0 |
| claude-3 | 1 | 5.2494 | 2066 | 0 |
| claude-4 | 1 | 1.0449 | 217 | 0 |
| claude-5 | 7 | 8.1057 | 2015 | 0 |
| codex2 | 7 | not recorded | 1050 | 0 |
| total | 19 | 20.2787 | 6726 | 0 |

| role | runs | cost_usd | seconds |
|---|---|---|---|
| sol | 7 | 18.9865 | 5252 |
| terra | 5 | 1.2922 | 424 |
| codex | 7 | not recorded | 1050 |

Seven codex2 rows have an empty cost_usd, so the total excludes codex2 spend. The M05-T04 read-through row names launcher `main` and branch `main`, so it is malformed.

### Failures and retries
| task | attempts | final status | cause | one line |
|---|---|---|---|---|
| M05-T02 | 2 | done | technical | REV-M05-T02 found the baseline loader did not validate its fields; fixed on the second attempt. |
| M05-T03 | 3 | done at 215148d | technical (design gap) | Six review items on identity joins, key cap, separator spellings and note wording; two repair rounds. |
| M05-T04 | 3 | done | not recorded in result.md | REV-M05-T04 needed repairs; approved at bdd9063 after them. |
| REV-M05-T02, REV-M05-T03, REV-M05-T04 | 1 each | done | mechanical | Reviewer worktree lacked `.venv` or a writable temporary folder, so verify was not run there. |
| M05 DoD item 1 | n/a | open | mechanical | No "D5 design" DEC entry with approver G; orchestrator item. |

Non-zero exits: 0. Retry attempts beyond the first: 5.

### Proposed brief fixes
- `terra-implement.md` (M05-T02): require a type and range check on every baseline field, exit non-zero on malformed input, and one test per field.
- The sol writer brief used for M05-T03 (name not in the ledger; likely `sol-architect.md`): design.md must list identity-join and spelling-variant cases with expected outcomes before code.
- `codex-review.md`: before verify, link `.venv` from the main checkout and set `TMPDIR` to `$TMPDIR` in the reviewer worktree.

### Keep
- Frozen interface first: M05-T01 froze the harness interface before M05-T02 started, and M05-T02 was done in one retry with no design change.
- Other-provider review on writer tasks: REV-M05-T02, REV-M05-T03 and REV-M05-T04 (codex2) all reached approve, and REV-M05-T03-privacy (claude-5) reviewed the privacy surface.
- Repair rounds capped at two: M05-T03 closed in two rounds at 215148d.
- Cheap doc work on terra: M05-T04 cost $0.17 to $0.38 per run and its result.md checks the constants against the code.
