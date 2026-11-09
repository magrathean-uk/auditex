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
