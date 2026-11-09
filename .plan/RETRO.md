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
