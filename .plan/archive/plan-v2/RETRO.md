# Retro
<!-- Rolling lessons, pruned. luna-retro appends a section at each milestone end; the orchestrator prunes what no longer applies. -->

## Keep
- none yet

## Change
- none yet

## Reset 8 Nov 2026 - plan-tooling defects (proposed skill fixes)
- Tracked `work/*/brief.md` and `dispatch.txt` carry absolute workstation paths, which this public repo forbids. Fixed here by un-ignoring only result files in `.plan/work/.gitignore` (and re-ignoring `*/brief.md`, `*/output.md` after the `PLAN-*/*.md` rule); propose the same for `templates/plan/work/.gitignore`.
- Task and review worktrees have no `.venv`, so every verify that calls `.venv/bin/python` fails for workers and for `merge.sh --verify`. Propose: dispatch.sh links `.venv` to the main checkout's venv when one exists. Until then the merge gate links it in the verify command.
- Codex workspace-write cannot write the routed bytecode cache, so lint (`compileall`) and builds fail inside Codex; Claude reviewers and the merge gate carry verification for Codex-authored tasks.
- terra-verify's external-consumer class can never be satisfied from inside the repo, so no deletion candidate ever grades `safe`.
- dispatch.sh uses the truncated worker summary as the task-branch commit subject (for example "chore(M01-T01): Implementation complete on").
- Workers run `clean-development doctor` unprompted and report its lock FAIL every time; G's 5 Nov rule leaves clean-development issues alone. Propose a footer line telling workers not to run it.
- sol-architect at xhigh needed more than the default 1800 s for a reset plan; use 3600 s for MODE=reset.

## M02

Scope: 16 ledger rows (M02-T01 to T07, REV-M02-T01 to T07 with T05 reviewed twice, plus M00-T04 because its result names M02-T02). Milestone task status: 6 done, M02-T06 todo in the table (result says done, proposal only). Detail: `.plan/work/RETRO-M02/notes.md`, rows: `.plan/work/RETRO-M02/evidence.md`.

### Spend

Recorded `cost_usd` covers Claude rows only. The 7 Codex rows have no cost recorded, so Codex spend is unknown, not zero.

| launcher | runs | cost_usd | rows without cost | seconds | non-zero exits |
|---|---|---|---|---|---|
| claude-1 | 2 | 0.4049 | 0 | 50 | 0 |
| claude-2 | 1 | 0.0791 | 0 | 203 | 0 |
| claude-3 | 1 | 0.1721 | 0 | 27 | 0 |
| claude-4 | 3 | 0.5577 | 0 | 142 | 0 |
| claude-5 | 2 | 0.3026 | 0 | 48 | 0 |
| codex | 4 | not recorded | 4 | 283 | 0 |
| codex2 | 3 | not recorded | 3 | 170 | 2 |
| **total** | **16** | **1.5164** | **7** | **923** | **2** |

| role | runs | cost_usd | rows without cost | seconds | non-zero exits |
|---|---|---|---|---|---|
| terra | 8 | 1.4373 | 0 | 267 | 0 |
| luna | 1 | 0.0791 | 0 | 203 | 0 |
| codex | 7 | not recorded | 7 | 453 | 2 |

### Failures and retries

Failure count: 2 non-zero exits, both M02-T05 attempts (status `partial` each time).

| task | attempts | final status | cause |
|---|---|---|---|
| M02-T05 | 2 implementation (codex2, exit 1 each), 2 reviews (terra, approve) | partial (ledger and result.md); milestone table says done | Mechanical: worktree has no `.venv`, so the verify command failed. Technical: review item 1 (roots from ignored output dirs) fixed in attempt 2. Attempt 1 cause not recorded. |
| M02-T02 | 1 | done, changes none | Design: the branch content (fe78ee1) carried model-answered counts the criteria forbid; no scanner paragraph existed. Not a retry. |
| M02-T01, T02, T03, T04, T07; REV-M02-T01, T03, T04, T05 | 1 each | done | Mechanical, not retried: no `.venv` in worktree; verify run on the main checkout's venv, or a linked venv (T07). Reviews reported NOT RUNNABLE (exit 127). |
| `clean-development doctor` | run by M02-T05 and 5 reviews | exit 1 every time | Environmental: cleanup lock dead or unverifiable owner; GUI DEVCACHE unset. Not retried. |
| result.md format | M02-T02, M02-T05 | done / partial | Mechanical: repeated `summary:` and `risks:` keys; REV-M02-T05 adds a `dispatch:` line. |
| ledger | REV-M02-T02, M02-T06 | n/a | Mechanical: `branch` column holds a sha, not a branch name. |

### Proposed brief fixes

Brief files are under `~/.claude/skills/plan/briefs/`. The role-to-brief mapping is inferred from the ledger.

| brief file | problem seen | one-line change |
|---|---|---|
| terra-implement.md, codex-implement.md, terra-verify.md, codex-review.md | `.venv/bin/python` missing in worktrees (M02-T01, T02, T03, T04, T07; REV-T01, T03, T04, T05) | Before verify, `ln -s <main checkout>/.venv .venv` in the worktree. Brief-side stopgap for the dispatch.sh fix in the Reset section. |
| _footer.md | Workers ran `clean-development doctor` and reported exit 1 (M02-T05; REV-T01, T02, T03, T04, T07) | Add: "Do not run `clean-development doctor`; report only if a listed verify command needs it." Already in the Reset section; M02 adds evidence. |
| terra-implement.md, codex-implement.md | Repeated `summary:` and `risks:` keys in result.md (M02-T02, M02-T05) | Emit exactly one `summary:` and one `risks:` line; fold round notes into them. |

### Keep

- Two-provider review on writer tasks: REV-M02-T01, T02, T04, T07 (Codex) and REV-M02-T03 (Codex2) approved; REV-M02-T05 (terra) approved after a fix round.
- Review-fix-review closed on M02-T05: review, targeted repair, second review approved (ledger rows in order).
- No unsupported content landed: M02-T02 changed nothing where criteria forbade the figures; REV-M02-T02 confirmed.
- Approved wording applied verbatim: M02-T06 drafted a proposal only; M02-T07 applied G's text after approval (REV-M02-T07 byte comparison).
- Low-cost docs tasks: M02-T01, T02, T04, T06, T07 recorded 0.13 to 0.21 USD each on terra low effort.
- Scope held: every review found no out-of-scope paths.

Applied 8 Nov 2026 to briefs/_footer.md: single RESULT keys, link main-checkout tools such as .venv instead of installing, no clean-development doctor runs.

## M00

### Spend

Source: ledger rows for M00-, REV-M00-, VAL-v2 (names M00 tasks) and RETRO-M02 (names M00-T04). 31 runs; cost blank on 10 rows (all Codex launches, not estimated).

| launcher | runs | cost_usd | seconds | non-zero exits | blank cost |
|---|---|---|---|---|---|
| claude-1 | 5 | 1.5951 | 326 | 0 | 0 |
| claude-2 | 12 | 0.2904 | 5120 | 9 | 1 |
| claude-4 | 5 | 1.2389 | 395 | 0 | 0 |
| codex | 3 | 0.0000 | 216 | 1 | 3 |
| codex2 | 6 | 0.0000 | 748 | 3 | 6 |

| role | runs | cost_usd | seconds | non-zero exits | blank cost |
|---|---|---|---|---|---|
| luna | 12 | 0.2904 | 5120 | 9 | 1 |
| terra | 8 | 1.7614 | 552 | 0 | 0 |
| sol | 2 | 1.0726 | 169 | 0 | 0 |
| codex | 8 | 0.0000 | 594 | 4 | 8 |
| astra | 1 | 0.0000 | 370 | 0 | 1 |

Total: 31 runs, 3.1244 USD recorded, 6805 seconds, 13 non-zero exits.

### Failures and retries

| task | attempts (ledger) | final status | cause |
|---|---|---|---|
| M00-T01 | 10: timeout (exit 124, 900), 7 partial (exit 1), done (exit 0, c230a61), blocked (exit 3, 19c7ea7) | ledger blocked at 19c7ea7; result.md partial | Technical: `scripts/release-smoke.sh` calls bare `python` (exit 127); fixed by M00-T07. Mechanical: worker reply carried no RESULT block, so the orchestrator filed it. Cause of the timeout and the 7 partials not recorded. Ledger done and blocked rows conflict. |
| M00-T02 | 2 writer runs (codex2, exit 1) + REV-M00-T02 x2 (approved) | partial; no done row, but milestone table says done | Technical: sandbox denied `mktemp` in routed TMPDIR; process listing failed, so `make release-check` skipped. Mechanical: ran `clean-development doctor` (exit 1), duplicate `summary:` keys, extra `dispatch:` key. Cause of exit 1 not recorded. |
| M00-T03 | 3 writer runs (codex2 partial exit 1; terra done; terra done) + REV-M00-T03 x2 | done | First exit 1 cause not recorded. Design/review: review item 1 (`uv pip compile` could build sdists) and a comment mismatch, repaired by terra. |
| M00-T05 | 2 writer runs (codex partial exit 1; terra done) + REV-M00-T05 x2 | done | First exit 1 cause not recorded. Review: smoke matrix test needed `${artifact}` forms; repaired by terra. Mechanical: default `make dist` failed in the worktree (no `.venv`, no setuptools). |

Clean, no failed runs: M00-T04, M00-T04-check, M00-T06, M00-T07.

### Proposed brief fixes

| brief | problem seen | one-line change |
|---|---|---|
| `luna-explore.md` | M00-T01: worker reply carried no RESULT block; orchestrator filed it from notes | Make the final reply the RESULT block itself; put long notes in the work dir and reference them. |
| `codex-implement.md` | M00-T02, T03, T05: partial exit 1 with no cause in ledger or result | On partial exit, write one cause line into the RESULT summary. |
| `codex-implement.md`, `terra-implement.md` | M00-T02: four `summary:` lines and a `dispatch:` key in result.md | Add no keys beyond the RESULT contract; the orchestrator writes dispatch lines. |

### Keep

- Gate evidence without fixes: M00-T01 recorded each gate step with counts, which exposed the bare-python defect; M00-T07 fixed it in a scoped task (one file, `env PATH=/usr/bin:/bin` smoke pass).
- Review-fix-review closed twice: M00-T03 (REV-M00-T03 x2, approved) and M00-T05 (REV-M00-T05 x2, the second on the repaired commit).
- Two-provider review on writers: M00-T06 (sol, reviewed by codex) and M00-T07 (terra, reviewed by codex sol).
- Cheap first-time passes: M00-T04 (luna, 0.0791 USD) with M00-T04-check (terra, 0.1543 USD); M00-T07 (terra low, 0.1568 USD).
- Scope held: M00-T03 touched only `Makefile`; M00-T07 touched only `scripts/release-smoke.sh`; reviews judged the frozen commits.

## M01

Selection: 62 ledger rows (ids `M01-*` and `REV-M01-*`, plus `REV-PLAN-v2` and `VAL-v2`, whose result.md names M01 tasks; those four rows carry no cost and 667 s). All rows have 12 columns. Codex launchers (`codex`, `codex2`) record no `cost_usd` on any of their 32 rows, so codex spend is not measured; the 22.7271 USD total covers the 30 Claude and luna rows only. Full figures and selection: `.plan/work/RETRO-M01/evidence.md`.

### Spend

| Launcher | Runs | Cost USD | Seconds | Non-zero exits |
|---|---|---|---|---|
| claude-1 | 7 | 4.1313 | 1527 | 1 |
| claude-2 | 1 | 0.0178 | 63 | 0 |
| claude-3 | 1 | 0.2548 | 50 | 0 |
| claude-4 | 18 | 16.2610 | 3752 | 1 |
| claude-5 | 3 | 2.0622 | 356 | 0 |
| codex | 7 | not recorded | 964 | 1 |
| codex2 | 25 | not recorded | 3150 | 4 |
| **Total** | **62** | **22.7271 (30 rows)** | **9862** | **7** |

| Role | Runs | Cost USD | Seconds | Non-zero exits |
|---|---|---|---|---|
| sol | 11 | 17.4456 | 4290 | 0 |
| terra | 18 | 5.2637 | 1395 | 2 |
| luna | 1 | 0.0178 | 63 | 0 |
| codex | 31 | not recorded | 3744 | 5 |
| astra | 1 | not recorded | 370 | 0 |

Status: 55 done, 5 partial, 2 blocked. Total runs 62; failure count 7 (the non-zero rows).

### Failures and retries

| Task | Attempts (ledger) | Final | Cause |
|---|---|---|---|
| M01-T01 | 1: codex partial, exit 1 | partial on branch; REV-M01-T01 approve at f6ffc78 | Mechanical: worktree had no `.venv`, verify exit 127; the acceptance command never ran. |
| M01-T02 | 4 author runs (terra x2, sol x2); 4 REV-M01-T02 runs | done | Technical: classification findings across rounds. The result.md on disk is round 3 (changes-required, driven by the doctor FAIL); the milestone DoD cites a round 4 approval with no round 4 result.md on disk, so this is unverified here. |
| M01-T03 | 4 author runs: codex2 partial exit 1, then 3 done; 3 REV runs | done | Partial cause not recorded. Reviews found aliased urllib imports (technical), closed in the final round. |
| M01-T04 | 3 author runs (sol, all done); 3 REV runs | done | Repair rounds from REV-M01-T04 round 2 and 3 items, not failures. |
| M01-T06 | 2: luna done (reported `--check` failing), then terra check done | done | Mechanical: no `.venv`; `build-model-examples.py --check` gave ModuleNotFoundError. The re-check showed the failure was environmental. |
| M01-T07 | 5: codex2 blocked exit 2 twice; terra done 3 times | done | Blocked cause not recorded. Final result: rebase conflict in shared `tests/test_read_boundaries.py` (design: parallel tasks on one test table; M01-FU had flagged it). |
| M01-T09 | 3 author runs: done, partial exit 1, done; 2 REV runs | done | Technical: result says the first commit 8a9a131 had a failing new test (fixed in ca63a12) although its ledger row read done. Partial cause not recorded. |
| M01-T10 | 3 author runs, all done (terra, terra, sol) | done | Reason for the extra runs not recorded in ledger or result. |
| M01-T11 | 2: terra partial exit 1, then terra done | done | Partial cause not recorded. |
| M01-T12 | 3: codex done, codex2 partial exit 1, sol done | done | Partial cause not recorded; the sol run carried the fix. |
| REV-M01-T08, -T09, -T10, -T12 | 1 each, all approve | approve | Mechanical: read-only sandbox refused the `.venv` link ("Operation not permitted"); reviewers did not run pytest or contract-smoke. |
| REV-M01-T02, REV-M01-T03 | 1 each | changes-required; approve | Mechanical: review asked for `clean-development doctor`, which failed on routing and lock checks. The only FAIL on record in T02 is that check. |

### Proposed brief fixes

| Brief (`~/.claude/skills/plan/briefs/`) | Problem (backed by) | Change |
|---|---|---|
| `codex-review.md`, `sol-review.md` | Doctor FAIL forced changes-required (REV-M01-T02); approve with FAIL (REV-M01-T03) | Record `clean-development doctor` as an observation, never a verdict input. |
| `codex-implement.md`, `terra-implement.md` | Non-zero exits with no cause (M01-T03, T07, T09, T11, T12); same defect as M00 | On non-zero exit, write one cause line into the RESULT summary. |
| `codex-implement.md`, `terra-implement.md`, `codex-review.md`, `sol-review.md` | Missing `.venv` (M01-T01 exit 127, M01-T06 check); link refused in read-only review (REV-M01-T08, -T09, -T10, -T12) | Orchestrator links `.venv` into each worktree before dispatch; a reviewer that cannot link writes "verify not run" into its verdict line. |
| `codex-implement.md`, `terra-implement.md` | Rebase conflict in a shared test table (M01-T07); a done row with a failing commit (M01-T09) | If a file in your list is also open in another task, rebase onto main, and run verify on the final commit before reporting done. |

Mapping from role to brief is inferred; the ledger has no brief column.

### Keep

- Tier A cross-provider review caught real gaps: REV-M01-T03 (aliased urllib imports), REV-M01-T12 (substring heuristic replaced by `CONTENT_CMDLET_DENY`), REV-M01-T10 (P2 discard path through the writer wrapper), REV-M01-T09 (failing test on the first commit).
- Frozen-commit reviews: each REV result names its reviewed sha (for example REV-M01-T05 at 1e25c95, REV-M01-T11 at 2246e06).
- Pre-dispatch risk notes: M01-FU named the shared-file contention and the M01-T04 prerequisite before dispatch; the M01-T07 conflict stayed within three hunks.
- Cheap re-check: M01-T06-check (terra, 0.1270 USD) cleared a false fail from M01-T06 (luna, 0.0178 USD).
- Low-effort terra writers on Tier A tasks passed first review: M01-T08 (0.2329 USD), M01-T11 (0.1631 USD).

Applied 8 Nov 2026 after the M00 and M01 retros, to briefs/_footer.md: a cause line on any partial or blocked status, no keys beyond the contract, verify on the final commit.

## M03

Scope: 17 ledger rows (M03-T01 4 writer rows, REV-M03-T01 3, M03-T02 3, M03-T03 2, M03-T04 2, M03-T05 2, M03-T06 1). VAL-v2 excluded: its result names the milestone file, not an M03 task id. Detail: `.plan/work/RETRO-M03/notes.md`; rows and discrepancies: `.plan/work/RETRO-M03/evidence.md`.

### Spend

Recorded `cost_usd` covers Claude rows only. The 5 codex2 rows and 2 astra rows have no cost, so their spend is unknown, not zero.

| launcher | runs | cost_usd | rows without cost | seconds | non-zero exits |
|---|---|---|---|---|---|
| claude-4 | 6 | 1.8366 | 0 | 722 | 1 |
| claude-2 | 6 | 0.0868 | 0 | 1910 | 3 |
| codex2 | 5 | not recorded | 5 | 707 | 0 |
| **total** | **17** | **1.9234** | **5** | **3339** | **4** |

| role | runs | cost_usd | rows without cost | seconds | non-zero exits |
|---|---|---|---|---|---|
| terra | 6 | 1.8366 | 0 | 722 | 1 |
| luna | 6 | 0.0868 | 0 | 1910 | 3 |
| codex | 3 | not recorded | 3 | 268 | 0 |
| astra | 2 | not recorded | 2 | 439 | 0 |

### Failures and retries

Failure count: 4 non-zero exits in 17 runs, all exit 2 and all `blocked`, across 3 tasks.

| task | attempts | final status | cause |
|---|---|---|---|
| M03-T02 | 3: blocked (21 s), done (1204 s), blocked (551 s) | blocked in ledger and result.md; milestone DoD item 1 still says done | Mechanical: v3.9.1 `vectors.jsonl` kit not found in any location searched. Cause of the first blocked run not recorded. |
| M03-T03 | 2: blocked (23 s), done (83 s) | done | Cause of the blocked run not recorded. |
| M03-T05 | 2: blocked (65 s, xhigh), done (198 s) | done; tag and release published | Cause of the blocked run not recorded. |
| M03-T01 | 4 writer and 3 review runs, all exit 0 | done; review approve | Technical: review found a 1.2.4 contract-history claim in the wrong list; two fix rounds. |
| release artefacts | not a retry | conflict | Technical: sha256 for the same commit d9f050f differs between M03-T03 and M03-T05 (wheel c938ad5c vs 6b2efad8). Not explained by the inputs. |

Discrepancy: M03-T02 final ledger row and result.md are blocked, but the milestone DoD item 1 cites a pass ("6 passed"). The result carrying that pass is not in the inputs.

### Proposed brief fixes

Brief mapping is inferred; the ledger has no brief column.

- `luna-explore.md` (inferred for M03-T02): precondition step checks each required input path and exits blocked with the paths searched, before run-job. Problem: M03-T02 blocked on the missing kit.
- `_footer.md`: each attempt writes its own result file (for example `result.attemptN.md`), so a later blocked attempt cannot overwrite a done one. Problem: M03-T02 done then blocked; causes for M03-T03 and M03-T05 lost.
- `terra-implement.md`: check each "since version X" or "first documented in" claim against the tagged source before handoff. Problem: M03-T01 review round on a wrong 1.2.4 claim.
- `terra-implement.md` (inferred for the release steps): pin SOURCE_DATE_EPOCH and require the publishing build's sha256 to match M03-T03 before tagging. Problem: artefact hash mismatch between M03-T03 and M03-T05.

### Keep

- Frozen-commit cross-provider review: REV-M03-T01 (codex2) approved the release notes after three rounds.
- Blocked reported with evidence, not faked: M03-T02 named the missing file, the paths searched and the question for G.
- Gate before publication: M03-T04 (astra) verdict ready at d9f050f before G's yes.
- Post-publication check from a fresh download with checksum and install: M03-T06 (luna, 0.0111 USD).
- Signed tag verified before push, and release asset digests compared to local files: M03-T05.
