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
