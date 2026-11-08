## RESULT INV-history
status: done
summary: Tags v1.2.0 to v1.2.4 exist and match CHANGELOG headings and the release/1.2 line. v1.2.1 to v1.2.3 shipped a stale build/ tree, which 1.2.4 fixes. The .plan/ scaffold is still unfilled. The handover's claim of no local worktrees is stale: there are 207 now.
changes: none (notes written to .plan/work/INV-history/notes.md)
verification: git for-each-ref refs/tags; git rev-parse v1.2.0..v1.2.4; git log main..release/1.2; git log -n 150; git worktree list; git branch --no-merged main; clean-development doctor | head -60; rg/grep on CHANGELOG.md headings and .plan/ placeholders. All pass as commands; no build or test run.
risks: Remote branch and GitHub release state unverified (no gh or ls-remote run). 145 detached worktrees may hold unique commits. The doctor lifecycle failure is unexplained.
questions_for_g: none
### Findings
1. exists
- Tags v1.2.0 (565f798, 2026-10-23), v1.2.1 (732ed1b, 2026-10-25), v1.2.2 (30ac5a5, 2026-11-05), v1.2.3 (29bab5c, 2026-11-05), v1.2.4 (c9edea5, 2026-11-06). Source: git for-each-ref refs/tags.
- CHANGELOG.md:657 [1.2.0], :628 [1.2.1], :610 [1.2.2], :591 [1.2.3], :577 [1.2.4]; earlier releases at :1244 [1.1.0] and :1393 [1.0.0].
- release/1.2 head = c9edea5 (= v1.2.4). It holds 5 commits not on main: c9edea5, 29bab5c, 30ac5a5, 51ca64a, e7ab577 (the last two are inferred cherry-picks of main's 8b270de/f32448c).
- pyproject.toml:7 version = "1.3.0.dev0". CHANGELOG.md:8 [Unreleased] carries the 1.3.0 content. No v1.3 tag.
- .plan/ scaffold: STATE.md, BACKLOG.md, DECISIONS.md, master-plan.md, CLEANUP.md, RETRO.md, milestones/M00-foundation.md, ARCHITECTURE.md.
- Outside files (basename): PASSOVER.md, DECISIONS.md (D1 to D9), development-20261107/ (246 entries) and planning-20261107/ in records/auditex/.
2. works
- Tags resolve and are annotated with "Release x.y.z" subjects: `git for-each-ref`, `git rev-parse`.
- v1.2.0..v1.2.4 = 7 commits, no merges: `git rev-list --count`.
- v1.2.4..main = 156 commits: `git rev-list --count`.
- 1.2.4 packaging fix (CHANGELOG.md:581-586): v1.2.1 to v1.2.3 tracked a stale build/ tree from 1.2.0; read in full.
- 1.2.2 (CHANGELOG.md:610-626) and 1.2.3 (:591-608) security fixes: abbreviated-flag secret leaks in the main CLI and lab bootstrap copy; read in full.
- Doctor: storage external mode OK; hook shim 0.6.6 OK; 22 active job leases; 0 deletion queues pending: `clean-development doctor | head -60`.
3. broken
- Brief-named plans missing: ~/Desktop/auditex-development-plan.md and ~/Desktop/auditex.md (`ls`: no such file).
- .plan/master-plan.md:1-33, STATE.md:3-10, DECISIONS.md:4-10, milestones/M00-foundation.md:14-30: template placeholders (`<product>`, `<title>`, `<ci status command>`, `<test command>`) never filled.
- Doctor warnings (outside slice, one line): 3 literal cache paths in LaunchAgents plists; 7 unexpected dot-folders.
4. dead candidates
- 145 detached worktrees (`git worktree list`), mostly review-*, rv-*, ff-*, failfirst-*, at commits that may no longer be branch tips (tip status not checked).
- 13 local branches merged into main (inferred: 91 local minus 78 from `git branch --no-merged main`, including main); list with `git branch --merged main`.
- Tags with no CHANGELOG heading: v1 (445ecca, 2026-05-22, dated after v1.1.0), v0.9, release-2026-04-29, release-2026-05-06 (named in CHANGELOG.md:603-605 only in prose).
- .plan/work/ (only .gitignore), .plan/CLEANUP.md (empty ledger), .plan/BACKLOG.md (`none` in all three lists).
5. contradictions
- records PASSOVER.md "State at handover" (5 Nov): "no local worktrees remain" and "nine wt/* branches" vs 207 worktrees and 88 local wt/* branches now (`git worktree list`, `git branch`).
- PASSOVER.md: "main = 22d64f2" vs main = 8b3a334 now.
- PASSOVER.md: "1.2.3 cut without G's yes" vs DECISIONS.md, which records approval only for 1.2.4 (D1) and the 1.3.0 gate (D7); no 1.2.3 approval entry found.
- DECISIONS.md D8 (main stays b591772) is superseded by D9; the scaffold commit 8b3a334 is now main.
- Two decision logs: the working log is records DECISIONS.md (D1 to D9); .plan/DECISIONS.md holds only the template.
6. open questions
- Does origin hold the 9 wt/* branches the handover names? `git ls-remote --heads origin`.
- Does the GitHub release v1.2.4 point at c9edea5, and were v1, release-2026-04-29 and release-2026-05-06 published? `gh release list`, `gh release view v1.2.4`.
- Which of the 207 worktrees are merged and clean? `git branch --merged main`, then `git -C <wt> status --short` per worktree.
- What is the hook's lifecycle failure? `clean-development doctor | tail -n +61`.
- Is records/auditex/development-20261107/ the plan archive? Not read.
- Full notes, evidence and command list: .plan/work/INV-history/notes.md
