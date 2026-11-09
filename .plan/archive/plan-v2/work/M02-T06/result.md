## RESULT M02-T06
status: done
summary: `proposal.md` quotes line 17 of `docs/legal/third-party-notices.md`, which names the bare upstream path `skills/mcp-builder/scripts/requirements.txt`. The file is tracked at `tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt`. The floors `anthropic>=1.8.0,<2` and `mcp>=1.30.0,<2` and the change comment all match the notice. The proposal gives the exact replacement line and the M02-T07 post-apply check. Every criterion is met.
changes: .plan/work/M02-T06/proposal.md (written in the main checkout's `.plan/work`, the owned path; the worktree has no such directory). There is no commit and no tracked change.
verification: `test -s .plan/work/M02-T06/proposal.md && git diff --quiet -- docs/legal` run in the main checkout: pass. `git status --porcelain` in the worktree: empty.
risks: The upstream version floors (`anthropic>=0.39.0`, `mcp>=1.1.0`) and upstream commit `33b5983` are not checked, because upstream is not in this tree. The proposal leaves them unchanged.
questions_for_g: Approve the replacement line in `proposal.md` verbatim, so M02-T07 can apply it?
