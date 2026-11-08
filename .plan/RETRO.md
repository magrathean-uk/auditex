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
