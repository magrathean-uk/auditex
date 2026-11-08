## RESULT M03-T02
status: blocked
summary: Full v3.9.1 replay not run; `vectors.jsonl` (sha256 3515b6fa…, 26,898 rows) with sibling `a2-vectors.jsonl` and `a2-label-overrides.jsonl` is not on disk in the worktree, main checkout, lab, 4TB dev/machine trees or records. Blocked on the kit path.
changes: none (evidence at .plan/work/M03-T02/evidence.md)
verification: find and grep over the locations above, no match; worktree git status clean; no .venv link created; acceptance pytest not run (no file)
risks: The kit may not have been carried over from the 31 Oct model-development run, so the full replay acceptance remains unverified for 1.3.0.
questions_for_g: Where is the v3.9.1 `vectors.jsonl` kit (path, or the lab owner)? Once given, the run is one command with the variable set.
