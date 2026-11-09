## RESULT M03-T05
status: blocked
summary: Step 1 passed (HEAD is d9f050f, no v1.3.0 tag locally or on origin). Step 2 failed: `make dist` gave different hashes from the M03-T03 pair, and repeat builds differ from each other because `make dist` doesn't pin the timestamp. Stopped per the brief; no tag, push or release made. Details in .plan/work/M03-T05/notes.md.
changes: none (git-ignored `.venv` link and `dist/` in this worktree only)
verification: git rev-parse HEAD: pass; git tag -l v1.3.0 and git ls-remote --tags origin v1.3.0: pass (both empty); make dist: pass; shasum -a 256 dist/* vs expected: FAIL (wheel f3457aea..., sdist db7c1d9b...); second make dist: different again; SOURCE_DATE_EPOCH build twice: wheel stable (6b2efad8...) but not the expected hash, sdist varies; steps 3 to 7: not run
risks: the equality check can't pass on any fresh build, so the brief needs amending; T03's artefacts are gone, so the exact bytes it hashed can't be published; a byte-reproducible build would need a code change and a new release commit
questions_for_g: none (orchestrator decision: publish a fresh build with its hashes recorded, which I recommend, or make the build reproducible first)
