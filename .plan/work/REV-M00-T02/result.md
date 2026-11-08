## RESULT REV-M00-T02
status: done
summary:
verdict: approve
reviewed: 836261c0cb3e73b79cdf18582952e6e08e058a5f
The `Makefile` split is clean: `release-archive` is carved out of `release-check` unchanged apart from `${TMPDIR:-/tmp}`, and the new `dist` target is sound. The verify command passes with `TMPDIR` unset and set, and the `dist/` ignore check passes.
changes: none (evidence written to `.plan/work/REV-M00-T02/evidence.md`)
verification:
- `env -u TMPDIR make release-archive dist`, run in a local clone of 836261c under `$TMPDIR` using the cached venv python: pass
- `TMPDIR=<dir> make release-archive dist` in the same clone: pass
- `git check-ignore -q dist/x`: pass
- full `make release-check`: not run, the heavy gate is left to `merge.sh --verify`
risks:
- `dist/` is not cleaned before a build, so stale wheels or sdists from an older version could stay beside new ones and trip M00-T05's `dist/*.whl` globs.
- The author's own verify failed in their sandbox. Their `result.md` says `status: partial` with that failure as the reason, and I could not reproduce it in my clone.
questions_for_g: none

### Findings
Criteria:
1. Archive-and-wheel block moves to `release-archive`, called by `release-check`, behaviour unchanged with `TMPDIR` set: met. `Makefile:53` calls it and `Makefile:58-72` holds the block; the only change from `main` is the `${TMPDIR:-/tmp}` default.
2. With `TMPDIR` unset, a safe default is used, with no abort and no write to `/`: met. `Makefile:60` falls back to `/tmp`, and the unset-`TMPDIR` run exited 0.
3. `dist` builds the wheel and sdist into `dist/` from a clean tree, and `dist/` is git-ignored and in `buildDirs`: met.
   - The target builds from a `git archive HEAD` extract at `Makefile:76-89`.
   - `.gitignore:9` ignores `dist/`, and `.clean-development.json:8` lists it.
   - The run produced `auditex-1.3.0.dev0-py3-none-any.whl` and `auditex-1.3.0.dev0.tar.gz`.
4. `release-check` keeps every step in the documented order and stops at the first failure: met. The order at `Makefile:50-57` is lint, test, contract-smoke, release-archive, rule-pack drift, taint scan, gitleaks, identical to `main`; separate recipe lines stop at the first failure.
5. Verify command: pass.

Definition of Done (the item this task claims): "release archive and dist steps work with `TMPDIR` unset and set" is met, as shown by the verify run above.

Security: no secrets, no new dependencies and no `pyproject.toml` change. Paths come from `mktemp -d` and are quoted, and the trap removes the temp directory. `$(abspath $(PYTHON))` is needed because the recipe does `cd` before invoking Python, and it is correct.

Scope: the changed paths are `Makefile`, `.gitignore` and `.clean-development.json`, all on the task's files line. There is no scope creep.

Required changes: none.

Suggestions (non-blocking):
- `Makefile:89`: clear `dist/*.whl` and `dist/*.tar.gz` before the copy, so stale versions cannot sit beside new ones. The task spec says nothing about this.
- `Makefile:76-85` duplicates the archive-and-extract setup from `release-archive`. It is acceptable at this size.
