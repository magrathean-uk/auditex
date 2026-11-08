## RESULT M00-T03
status: done
summary: `make audit-deps` resolves the base install and the `mcp`, `test`, `google`, `model_train` and `dev` extras with `uv pip compile` (metadata only, no install into `.venv`). It resolves `model_train` a second time for Linux aarch64. `pip-audit --no-deps --disable-pip` then audits all 7 lists and the target exits non-zero if any list fails.
summary: `pip-audit` sits in the new `dev` extra and runs from a tool venv under `build/audit-deps/`. That directory is already git-ignored and listed in `.clean-development.json` through `build`, so neither file needed a change.
summary: Findings: none across all 7 lists, so there is no `pyproject.toml` pin change and no `scripts/audit-deps-ignore.json`. The target reads that file if it appears, and each entry needs id, package, reason and decision.
changes: Makefile, pyproject.toml (commit 6280844 on task/M00-T03-audit-deps)
verification: `make audit-deps` pass, exit 0, "No known vulnerabilities found" for all 7 lists, run twice; `git status --porcelain` empty. I did not test the failure path with a known-vulnerable pin, and I did not run `make test` or the module's `make release-check`.
risks: `uv` is now a prerequisite for `audit-deps`; the target exits 2 with an install hint if it is missing. The ignore-file path and the non-zero exit on a vulnerable list are untested. Resolution uses the host Python from `select-python.sh`, so a different host Python could resolve different versions.
questions_for_g: none
