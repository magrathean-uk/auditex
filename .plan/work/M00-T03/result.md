## RESULT M00-T03
status: done
summary: Review item 1 is fixed. `uv pip compile` now runs with `--no-build`, so resolution never builds a source distribution. On failure the target prints a clear message naming the extra and exits 1. The non-blocking comment mismatch is fixed too: stale lists are removed before each run and the comment now says so. All criteria are met, and `make audit-deps` reports no known vulnerabilities across all 7 lists (base, mcp, test, google, model_train, dev, model_train for Linux aarch64). No ignore file is needed.
changes: Makefile
verification:
- `make audit-deps` on head 0722e93: pass, exit 0, no known vulnerabilities in any list
- `git status --porcelain`: empty
risks:
- The pip-audit warning about unhashed pins is printed on every list and is harmless here.
- Full test suite and `make release-check` were not run; the change touches only a make target.
questions_for_g: none

### Findings
- Review item 1 (`Makefile:62`, `--no-build`): fixed.
- Non-blocking comment mismatch (`Makefile:54`): fixed.
- Findings for `result.md`: none, so no `pyproject.toml` version changes and no ignore entries.
