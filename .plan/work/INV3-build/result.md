## RESULT INV3-build
status: done
summary: Inventory of the byte-reproducible `make dist` slice at HEAD 58084bb (version 1.3.0). Nothing was built or tested; the non-reproducibility finding comes from M03-T05 notes, not a run here. Full notes in `.plan/work/INV3-build/notes.md`.
changes: none in the repo; notes written to `.plan/work/INV3-build/notes.md`
verification: 5 shell commands (git log, ls, rg/sed reads of Makefile, pyproject, scripts/check-reproducible-build.py, tests, .plan/work/M03-T05/notes.md, target and SOURCE_DATE_EPOCH rg), all read-only, all pass; no build or suite run
risks: `make dist` may be non-reproducible in the way M03-T05 reports (inferred cause, not re-run); the reproducibility check gives a false sense of byte identity; T03 artefacts may be gone
questions_for_g: Should the release gate compare sdist bytes or only members, and should `make dist` be made byte-reproducible before 1.3.0 is tagged?

### Findings

**1. exists**
- `Makefile:104-118` `dist` target: `git archive HEAD` into a mktemp dir, sdist then wheel via setuptools `build_meta`, copied to `dist/`.
- `Makefile:88-101` `release-archive`: wheel from archived source, rejects build/ and egg-info, runs `scripts/check-archive-wheel.py`.
- `scripts/check-reproducible-build.py` (72 lines): two builds with `SOURCE_DATE_EPOCH` from commit time (`:44`, `:55`); wheel compared by bytes (`:65`); sdist compared by member names and content digests only (`:66`, helper at `:18-30`).
- `scripts/release-smoke.sh:7-18` consumes `dist/*.whl` and `dist/*.tar.gz`.
- `tests/test_check_reproducible_build.py` (28 lines): one test of member ordering and content detection.
- `pyproject.toml:2-3` build-system `setuptools>=84.0.0`; `pyproject.toml:7` version `1.3.0`.
- `.gitignore:9` ignores `dist/`; `.clean-development.json:8` lists `dist`.
- `docs/development/runbook.md:97-110` describes the targets and release order.

**2. works**
- `git log --oneline`: HEAD `58084bb`; `d9f050f` "release: prepare 1.3.0" in history.
- `rg '^(audit-deps|release-archive|release-check)[: ]' Makefile`: targets at `Makefile:57`, `:78`, `:88` exist.
- `rg SOURCE_DATE_EPOCH Makefile pyproject.toml`: no hits, so `make dist` does not pin the epoch.
- `scripts/check-reproducible-build.py:44` is the only place the variable is set.
- Not run: `make dist` itself.

**3. broken**
- none observed (no failing command run).
- By reading: `scripts/check-reproducible-build.py:66` compares sdist members, not archive bytes, so "reproducible build ok" does not show byte-identical sdists.

**4. dead candidates**
- none found in the slice; `sdist_members`, `build`, `digest` are referenced in the script and its test.

**5. contradictions**
- `docs/development/runbook.md:106` presents the check as the reproducibility gate before tagging; the code (`scripts/check-reproducible-build.py:66`) and runbook `:101` only compare members and digests. The gate overstates what it proves.
- `docs/development/runbook.md:98` describes `make dist` without timestamps or epoch; `Makefile:104-118` sets neither.
- `.plan/work/M03-T05/notes.md` reports: plain `make dist` runs differ in both wheel and sdist hashes; with `SOURCE_DATE_EPOCH` set, the wheel hash matches across runs (`6b2efad8...27e0`) but sdist hashes differ (`60aba540...f1ce` vs `e1306580...9009`); T03 hashes cannot be reproduced. Taken from that note; not re-run here.

**6. open questions**
- Does setuptools >=84 honour `SOURCE_DATE_EPOCH` for the sdist gzip header? Settle by running `make dist` twice with the variable set and `shasum -a 256 dist/*`, or by reading setuptools' sdist code in the build venv. Inferred cause: Python `tarfile` "w:gz" uses the clock for the gzip mtime; file modes come from extraction and umask.
- Do the T03 artefacts still exist? `.plan/work/M03-T05/notes.md` says no `.whl` or `.tar.gz` survives in its scratch dir. Settle with `ls dist/` in the release checkout.
- Neighbour: `docs/development/runbook.md:110` release publication (`gh release create`) needs G's yes naming v1.3.0; not inspected.
