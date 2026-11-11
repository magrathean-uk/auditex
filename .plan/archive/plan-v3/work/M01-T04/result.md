## RESULT M01-T04
status: done
summary: `make acceptance` exited 0 under run-job. The value-rule replay passed with 0 skips. The explainer jobs all passed with 0 skips. The runbook build and acceptance sections match the Makefile and the script.
changes: none (`.venv` link only, git-ignored)
verification: load was 14.8 at start, so I waited until it fell to 10.4 and no other full `make test`, `make release-check` or `make acceptance` was running. `make acceptance` with the kit env: pass (exit=0). Sha256 of the three kit files: pass (match the runbook table).
risks: none
questions_for_g: none
### Findings
- commit: b3fc70f2775cb46b7d391dc98ad49104ff568f99
- kit sha256 (all three match the runbook table):
  - vectors.jsonl: 3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e
  - a2-vectors.jsonl: 0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b
  - a2-label-overrides.jsonl: 74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1
- hash check: passed. The replay test verifies the hashes before replaying, and it passed.
- value-rule replay (`-m value_rule_acceptance`): 1 passed, 0 skipped, 0 failed (the one test replays all vectors).
- explainer acceptance: 6 pytest invocations, each 1 passed, 0 skipped, 0 failed. These were mutation chunks 00 to 03, twins, and byte_identical.
- run-job log: `log.txt` in the run directory shows no skipped or failed lines.
- read-through verdict: exact, with no discrepancies.
  - `docs/development/runbook.md:98` (`make dist`) matches Makefile lines 127-144. It uses `git archive HEAD` in a temp dir, defaults `SOURCE_DATE_EPOCH` to the HEAD commit time, and normalises the sdist through `check-reproducible-build.py --normalise-sdist`. It then builds the wheel and copies both to `dist/`. The normaliser rewrites gzip time, member times, uid/gid and names, mode and order, as described.
  - `docs/development/runbook.md:101` (`check-reproducible-build.py`) matches the script. It makes two clones of HEAD, runs plain `make dist` with `SOURCE_DATE_EPOCH` unset, and compares wheel and sdist bytes. It names the differing artefact and exits 1 on a mismatch.
  - `docs/development/runbook.md:108-118` (acceptance) matches Makefile lines 11-20 and `pytest.ini:3-7`. The kit variable is checked as unset or missing with exit 2. The replay runs first. The explainer jobs run serially, as four chunks then twins then byte_identical. Each has a 300 s cap and `-o addopts=`. `make test` deselects both markers through `addopts`.
  - The kit hash table at lines 112-118 matches the files I hashed.
