## RESULT GATE-M02-M04
status: done
summary: `make test` and `make acceptance` both exited 0 on the `main` head. Neither run had a failure. The replay reported 1 passed with no skips. The replay test ran with the kit path set and passed, but the log shows no separate line for the hash check.
changes: none (git-ignored `.venv` link only)
verification: `git rev-parse HEAD` = fe9d1e454b4f53662fe548c248409183ce5f7d6a; `make test` pass (22547 passed, 273 skipped, 0 failed, 7 deselected, 34 xfailed); `make acceptance` pass (exit 0); replay hash check not logged separately, see risks
risks: The 273 skips in `make test` are the suite's own conditional skips and I did not review them. The acceptance log carries no separate hash-check line, so I am inferring the check passed because the replay test passed.
questions_for_g: none

### Findings
- Commit tested: fe9d1e454b4f53662fe548c248409183ce5f7d6a.
- `make test`: 22547 passed, 273 skipped, 0 failed, 7 deselected, 34 xfailed in 1404 s.
- Kit sha256:
  - `vectors.jsonl`: 3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e
  - `a2-vectors.jsonl`: 0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b
  - `a2-label-overrides.jsonl`: 74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1
- `make acceptance` per suite:

  | Suite | Passed | Skipped | Failed |
  |---|---|---|---|
  | v3.9.1 replay (`value_rule_acceptance`) | 1 | 0 | 0 |
  | explainer mutation, chunks 00-03 | 4 (1 each) | 0 | 0 |
  | explainer twins | 1 | 0 | 0 |
  | explainer byte-identical | 1 | 0 | 0 |

- Logs are in my `$TMPDIR` (`gate-test`, `gate-acceptance`). I wrote no notes to `.plan/work`.
