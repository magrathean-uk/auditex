## RESULT REV-M01-T03
status: done
summary:
verdict: approve
reviewed: 798a49c4d7e78744bddf82ba60de4ad9beb47441
Both urllib gaps closed with regression tests; no regression found against 49ae521.
Allow-list still matches section E's operations, methods and classes.
changes: none
verification:
- PASS: read-only `python -B -c` harness executed 48 scanner cases and nine Graph refusal cases.
- PASS: all six new regressions were missed by 49ae521 and rejected by HEAD.
- PASS: all 38 existing source classifications unchanged; allow-list and guard-map ASTs unchanged.
- PASS: inventory comparison; A24 destination wording correction leaves allowance scope unchanged.
- PASS: `git diff --check 49ae521 HEAD`; working tree clean.
- SKIPPED: full pytest command because its fixtures create temporary directories; builds and installs prohibited.
- FAIL: environment-required `clean-development doctor`; routing mismatches and unverifiable lifecycle lock.
risks:
- Full pytest suite was not independently rerun.
- Lifecycle registration remains unconfirmed; diagnostic issues reported without repair.
questions_for_g: none
### Findings
- CLOSED: aliased urllib Request/urlopen imports resolve by origin and fail classification when unlisted.
- CLOSED: opener construction provenance detects arbitrarily named receivers, attributes and inline calls.
- BACKLOG, non-blocking under DEC-011: `_opener_names` does not propagate `alias = client`; subsequent `alias.open(...)` remains unseen. Confirmed by an in-memory probe.
