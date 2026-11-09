---
id: M04
name: boundary-scanners
weight: 10
status: planned
---
# M04 boundary-scanners
Runs after M02-T04 merges (shared `tests/test_http_verb_allowlist.py`). Follows up v2 DEC-011: the static scanners shipped in 1.3.0 with named blind spots.

## Goal
The static boundary scanners close the blind spots recorded under v2 DEC-011 where they can, and fail closed where they cannot: the HTTP scanner sees openers passed as untyped parameters or held in containers; the read-boundary scanner covers non-subprocess launchers, dynamic callee lookup, requests held in containers or fetched through `getattr`, and does not rely on per-module handle naming. Every limit that remains is stated in the security and privacy reference.

## Definition of Done
- [x] The HTTP scanner reports planted openers passed as untyped parameters and held in containers, and passes on `main`: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py`
- [x] The read-boundary scanner reports or fails closed on planted cases for limits L1 to L4, and passes on `main`: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_read_guard_content_cmdlets.py`
- [ ] Review: terra confirms every DEC-011 limit (the two HTTP limits and L1 to L4) is either closed by a named test or stated in `docs/reference/security-privacy.md` (read-through recorded in `.plan/work/M04-T03/result.md`)
- [ ] Full suite passes: `make test`
- [ ] Both acceptance suites, the full v3.9.1 replay included, pass at milestone close: `make acceptance`
- [ ] Review: other-vendor reviews approve the plan v3 merges of M04-T01 and M04-T02 (Tier A: network) at the exact merged heads (ARCHITECTURE.md review binding): `ok=1; for T in M04-T01 M04-T02; do ( c=$(git log v1.3.0..HEAD --format=%H -1 --grep="^Plan-Task: $T\$") && test -n "$c" && s=$(git log -1 --format=%B "$c" | sed -n "s/^Plan-Review: REV-$T approve \([0-9a-f]\{12,40\}\)\$/\1/p") && test -n "$s" && grep -qE "^[[:space:]]*(summary: )?reviewed: $s" ".plan/work/REV-$T/result.md" && grep -qE '^[[:space:]]*(summary: )?verdict: approve' ".plan/work/REV-$T/result.md" ) || ok=0; done; test $ok = 1` Orchestrator check at close (ARCHITECTURE.md provider binding): the dispatch record names a launcher of the other vendor from the author's.

## Tasks
| id | title | owner | size | tags | status |
|---|---|---|---|---|---|
| M04-T01 | Close the HTTP scanner blind spots | codex | M | hard | done |
| M04-T02 | Close the read-boundary scanner blind spots L1 to L4 | codex | M | hard | done |
| M04-T03 | State the remaining scanner limits in the privacy reference | terra | S | - | doing |

## Acceptance criteria
### M04-T01 Close the HTTP scanner blind spots
- Sources: the M01-T03 limits in the v2 work notes and the DEC-011 BACKLOG text in `.plan/archive/plan-v2/BACKLOG.md`.
- Each limit has a planted-source test (written with `tmp_path`, no new fixture directory) that fails on the current scanner and passes after the change; a call site the scanner cannot trace fails the test instead of passing silently.
- On `main` the scanner finds no new real call site; if it does, the site is classified under the ARCHITECTURE.md transport policy in `result.md` and an unclassifiable site stops the task for sol.
- Merge bar (DEC-009): the two DEC-011 HTTP limits closed for planted cases plus a fail-closed rule for openers and request values the scanner cannot prove; further bypass classes a review finds are named limits for M04-T03, not blockers.
- verify: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_transport_hygiene.py`
- files: `tests/test_http_verb_allowlist.py`

### M04-T02 Close the read-boundary scanner blind spots L1 to L4
- Sources: the M01-T04 limits L1 to L4 in the v2 work notes and `.plan/archive/plan-v2/BACKLOG.md`.
- Each of L1 to L4 has a planted-source test (`tmp_path`, no new fixture directory) that fails on the current scanner and passes after the change, or a fail-closed rule with a test proving that an untraceable launcher, callee or request fails the suite.
- On `main` the scanner finds no real content read; if it does, the task stops and the orchestrator raises it with G.
- Out of scope (DEC-008): bypasses that need in-repo code to shadow a read-only hand-off or transparent-conversion callee name, or to rebind a launcher argument name after a literal assignment through an import or a plain `with`, `def`, `class`, `except` or `match` binding or a comprehension walrus, and a launch in a class body that reads a class-local name. Further bypass classes a review finds beyond L1 to L4 are named limits, not blockers (DEC-008 amendment 2); M04-T03 lists them all.
- verify: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_read_guard_content_cmdlets.py`
- files: `tests/test_read_boundaries.py`

### M04-T03 State the remaining scanner limits in the privacy reference
- Runs after M04-T01, M04-T02 and M03-T02 merge (M03-T02 edits the same file).
- `docs/reference/security-privacy.md` lists each limit that remains after M04-T01 and M04-T02, with the test that bounds it; limits now closed are not listed. `result.md` holds the DoD read-through.
- verify: `.venv/bin/python -m pytest tests/test_docs_paths.py`
- files: `docs/reference/security-privacy.md` (scanner limits section only)
