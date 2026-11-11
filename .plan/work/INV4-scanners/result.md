## RESULT INV4-scanners
status: done
summary: Both scanners live inside their test files, not in separate modules. All named planted tests exist, but the two shadow-callee limits (`info`, `list`) have no planted case. The DEC-011 ID is used for two different decisions across the archive and live logs. Nothing was run; claims rest on reading.
changes: none (notes written to `.plan/work/INV4-scanners/notes.md`)
verification: 2 shell commands (git log/wc/rg test-name check; notes write), no test or build runs, none
risks: DEC-011 collision could mislead a reviewer tracing the scanner limits; `test_a_receiver_proved_not_to_be_an_opener_is_not_a_site` is cited for the `pathlib.Path` rebinding limit but its body was not read in full; the `info`/`list` shadow limits lack a planted case.
questions_for_g: none

### Findings

1. exists
- `tests/test_read_boundaries.py` (3386 lines), scanner classes `_Module` :361, `_Resolver` :831, scan at import :788.
- `tests/test_http_verb_allowlist.py` (1389 lines), constants :58-111, `_classify` :363, `scan_tree` :781.
- `src/azure_tenant_audit/adapters/read_guard.py` (runtime backstop; imported at `tests/test_read_boundaries.py:34`).
- `docs/reference/security-privacy.md:206-245` (limits tables, 13 read-boundary rows, 4 HTTP rows).
- `.plan/DECISIONS.md:69` (DEC-008), `:80` (DEC-009); `.plan/BACKLOG.md:15-16`.

2. works
- All 14 named planted tests exist at the def lines in the notes (read-boundary :2085-3078; HTTP :989-1373). Checked with rg for the def names.
- The HTTP origin join at `tests/test_http_verb_allowlist.py:602` matches BACKLOG :16 and `.plan/work/REV-M04-T01/result.md:25`.
- Planted HTTP limits 1 and 2 are present at `tests/test_http_verb_allowlist.py:1187` and `:1214`.

3. broken
- none found by reading. Nothing run.

4. dead candidates
- none identified. No stale directories in the slice.

5. contradictions
- DEC-011 is cited as the v2 scanner-limit decision (`.plan/archive/plan-v2/DECISIONS.md:94`), but the live log uses DEC-011 for "Release 1.4.0" (`.plan/DECISIONS.md:98`). Cited from `tests/test_read_boundaries.py` (13, 17, 142, 1551, 2047, 2074, 2124, 2183, 2787-2795, 3049, 3085, 3122), `tests/test_http_verb_allowlist.py:1167`, `.plan/DECISIONS.md:83`, and `.plan/milestones/M04-boundary-scanners.md:11,33`.
- `docs/reference/security-privacy.md:228` says the import limit is covered for the declared form only; `.plan/DECISIONS.md:77` says the non-declared forms still fail to join. Partial coverage, not a clean match.
- `docs/reference/security-privacy.md:224-226`: the `info`/`list` shadow rows point to `test_values_proved_literal_stay_resolved` (`tests/test_read_boundaries.py:2374`), whose body uses those names only as ordinary calls. Docs say this is the "nearest test" (`:219`), so no planted case exists (inferred).

6. open questions
- Does `test_a_receiver_proved_not_to_be_an_opener_is_not_a_site` (`tests/test_http_verb_allowlist.py:1353`) actually plant `pathlib.Path = factory`? Read its body to settle it.
- Does `.plan/work/M04-T03/result.md` map all six DEC-011 limits to tests, as the milestone claims?
- Neighbouring area, one line: `.plan/BACKLOG.md:9-13` (fixture path, Ruff, vendored skills) sits outside this slice.
