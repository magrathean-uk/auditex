## RESULT M01-T03
status: done
summary: Final review round: both REV-M01-T03 urllib scanner gaps fixed, with regression tests that the old scanner fails.
Item 1 fixed: urllib Request/urlopen resolve by import origin, so aliased forms (`urlopen as send`, `Request as R`) are sites that fail classification.
Item 2 fixed: opener provenance tracked (assign/annassign/walrus from build_opener/OpenerDirector, any import form, plus inline build_opener().open); `.open` on them is a VARIABLE site.
Criteria: static enumeration with allow-list met (gaps closed); runtime guard refusal met (test_read_guard); graph.py comment met (unchanged); allow-list still equals the frozen inventory.
changes: tests/test_http_verb_allowlist.py (commit 798a49c); notes appended at .plan/work/M01-T03/notes.md
verification: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_read_guard.py tests/test_graph_read_only.py tests/test_transport_hygiene.py` pass (358 passed, exit 0); module `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py` pass; `make contract-smoke` pass; old scanner at 49ae521 confirmed to produce zero sites for both review examples; git status clean
risks: Opener tracking is module-wide and name-based; an opener passed as an untyped parameter or held in a container (`self.openers[0].open`) is still unseen (recorded in notes, not widened per the brief).
The SessionStart hook reported that clean-development lifecycle registration failed. The reviewer's run of `clean-development doctor` also failed, and G should be told.
questions_for_g: none
