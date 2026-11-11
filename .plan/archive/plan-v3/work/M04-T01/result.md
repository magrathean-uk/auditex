## RESULT M04-T01
status: done
summary: Review item fixed: read the M01-T03 notes, the REV-M01-T03 result, archive BACKLOG line 10 and DEC-009, and modelled the change on M04-T02's proven-literal rule.
Every `.open` call, `.open` taken as a value and `getattr(x, "open")` now needs a proved receiver. The scanner checks every value each name can hold anywhere in the module, in every binding form, with global and nonlocal included, plus attribute stores across src. A receiver it cannot prove is UNRESOLVED, fails the suite and cannot be allow-listed. Changing or deleting an object's `.open` is also UNRESOLVED.
Criterion 1 met: both limits (untyped parameter, container) have planted tmp_path tests. 61 of 63 planted cases passed silently on the old scanner; the 2 it already caught stay as regression checks. All 63 fail now.
Fail-closed rule for request values: urllib Request/urlopen with `*args`, `**kwargs` or an unknown keyword are no longer GET; a positional method is read; a urlopen URL literal counts as GET only with a scheme. The REV-M01-T03 opener-alias backlog item is closed too.
Criterion 2 met: on main, 37 `.open` sites, all `os.open` and proved safe; 0 unresolved; no new real call site; no model-endpoint site in src.
changes: tests/test_http_verb_allowlist.py (commit 9f6e3a7)
verification: `.venv/bin/python -m pytest tests/test_http_verb_allowlist.py tests/test_transport_hygiene.py` pass on 9f6e3a7 after rebase; module verify `.venv/bin/python -m pytest tests/test_read_guard.py tests/test_graph_read_only.py tests/test_contract.py` pass and `make contract-smoke` pass; `! git grep -q -i 'chat/completions' -- src` pass; ruff check pass; old-scanner comparison in .plan/work/M04-T01/old-scanner-check.log (evidence.md, notes.md); git status clean
risks: Named limits for M04-T03 and BACKLOG (DEC-009): another module writing through `__dict__`, `vars(obj)` or `sys.modules`; an argument that contradicts a trusted parameter annotation; httpx `stream`; a computed getattr name.
The scanner deliberately over-approximates: a parameter or class attribute sharing a receiver's name anywhere in the module makes that receiver unresolved (it fails, never passes silently). A future `.open` on an untyped value or a type outside `_NON_OPENER_TYPES` will need the value proved or the table widened by review.
The SessionStart hook reported that clean-development lifecycle registration failed; `clean-development doctor` was not run, per the brief.
questions_for_g: none
