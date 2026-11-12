## RESULT M05-T03
status: done
summary: Repair round: I made both required changes. The read-boundary table now has four more named-limit rows, covering the open classes that M05-T01 and its review handed on. The intro now says that only shadowing by a module binding is closed, and that the list covers only the limits known so far.
  I probed each class against the scanner (.plan/work/M05-T03/probe.py, probe-output.txt). No planted test closes any of them. I left out the `type` alias because it cannot hide a call (reasons below). The class M05-T02 handed on was already the first HTTP row.
changes: docs/reference/security-privacy.md (11d7b5e, 9a82562)
verification: `grep -qx 'read-through: complete' .plan/work/M05-T03/result.md` pass; make lint pass; PYTHONPATH=src pytest tests/test_read_boundaries.py tests/test_http_verb_allowlist.py pass (482); git diff --check main...HEAD pass; probes: 10 cases the scanner proves safe when they are not (the added rows), 7 that fail closed (forms with no known gap), and a control that is proven as expected
risks: The added rows rest on probes, not planted tests, which is expected for named limits. The list is only as complete as the scanners' notes and reviews.
questions_for_g: none
### Findings
read-through: complete
rows-dropped: 6
rows-kept: 13 (read-boundary 10, HTTP 3)
- Review item 1 fixed. Added rows:
  - a shortcut name called on another module or object (`helpers.info(argv)`, `obj.list(ARGV)`);
  - a call matched by name to a module function even where the call site binds the name otherwise;
  - a rebound `zip` or `enumerate` in loop unpacking, with a note that string methods, `.get` and `append`/`insert`/`extend` are matched by name but proved only on a literal receiver;
  - a store on `builtins` (`builtins.list = f`, `setattr`).
- Left out: the `type X = ...` alias, which the review marked optional. `shadows` already sees it, `.__value__` is unresolved, and the alias object cannot be called or passed as an argv.
- Review item 2 fixed. The intro claims closure only for:
  - a module binding of a read-only hand-off or conversion name;
  - the binding-form and class-body closures.
  It names the forms that stay open and no longer claims the list is complete.
- Review suggestion done: rows-kept is updated and the added rows are listed here. The per-class table and the read-through of the kept rows are in .plan/work/M05-T03/notes.md.
- No survivors of the removed wording ("shadowed-callee", "earlier tables", "opener-attribute-store", "still open are") in the doc or either scanner file.
