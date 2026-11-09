## RESULT M04-T02
status: done
summary: All three repair items are fixed in fab93a5, each with planted tmp_path regressions. Item 1 fixed: a `**mapping` at a launcher is resolved and its text keys are scanned; a mapping the scan cannot see leaves the launch unresolved. Item 2 fixed: `_origin` is replaced by `_origins`, which counts every binding and every import of a name. Item 3 fixed: defaults, annotations, decorators, class bases and a comprehension's first iterable now resolve in the enclosing scope, in both the command scan and the Google scan.
Nearby gaps closed or failed closed (full list in notes.md):
- The command scan had the same default-scope fail-open.
- A later import of a name hid an earlier one, and an import hid a plain alias.
- A launcher re-exported by another source module was not followed.
- `posix`/`nt` are now read as `os`; `sys.modules`, `builtins.__import__` and `importlib.__import__` with a literal name now resolve.
- `getattr(loop|adapter, "literal")` callees are now treated as the method.
- `subprocess` `input=` is now scanned.
- These are now reported: computed `sys.modules`; importers or dynamic builtins used as values; `eval`/`exec`/`compile`; `globals()`/`locals()`/`vars()` in a module that binds a launcher; any star import.
- Google handles bound at module scope or in a class body now fail closed.
Criteria: L1 met, L2 met, L3/L4 met. No real content read on main. File scope is only the owned file.
changes: tests/test_read_boundaries.py (commit fab93a5)
verification: `.venv/bin/python -m pytest tests/test_read_boundaries.py tests/test_read_guard_content_cmdlets.py` passed on fab93a5 (671 passed); `git diff --check` passed; old-vs-new evidence run: 30 planted cases, 0 pass on b7e3438, 30 pass on fab93a5 (evidence.md, Repair round 1). `_UNTRACEABLE_LAUNCHES` (1 row), `_UNRESOLVED_RUNNER_INPUTS` (21 rows) and the 28-method Google pin are unchanged. Not run: make test and make contract-smoke, because only the test file changed and the brief's verify command covers it.
risks: `getattr(obj, name)` with a computed name on a runtime object (not a launcher module) is still not judged; the scan also cannot read a script written to stdin after the process starts (`communicate`, `stdin.write`). Both are listed for M04-T03 in notes.md. `_origins` counts bindings from every scope in a module: this fails closed but could flag new src code later. One commit covers all three items because they touch the same functions in one file.
questions_for_g: none
