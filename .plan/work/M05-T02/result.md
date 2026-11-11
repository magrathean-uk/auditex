## RESULT M05-T02
status: done
summary: An imported name with a dot in it (`pathlib.Path`) is now trusted only when no module under `src/` stores an attribute on its path. It does not matter what the store is made on (`x.Path = ...`, a literal `setattr`, a class-body `Path`), and any `setattr`/`delattr` with a computed name also stops the trust. Otherwise the receiver is UNRESOLVED and fails the suite; the fail-closed rule is unchanged.
  The new check is `_Program.origin`. Both places that build trusted import names go through it: the import binding and the attribute join.
  Planted cases: 21 failed before the change and pass after (20 combinations of 5 read forms and 6 store forms, plus a store in the reading module). A store on a middle segment (`urllib.request`) moved from VARIABLE to UNRESOLVED; both fail the suite.
  10 cases passed before and after because the existing rule already caught them, and 5 controls stay proved. Each case is listed in `.plan/work/M05-T02/evidence.md`.
  Decision citations now name their plan: v2 DEC-011 (as the criterion asks), plus v3 DEC-009 and v2 DEC-006, because the live log reuses those numbers.
changes: tests/test_http_verb_allowlist.py (commit b659143, SSH-signed)
verification: PYTHONPATH=src .venv/bin/python -m pytest tests/test_http_verb_allowlist.py on b659143: pass (159 passed); make lint: pass (compileall and Ruff, all checks passed); before and after run of the planted tests with the old resolver restored in a scratch copy: 22 failed before, 37 passed after; git status --porcelain: empty; make test: not run, the review says it runs once for the merged batch
risks: docs/reference/security-privacy.md:242 still lists this limit and cites test_a_receiver_proved_not_to_be_an_opener_is_not_a_site. That file is not mine, so M05-T03 or M05-T04 should drop the row or point it at the new tests.
  The check matches attribute names only, so it over-reaches: any store named `Path`, `PosixPath` or `WindowsPath` anywhere under `src/`, or a computed `setattr` on self, would make every pathlib receiver fail. None exists today; the only receivers proved in the real tree are `os.open`.
  Named limit for M05-T03: a store made from another module through `__dict__`, `vars()` or `sys.modules` is still not seen, as the file's header already says.
questions_for_g: none
