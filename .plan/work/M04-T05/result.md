## RESULT M04-T05
status: done
summary: Rebased onto main without conflict. The masking passages in `docs/reference/security-privacy.md` now match the merged matcher, and all four review items are addressed. The limits and the session-key clause are added.
changes: docs/reference/security-privacy.md
verification: `grep` verify line PASS, run against `.plan/work/M04-T05/result.md` (my `result.md` there carries the `read-through: complete` line); `make lint` PASS; git status clean. No negative case: docs-only change.
risks: Items 1 to 4 below were checked against `output_redaction.py` only by reading it; I ran no matcher test. The nine privacy-review limits and the one T04 limit were copied from the review files, and I did not exercise each one. Item 5 is a wording gap in the code's note, which I did not change.
questions_for_g: none

### Findings
read-through: complete
1. Rebase: done, no conflicts.
2. Masking passages: fixed for unresolved middle initials or titles (withheld with `<redacted-text>`), parts-only user records, Unicode-form matching, and mapping keys equal to a name (withheld, `#n` on collision). The `vocabulary` count for exempt product keys was already documented.
3. Stated limits: added beside the masking boundary, covering the whole-string and whole-file withholding and that the placeholder gives no reason. The other limits are the window-end case, combining-mark and invisible-character cases, the readable mapping-key forms and parts-only records. Both the nine privacy-review lines and the T04 line are covered; the T04 line is the `Vosk Taren` window case.
4. Session key: the docs now say the key is per run and per process only when the manifest's `run_id` is usable. Otherwise it lives for the current guard context only and is shared with no other run or call (`session_pseudonym_key`).
5. Note wording: the code's fixed text says "the same words elsewhere are left as written", which is not true for `vocabulary` people (still masked in values and free text). The docs now say that. The code is unchanged and it is outside my files.
6. Other files: `CHANGELOG.md`, `docs/guides/product-manual.md` and `docs/development/scubagear-export-adapter.md` already carry the `prepare-key` and key lines, and I made no changes there.
