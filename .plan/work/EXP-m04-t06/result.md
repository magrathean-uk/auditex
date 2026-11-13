## RESULT EXP-m04-t06
status: done
summary: M04-T06 drafted in milestone format (criteria, verify, files), with evidence, at head 5ec21e0. The full draft is in .plan/work/EXP-m04-t06/notes.md.
changes: none (only .plan/work/EXP-m04-t06/notes.md written)
verification: one scratch probe of the matcher on this head, run with the main checkout's .venv (pass); no tests or benchmark run (read-only brief)
risks: a note line may change the contract-smoke digests if that run withholds anything (unknown); cutting a name across units only matters where the matcher joins (newline, unquoted comma); the task and the T05 doc edit both touch the stated limit
questions_for_g: none
### Findings
Today the final pass hands the matcher the whole rendered file as one string, and any unresolved initial-bearing name replaces that whole string with `<redacted-text>`. T06 should withhold only the line or cell holding the unresolved extent, and every unit that extent touches. It should add one number-only note line, emitted only when the count is above 0.
1 Final pass: `src/auditex/reporting.py:3907-3910` calls `redact_output(..., markup=True)`; also `reporting.py:1735` (customer pack) and `src/auditex/cli.py:633` (Markdown preview). The string branch of `_Redactor` calls `matcher.mask(value, markup)` on the whole file (`output_redaction.py:1967-1974`).
2 Placeholder: `TEXT_PLACEHOLDER` is at `output_redaction.py:46`. `_NameMatcher.mask` returns it for the whole `text` at `:1698-1703`. I reproduced "Neral A B C D E Vosk\nrest of file Vosk" turning into the placeholder entirely.
3 Note: `unmatched_names_note` is at `output_redaction.py:1572-1583`. It carries a total plus a per-reason count from `RedactionContext.unmatched_names` (`:292`, `:1127`; reasons `:1291`). `reporting.py:3913-3925` places it in html and md only, called at `:4013`. CSV and pack files carry no note today. The context is frozen, so the new count must come back from the pass (inferred).
4 Split names today (ran a probe with "Neral A. Vosk"):
   - Across a newline or an unquoted comma: matched (`_joins` at `:1296-1304`; test `tests/test_redaction_person_names.py:161`).
   - Across HTML `</td><td>`, or quoted CSV `"Neral","Vosk"`: not matched, because tags break the walk (`:1260`, `:1654`). So the "rest of the name stays readable" test matters for newline and unquoted comma. For HTML and quoted CSV, write the test as "withheld unit leaves no token", and it will pass trivially.
5 Existing tests:
   - Final pass and markup: `tests/test_redaction_person_names.py:444`, `:476`, `:488-491`.
   - Note: `:210-211`, `:251`, `:266-267`, `:394-401`.
   - Scan budget: `tests/test_redaction_scan_budget.py:347` (probes at most tokens x 6, window at most 6), `:365`, `:387`, `:411`, `:442`, `:518`.
   - HTML peak: `benchmarks/html_peak.py:27` (1.15).
6 Files T06 must own: `src/azure_tenant_audit/output_redaction.py` (matcher, unit split and note builder only), `src/auditex/reporting.py` (`_final_pass` and `_with_unmatched_names_note` only), `tests/test_redaction_person_names.py`, `tests/test_redaction_scan_budget.py`. Add `src/auditex/cli.py` only if the Markdown preview must carry the line.
7 Verify: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py tests/test_redaction_keyed_pseudonyms.py tests/test_writer_sinks_d3.py && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`
8 Contract: `docs/reference/output-contract.md` does not mention the note. The wording lives in `docs/reference/security-privacy.md:537-583`, which M04-T05 owns. The contract-smoke digests are hashes, so I could not tell whether that run triggers withholding. If the line is emitted only when the count is above 0, the digests are unchanged unless it does. Settle it on the task branch with `make contract-smoke && .venv/bin/python scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract`.
9 Unknown: whether `tests/test_writer_sinks_d3.py` exercises the final pass for pack files. It is in the verify line as a guard, and I did not read it.
