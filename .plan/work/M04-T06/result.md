## RESULT M04-T06
status: partial
summary: verify deferred: heavy slot busy. hostload deferred twice (exit 75); the slots were held by trackex-boot-test and CHK-M04-T06. make lint, the verify command and make contract-smoke with the digest comparison did not run, so there is no HTML peak figure yet.
B1 fixed: `_extend` now also covers every tag that still has attributes, or is a comment, on the way to whatever stops the walk: a token, a separator or the end of input. Those tags lose their attributes in HTML, and the lines and fields they sit in are withheld in Markdown and CSV. New helper `_bare_tag`, also used by `_html_regions`.
B2 fixed: the Markdown placeholder is now `&lt;redacted-text&gt;`, the same as HTML. It shows as `<redacted-text>` in Markdown prose, raw HTML blocks and HTML. Inside a Markdown code span or block it is not decoded, so it shows literally as `&lt;redacted-text&gt;`, which is still visible marker text.
Review items: 1 (B1) fixed; 2 (B2) fixed, with the one doc sentence updated; 3 nothing else changed (budgets, probes, pseudonyms, note and CSV handling untouched); 4 see verification; 5 deferred (heavy slot).
changes: src/azure_tenant_audit/output_redaction.py, tests/test_redaction_person_names.py, tests/test_redaction_scan_budget.py, docs/reference/security-privacy.md
verification: `.venv/bin/ruff check` on the three changed Python files: pass (All checks passed!).
`pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py -k final_pass_unit`: pass (37 passed).
New tests:
- `test_final_pass_unit_trailing_attribute_tag_keeps_no_content`, five cases: the reviewer's next-cell `<span title="Vosk">`, an `<img alt>` in the same cell after a withheld `<p>`, a tag at end of input, a comment at end of input, and a Markdown next line.
- `test_final_pass_unit_placeholder_shows_in_markdown_prose_raw_html_and_html`.
To check they fail on 4d93e40, I ran them against a `git archive 4d93e40` with the new test files copied in, and all six failed by behaviour:
- the HTML cases kept `title="Vosk"`, `alt="Vosk"` or `<!-- Vosk -->`;
- the Markdown case kept `<span title="Vosk">`;
- the B2 test failed because `\<redacted-text\>` still holds `<`.
Assertions changed only where they pinned the old Markdown marker: W_MD in person_names, and scan_budget lines 576, 601 and 640.
Grep for the removed `\<redacted-text\>` form across src, tests and the doc: no survivors.
Deferred: `make lint`, the full verify command (with the HTML peak ratio), `make contract-smoke` and the digest comparison.
risks: Stripping attributes from tags right after an unresolved name can change styling of the next cell, for example a `<td class>`. The reach can also withhold a Markdown line that holds only such a tag. Both err on the safe side.
Contract-smoke digests are unchecked until the deferred run. The Markdown marker change only shows up where something is withheld, so digests should move only if the smoke run withholds a unit.
questions_for_g: none
