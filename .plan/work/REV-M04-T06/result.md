## RESULT REV-M04-T06
status: done
summary:
verdict: changes-required
reviewed: ce543a5075fb853aff14f170481e6b35e16d20c8
B1 remains open. Under DEC-047, do not merge this task for this release; retain whole-file withholding on main.
changes: none
verification: PASS git status --short (clean), git diff --check 4d93e40..HEAD, git rev-parse HEAD; bounded source inspection completed. No tests or network calls.
risks: Counterexample traced statically; execution gates belong to the external worker; progress file unwritten under read-only constraints.
questions_for_g: none
### Findings
- B1 open - src/azure_tenant_audit/output_redaction.py:1909, :2036; the recognisers at :1260 and :1841 terminate tags at a quoted `>`. With indexed invented name `Neral Vosk`, input `<p>Neral A B C D E</p><span title=">; Vosk"></span>` becomes `<p>&lt;redacted-text&gt;</p><span>; Vosk"></span>`: only the attribute prefix is stripped, the semicolon stops extension, and the surname becomes visible text. Whole-string withholding removes it. Ordinary nested, self-closing and trailing tags are covered, but this valid attribute defeats B1; comment content containing `>; Vosk` has the same failure.
- B2 closed - src/azure_tenant_audit/output_redaction.py:1833; character references display `<redacted-text>` in Markdown prose, raw HTML blocks and HTML. Inside Markdown code spans or blocks, literal `&lt;redacted-text&gt;` is acceptable as a visible marker.
- Point 3 - tests/test_redaction_person_names.py:1077 and :1096 assert the intended trailing-tag removal, counts and marker visibility for their fixtures. They miss the quoted-delimiter counterexample. Changed expectations retain no readable name part; tests/test_redaction_scan_budget.py:576, :601 and :640 change only marker spelling, preserving every budget assertion.
- Point 4 - Only the four task paths changed. Tag reach and marker representation change as intended; visible-token allowances, CSV parsing, note logic, probe/window budgets and pseudonyms remain unchanged. `_bare_tag` preserves the previous stripping expression.
### Stated limits
- Visibility checks use entity decoding and HTMLParser, without a Markdown renderer; literal self-closing syntax and Markdown code contexts have no new explicit regression cases.
