## RESULT REV-M04-T04
status: done
summary:
verdict: approve
reviewed: d7b44247c103ba17d204be71b778184080691dd3
Approval is bounded to B1/B2 under DEC-044.
changes: none; progress file skipped because the sandbox is read-only
verification: git status, rev-parse, diff and diff --check PASS; code inspection completed; tests not executed as instructed
risks: external executing checks remain required; stated limit below needs recording in M04-T05
questions_for_g: none
### Findings
B1 fixed - src/azure_tenant_audit/output_redaction.py:1698-1703 withholds the five-initial extension despite a shorter hit, with or without a title; no additional probe or wider window.
B2 fixed - src/azure_tenant_audit/output_redaction.py:1253-1255 includes every Mn, Mc and Me character in source-spanned tokens; equivalent spellings fold consistently in both directions and retain original offsets.
3. tests/test_redaction_person_names.py:814 asserts B1 withholding; :827 asserts bidirectional equivalence, repeated replacements, preserved surrounding text, markup and idempotence; tests/test_redaction_scan_budget.py:542 asserts withholding and unchanged per-start, total-probe and window bounds. No new assertion pins a readable name or weakens a budget.
4. Only the matcher and the two permitted test files changed; behavioural changes are confined to the intended withholding and mark-tokenisation repairs. Budget constants and replacement logic are unchanged.
### Stated limits
src/azure_tenant_audit/output_redaction.py:1700 - With directory identities “Neral” and “Neral Vosk Taren”, “Vosk Taren” remains readable in “Neral A B C D Vosk Taren”: the six-token window ends on a non-initial prefix, allowing the shorter match to survive.
