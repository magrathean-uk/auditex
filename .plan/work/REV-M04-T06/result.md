## RESULT REV-M04-T06
status: done
summary:
verdict: changes-required
reviewed: 9a678b843d5cf08699734e5342d27a20d91a5d87
Read-only review complete. Counterexamples below are traced from source, not executed.
changes: none
verification: PASS git status --short (clean), git diff --stat main...HEAD, git diff main...HEAD, git diff --check main...HEAD, git rev-parse HEAD; tests, lint, benchmark, smoke and negatives not run, as instructed
risks: Runtime gates remain untestable here; progress/evidence files not written because the sandbox is read-only
questions_for_g: none
### Findings

- T06 preconditions: met; main contains the M04-T04 and M04-T05 merges. Criteria: .plan/milestones/M04-d5-keyed-pseudonyms.md:85.
- T06 review/check gate: review completed here; executing check untestable. .plan/milestones/M04-d5-keyed-pseudonyms.md:86.
- T06 unit withholding: not met fully, findings 1-4 and 6. Structure pass unchanged: src/azure_tenant_audit/output_redaction.py:1721 still returns the whole-string placeholder.
- T06 split-name protection and DoD final item: not met, findings 1-2. src/azure_tenant_audit/output_redaction.py:1875; .plan/milestones/M04-d5-keyed-pseudonyms.md:22.
- T06 note: not met in emitted output, finding 5. Builder emits only a positive count, with no name, length or position; vocabulary exception now accurately describes product-field names. src/azure_tenant_audit/output_redaction.py:1583.
- T06 budgets/pseudonyms: matcher still uses at most six probes per start and a six-token window; extension adds no probes. Reporting repeats the entire scan, finding 5. Pseudonyms still use pseudonym() with the validated 32-byte key: src/azure_tenant_audit/output_redaction.py:300, :310, :1851. Existing budget assertions and keyed tests are unedited.
- T06 test naming: met, tests/test_redaction_person_names.py:948 and tests/test_redaction_scan_budget.py:562. Documentation update deferred by this brief; docs/reference/security-privacy.md:560 still needs the authorised follow-up.
- T06 verify, benchmark ratio, masking benchmark and contract smoke: untestable here. .plan/milestones/M04-d5-keyed-pseudonyms.md:90.
- Interface/scope: met; withheld_units is an additive optional keyword, including a local-profile zero. All four changed paths and changed functions fit the files line. src/azure_tenant_audit/output_redaction.py:2283; src/auditex/reporting.py:3905.
- DoD design approval: met, .plan/DECISIONS.md:33. DoD test, initials/title/key, benchmark and milestone-close gates: untestable at this head, .plan/milestones/M04-d5-keyed-pseudonyms.md:15. Contract version difference is met statically, src/azure_tenant_audit/contracts.py:25.
- DoD prior reviews: recorded approvals match the merged review heads, .plan/work/REV-M04-T03/result.md:4, .plan/work/REV-M04-T03-privacy/result.md:4, .plan/work/REV-M04-T04/result.md:4 and .plan/work/REV-M04-T04-privacy/result.md:3; launcher provenance untestable. Prior documentation read-through recorded: .plan/work/M04-T05/result.md:12.

Boundary tracing after exhaustion, at src/azure_tenant_audit/output_redaction.py:1867:
- Plain line break, wrapped Markdown and an indented continuation of one list item: both units withheld for the tested single-word suffix.
- Unquoted CSV comma and quoted adjacent fields: both parts withheld by replacing their physical line. A quoted multiline cell also loses both touched lines in the supplied simple case.
- HTML </td><td>: both cells withheld for a single-word suffix. Nested visible tags are traversed, although wrappers can become malformed, finding 6.
- Markdown cells on one row: both parts withheld because the entire row is one line. A name split across separate pipe-prefixed rows or separate bullet items is not matched across that boundary today: existing _joins punctuation limit, src/azure_tenant_audit/output_redaction.py:1297.
- Tags, quoted CSV boundaries and Markdown pipes encountered before exhaustion still interrupt matching: existing opaque-tag/separator limits, src/azure_tenant_audit/output_redaction.py:1664. Attribute-only names remain opaque; the newly retained unresolved suffix case is blocking, finding 2.

The counted note reaches HTML/Markdown reports and exports, including customer-pack report.md. It does not reach CSV, JSON/SARIF/OSCAL, other pack files or the CLI Markdown payload path: src/auditex/reporting.py:3914, :2123, :1735; src/auditex/cli.py:633.
No output-contract field/schema change is needed for this note. The recorded digest comparator does not render these reports: scripts/compare-run-outputs.py:38, :160. Its summary.md is engine-written, src/azure_tenant_audit/output.py:923. A note-only change should move no recorded digest; execution remains pending.

Required changes:

1. src/azure_tenant_audit/output_redaction.py:1875 - extension stops after one non-initial. With display name “Neral Vosk Taren”, `Neral A B C D E\nVosk\nTaren` leaves “Taren” readable; the old rule withheld everything. Cover compound suffixes across all touched units without extra probes, with whole-string fallback where extent cannot safely be bounded; add line/cell regressions.
2. src/azure_tenant_audit/output_redaction.py:1873 - skipped tags retain unresolved attribute content. `<td>Neral A B C D E</td><td title="Vosk">ok</td>` preserves “Vosk” after withholding both text cells. Conservatively redact attributes on traversed tags, or withhold an encompassing safe unit; add this regression.
3. src/azure_tenant_audit/output_redaction.py:1796 - raw `<redacted-text>` disappears as an empty element in HTML and HTML-enabled Markdown viewers. Escape inserted placeholders for HTML/Markdown, preserving the literal visible marker. CSV/plain text display it; structured formats remain unchanged.
4. src/azure_tenant_audit/output_redaction.py:1862 - physical-line CSV replacement can remove one closing quote from a multiline record and change later-row parsing. Use quote-aware logical records or fields and serialise replacement cells safely. Test a record opening before the withheld line and closing on it, followed by intact rows.
5. src/auditex/reporting.py:3915 - the second pass rescans original content plus the note. Markdown ending `Neral A B C D E` consumes “Name” as its suffix and withholds the newly appended count line; the first count then understates emitted units. Attach the fixed note to already-redacted output at a safe boundary, without rescanning the report.
6. src/azure_tenant_audit/output_redaction.py:1908 - independent wrapper trimming unbalances nested tags. `<p><b>Neral A B C D E</b> Vosk</p>` retains `<p><b>` but deletes `</b>`. Retain only balanced wrapper pairs, or replace the complete enclosing element safely.
7. src/azure_tenant_audit/output_redaction.py:1772 - closure repeatedly scans every hit using stale unit keys. A chain of “Orin Pask” matches crossing successive lines grows one unit per iteration, producing quadratic work. Use an interval sweep/work queue and add a full-closure linearity regression.

Non-blocking: src/azure_tenant_audit/output_redaction.py:1745 retains sliced pieces while :1795 builds another set, so withholding can copy retained spans twice. Store offsets and materialise once; the peak ratio remains untestable.
Non-blocking: zero-count notes are byte-identical except for the expressly requested vocabulary correction at src/azure_tenant_audit/output_redaction.py:1584; qualify the byte-identity claim accordingly.

### Defect classes

Incomplete unresolved-extent closure; retained opaque attributes; invisible placeholders; CSV record corruption; note replay/count instability; unbalanced HTML; quadratic propagation.
