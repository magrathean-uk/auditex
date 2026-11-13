## RESULT REV-M04-T05
status: done
summary:
verdict: approve
reviewed: c55748e8f76cc45b67b5621edf6eb802c89e204e
Both required changes from the last review are fixed. docs/reference/security-privacy.md:608-612 now matches the merged matcher and agrees with :592-594. The earlier non-blocking suggestion was also taken (:645-647).
changes: .plan/work/REV-M04-T05/evidence.md, .plan/work/REV-M04-T05/progress.md (previous evidence kept as evidence-2.md)
verification: M04-T05 verify greps (result.md read from the main checkout): pass, exit 0. Matcher behaviour taken from the evidence-2.md probe, which still applies because src has not changed since then.
risks: docs-only read-through by a reviewer from the same vendor
questions_for_g: none
### Findings
Criteria (current head):
- Precondition M04-T04 merged: met. main is an ancestor of HEAD.
- Keyed scheme, pseudonym.key and its modes, HMAC, label: met (unchanged since the last review), docs/reference/security-privacy.md:704-720.
- Key sources (run key, memory key per context, session key for a keyless run, export-derived key): met (unchanged), :722-754.
- Masking boundary with middle initials, titles and mapping keys: met, :587-626. The stale items are corrected at :608 and :609-612.
- Oracle boundary; confirm-a-guess and salt wording dropped; no read-only tool writes a run; prepare-key named: met (unchanged), :117-122, :756-764.
- DEC-004 amendments: met (unchanged), :766-789.
- CHANGELOG, manual line, adapter key lines: met (unchanged).
- read-through: complete: present, and the passage it covers is now accurate.
- DoD terra read-through item: can be closed.

Security: docs only. No secrets, code or dependencies.
Scope: main...HEAD touches only the four paths on the files line.

Required changes: none.

Re-check of the prior review:
- Item 1 (security-privacy.md:608-609, decomposed initial listed as readable): fixed. :608 now lists only the zero-width space and the fullwidth full stop.
- Item 2 (security-privacy.md:610-614, `John A. B. C. D. Smith` said to stay readable): fixed. :609-612 now say it is withheld as `<redacted-text>`, or masked when the full name is recorded. This matches tests/test_redaction_person_names.py:812-817.
- Earlier defect class "documentation of an unmerged dependency": still fixed.
- Suggestion (Orin Pask regression note): taken at :645-647. It matches .plan/work/REV-M04-T04-privacy/result.md:19.

Suggestions (non-blocking):
- security-privacy.md:609-612: this item says a name "is not left readable", but it sits in a list introduced as limits where names are left as written. Moving it next to the withholding sentence at :592-594 would read more cleanly.
