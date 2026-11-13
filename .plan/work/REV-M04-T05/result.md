## RESULT REV-M04-T05
status: done
summary:
verdict: changes-required
reviewed: 00507754d7d9aec04ba0f55a2d0c73609a2ef4ae
Rebased onto main with M04-T04 merged. The new masking text, the nine privacy-review limits, the T04 limit, the session-key clause and the note-wording line all match the merged code.
Prior item 1 is only partly fixed: docs/reference/security-privacy.md:608-614 still list two cases as readable that the merged matcher masks or withholds, and :610-614 contradicts the doc's own :592-594.
changes: .plan/work/REV-M04-T05/evidence.md, .plan/work/REV-M04-T05/progress.md (prior evidence kept as evidence-1.md)
verification: M04-T05 verify greps (result.md read from the main checkout): pass, exit 0; matcher probed read-only with main .venv: output in evidence.md
risks: author ran no matcher test for the docs claims; same-vendor read-through only
questions_for_g: none
### Findings
Criteria (current head):
- Precondition M04-T04 merged: met (main is an ancestor of HEAD).
- Keyed scheme, pseudonym.key and its modes, HMAC, label: met, docs/reference/security-privacy.md:704-720, :101.
- Key sources (run, memory per context, session for keyless with the run_id clause, export-derived): met, :722-754; matches src/azure_tenant_audit/output_redaction.py:341-360.
- Masking boundary with middle initials, titles, mapping keys: not met. :581-594, :616-657 are correct, but :608-614 are stale (required change 1).
- Oracle boundary, confirm-a-guess and salt wording dropped, no read-only tool writes a run, prepare-key named: met, :117-122, :361-362, :756-764.
- DEC-004 amendments (keyless kinds, no MCP approval claim, nolock and flush limits, temporary-key stability): met, :117-122, :766-789.
- CHANGELOG, manual line, adapter key lines: met (unchanged since the first review).
- read-through: complete: present, but the passage it vouches for still carries stale claims.
- DoD terra read-through item: open until change 1 is made.
Security: docs only; no secrets, code or dependencies. Scope: all four paths are in the files line.
Required changes:
1. docs/reference/security-privacy.md:608-609. This line lists "a decomposed initial (a letter plus a combining accent)" as readable, but the merged matcher masks it (`Neral E\u0301. Vosk` gives `User <hex>`; tests/test_redaction_person_names.py:851-858). Fix: drop the decomposed-initial clause and keep the zero-width space and the fullwidth full stop, which are still readable.
2. docs/reference/security-privacy.md:610-614. This item says `John A. B. C. D. Smith` stays readable beside a `John A. B. C. D. Jones` sign-in path. The merged matcher withholds that string as `<redacted-text>`, or masks it when the full name is recorded (tests/test_redaction_person_names.py:812-817), and the item contradicts :592-594. Fix: remove the item, or reword it as withholding of the whole string.
Re-check of the prior review:
- Item 1 (rebase, re-read the masking passages, correct them, refresh the read-through): partly fixed. Rebase and new passages are done; :608-614 are not fixed.
- Suggestion (session-key run_id clause): fixed, :737-739.
- Defect class "documentation of an unmerged dependency": fixed (rebased onto main, which contains M04-T04).
Suggestions (non-blocking):
- security-privacy.md:647-648: the privacy review notes that `Orin Pasḱ` was masked before this change. Adding that would tell a reader that this limit is a regression.
