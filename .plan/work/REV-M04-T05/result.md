## RESULT REV-M04-T05
status: done
summary:
verdict: changes-required
reviewed: 45bb34f4e82ad6753a8a67078ada3d832ebd8951
The precondition "M04-T04 merged" is not met: 0adcc49 is in neither main nor HEAD, and the task table shows M04-T04 as todo. The masking-boundary passages in security-privacy.md describe code that exists only on task/M04-T04-name-masking (`_D5_FIELD_NAMES`, the title list), so merging now would claim masking that main does not do.
The key-scheme, key-source, MCP, limits, CHANGELOG, manual and adapter text matches HEAD code. Verify passes. No scope creep.
changes: .plan/work/REV-M04-T05/evidence.md, .plan/work/REV-M04-T05/progress.md
verification: M04-T05 verify greps (result.md read from the main checkout): pass, exit 0
risks: if T04 changes in its Tier A reviews, the masking-limit list (security-privacy.md:579-621) drifts again; the author reported a same-vendor read-through only
questions_for_g: none
### Findings
Criteria:
- Precondition M04-T04 merged: not met (evidence.md).
- Keyed scheme (key at collection, pseudonym.key and modes, HMAC, label): met, docs/reference/security-privacy.md:666-679 and :101.
- Key sources (run, memory per context, session key for keyless, export-derived): met, security-privacy.md:681-714.
- Masking boundary (middle initials, titles, mapping keys): written (security-privacy.md:566, :579-621) but not checkable against merged code; not met until T04 merges.
- Oracle boundary of design section 2: met, security-privacy.md:716-724.
- Confirm-a-guess limit and salt wording dropped from the design section 13 passages: met. Remaining "salt" uses are historical (:670-673, :748).
- No read-only tool writes a run, and prepare-key is named: met, security-privacy.md:117-122, :352-354.
- DEC-004 amendments: every keyless kind covered and no MCP approval claim (:117-122, :693-701); nolock and flush limits named (:726-741); temporary-key stability plus command (:742-743). Met.
- CHANGELOG entry under [Unreleased]: met, CHANGELOG.md:8-18. Manual line: met, docs/guides/product-manual.md:282. Adapter key lines match scubagear_export.py:314-345: met, docs/development/scubagear-export-adapter.md:94-98.
- `read-through: complete` in result.md: present, but read against the unmerged T04 branch (`masking-boundary-source: task/M04-T04-name-masking@0adcc49`).
- DoD: the terra read-through item stays open until the precondition holds.
Security: no secrets, no code, no dependencies.
Scope: all four paths are within the files line.
Required changes:
1. docs/reference/security-privacy.md:566, :579-621. The text documents matcher behaviour that is not on main. Fix: once M04-T04 merges, rebase this branch onto main, re-read these passages against the merged output_redaction.py (and the tests in tests/test_redaction_person_names.py), correct anything T04's reviews changed, and refresh `read-through: complete` in result.md against the merged head.
Suggestions (non-blocking):
- security-privacy.md:698: the session key is one per run per process only when the manifest's run_id is usable. Otherwise it lasts for one guard context (output_redaction.py:341-357). Say so in a clause.
### Defect classes
- documentation of an unmerged dependency (precondition not met, text read against a branch rather than the base)
