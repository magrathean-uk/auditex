## RESULT REV-M05-T03
status: done
summary:
verdict: approve
reviewed: 9a82562125c5cacfe018c3f26ce0fe63b399cd6c
This re-check covers 11d7b5e..HEAD. All 4 open classes handed on by M05-T01 and REV-M05-T01 are now named-limit rows citing v2 DEC-011, and the author's probes support each one. The intro now claims closure only for shadowing by a module binding and for the binding forms; planted tests cover both. The only changed path is docs/reference/security-privacy.md, inside the scanner limits section.
changes: none to the repository (review files only: .plan/work/REV-M05-T03/evidence.md, progress.md)
verification: `grep -qx 'read-through: complete' .plan/work/M05-T03/result.md` pass; `git diff --check main...HEAD` pass; scanner pytest not run (docs-only change; the author reports 482 passing and the merge gate covers it)
risks: The added rows rest on the author's probes, not planted tests, which is expected for named limits. The list is only as complete as the scanners' notes and reviews, and the intro now says so.
questions_for_g: none
### Findings
Criteria checklist (current head):
- Met: closed limits are dropped. The intro names what is closed (docs/reference/security-privacy.md:221-227), and planted tests cover it (tests/test_read_boundaries.py:2614, :2640; the parameter shadow is at :2604 and :2632).
- Met: every remaining row is marked "named limit (v2 DEC-011)" (docs/reference/security-privacy.md:233-249), and v2 DEC-011 is cited in the intro at :219.
- Met: the list now holds the open limits handed on by M05-T01 and its review (rows at :239-242). Author probes 1a-1c, 2a-2c, 3a-3b, 5 and 5b show the scanner proving each case literal, which is the miss.
- Met: `read-through: complete` is under `### Findings` in .plan/work/M05-T03/result.md, and verify passes.
- Met: scope. The only changed path is docs/reference/security-privacy.md, with hunks only in the scanner limits section.
- DoD (limits-tables review item): met.
- Security: no code, secrets, dependencies or mode changes. Maintainability: no issues.
Required changes: none.
Suggestions (non-blocking):
- docs/reference/security-privacy.md:241 packs the zip/enumerate limit and the "no gap known" note on string methods into one long cell. Splitting the note into the intro would read more easily.
Prior review items:
- 1 (missing named-limit rows at :226-233): fixed. Rows added at docs/reference/security-privacy.md:239-242. Leaving out the `type` alias, which the review marked optional, is justified in .plan/work/M05-T03/notes.md, and probes 4 and 4b fail closed.
- 2 (intro overclaimed closure and completeness): fixed at docs/reference/security-privacy.md:218-227.
- Defect class "named limits handed on by earlier tasks not carried into the table": fixed (:239-242; the author's notes table traces each source).
- Defect class "prose claiming the list is complete or a limit closed, contradicted by the scanner's notes": fixed (:220-227 now reads "found so far; a static scan can have others").
