## RESULT M07-T18
status: done
summary: compare.py in dt-r7s now reads Auditex 1.5.0's assessment: schema 2026-11-05 plus class value_rule and reason rule_not_implemented (both also written by the product), still malformed in a 2026-10-29 file.
2026-10-29 is still accepted; any other schema is refused with the same one-line exit 2. Scoring is unchanged: value_rule rows go through the existing rule-row path.
Change from the brief: an unknown class is refused per row as before (listed as malformed, rc 0, never a disagreement), not exit 2. The kit's validation rule and the kept test ModelBranch.test_rule_precheck_present_exactly_for_rule_rows require that. The proposed gate line checks for malformed rows instead.
Fixture: the product's offline demo output, with only `projection` removed. 9 new cases; ROUND-7S.md part 2a written.
changes: kit/20261111-kit-7s/dt-r7s/compare.py, kit/20261111-kit-7s/dt-r7s/tools/test_compare.py, kit/20261111-kit-7s/dt-r7s/tools/compare-fixtures/auditex-1.5.0-demo-model_assessment.json (new), kit/20261111-kit-7s/ROUND-7S.md; driver logs kit/20261111-kit-7s/quick-2, quick-2.out; evidence .plan/work/M07-T18/evidence-2a.md, part2a-compare.diff, part2a-hashes-before.txt, part2a-hashes-after.txt; repository unchanged
verification: python3 -I -B tools/test_compare.py on dt-r7s pass (341/341); new class on dt-r7s pass 9/9, on part 1's compare.py 8 code cases fail as intended; compare.py on the released demo output pass (rc 0, 0 malformed); check-suite-7l.sh --quick dt-r7s quick-2 via host slot pass (OVERALL PASS, 7 steps; two earlier tries deferred, nothing run); hygiene of 289 added lines pass; protected tree hashes before and after identical pass
risks: an unknown rule class does not trigger exit 2 or exit 1, so E11 must check that no "malformed rows (not scored)" section appears | dt-r7s-cand still carries part 1's compare.py: part 2a reaches the tenant chat only with the next candidate or frozen copy | rule_not_implemented and the not-applicable form are proven from the product's writer code, not from product output (the demo has neither)
questions_for_g: none
### Findings
compare-schemas: 2026-10-29, 2026-11-05 (".N" minors of each)
compare-classes: closed_gate, absent_section, absent_field, empty_required_list, value_rule (value_rule only in 2026-11-05 files)
new-cases: 9 pass
released-output-scored: rc 0 malformed 0
cand-unchanged: yes
phase-e-gate-line: Gate passes when grep -n '^SUPPORTED_SCHEMA\|^PRECHECK_CLASSES' "$KIT_ROOT/compare.py" shows "2026-11-05" and "value_rule" (kit 7s part 2a or later): run E11 with the kit's own compare.py, no fallback; E11 passes only on exit 0 with no "malformed rows (not scored)" section and no disagreement.
