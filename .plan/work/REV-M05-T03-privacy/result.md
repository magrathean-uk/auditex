## RESULT REV-M05-T03-privacy
status: done
summary:
verdict: approve
reviewed: 215148d2951bd775b1b516a22ec47306e49d280c
Both round-1 privacy items are fixed and re-checked by reproduction: the separator spelling is now reported, and the note wording is true for every reason. The full verify passes: 161 tests, contract-smoke, html_peak ratio about 1.03, unmasked_name_hits 0.
There are no security, dependency or scope problems. The remaining gaps are limits the design names, listed below for M05-T04.
changes: .plan/work/REV-M05-T03-privacy/evidence.md (main checkout; no repository files touched)
verification: PYTHONPATH=src pytest of the five suites pass (161); make contract-smoke pass; html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked pass (peak 625704960, limit 699042202, hits 0); log in evidence.md
risks: The DoD predicate looks for a DEC entry titled "D5 design" with approver G. None exists; only DEC-003 and DEC-004 (G's answers to design Q1 and Q2) do, so the orchestrator must record it. Several things are left as written: URL-encoded or "+"/"/" joined names, a family name on its own, initials, and structural mapping keys (`priya_kovalenko`, `PriyaKovalenko`). That last one is silent: it is not counted in the unmatched note. The code departs from the design text in four places, all from repair rounds: a key cap of 16 instead of 8, a comma joiner, and the `separator` and `limit` reasons. The probe budget is unchanged.
questions_for_g: none
### Findings
Criteria (M05-T03):
- Precondition, G approved design.md: met in substance (DEC-003, DEC-004). The formal "D5 design" entry is missing; that is an orchestrator item, not an author change.
- Shareable, customer_pack and explainer mask everyone in the directory records, in free text and ids: met. See output_redaction.py:1021, :1402, :1674, :1781 and tests/test_redaction_person_names.py:63, :119.
- Local profile unchanged: met (output_redaction.py:1846, test :72).
- Deterministic per run salt: met (test :501).
- Matching cost within the design budget: met (tests/test_redaction_scan_budget.py:328-385; probes at most 6 per token, window at most 6, and the probe count does not depend on how many people there are).
- Tests cover narrative text, ids, exports, notify payloads, the guard and the unmatched case: met (tests :63, :119, :444, :479, :182, :242, :373).
- D3 tests change only where the design names it: met. tests/test_redaction_profiles_d3.py:307 is the DEC-003 change.
- Harness unchanged and passing with --require-masked; benchmarks/ not edited: met.
- Verify command: pass.
DoD items this task feeds: the peak item and the five-suite item pass. The two-provider item needs REV-M05-T03 at this same sha.
Security: no secrets or workstation paths, no injection, no file-mode changes. The only new imports are the standard-library unicodedata and deque. All four commits are signed.
Scope: all 5 paths match the files line. src/auditex/reporting.py:3877 is the `preview_report` caller named in design section 8.
Required changes: none.
Suggestions (non-blocking):
1. output_redaction.py:1674: let a structural mapping key through to masking when the whole key is an index key (`priya_kovalenko`), or count it in the note. Otherwise M05-T04 must document it as a limit.
2. tests/test_redaction_person_names.py:242, :354: the test names refer to review-round items. Behaviour-based names would read better later.
3. M05-T04 should document the key cap of 16, the comma joiner, the `separator` and `limit` reasons, and that URL-encoded names and names inside HTML tags are left as written.
