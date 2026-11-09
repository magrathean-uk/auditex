## RESULT REV-M05-T03-privacy
status: done
summary:
verdict: changes-required
reviewed: cce05774d816d369e8648a5beb71f82933ee1b98
A spelling the index accepts stays readable and uncounted when the same person is matched in another record (reproduced). The note misstates why "separator" people are unmatched.
The full verify passes: 154 tests, contract-smoke, html_peak ratio 1.115, unmasked_name_hits 0. No security, dependency or scope problems.
changes: /Users/bolyki/dev/source/auditex/.plan/work/REV-M05-T03-privacy/evidence.md (review evidence only; no repository files touched)
verification: PYTHONPATH=src pytest test_redaction_person_names, _profiles_d3, _scan_budget, test_notify_redaction, test_redaction_export_schemas pass (154); make contract-smoke pass; html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked pass (peak 678019072, limit 699042202); log in evidence.md
risks: Middle-initial and title spellings ("John A. Smith", "Dr. Jane Doe") match the design's separator rule, so they are counted unmatched and stay readable in free text; real tenants may have many. Single-token and structural mapping keys (`Priya_Kovalenko`, `PriyaKovalenko`) stay as written, as the design says. The final markup pass leaves names inside HTML tags as written; main's D3 pass masked privileged names there, so structure-first redaction is the only defence.
questions_for_g: none
### Findings
Criteria (M05-T03):
- Precondition, G approved design.md: not met. No "D5 design" DEC entry exists (STATE.md:16). The orchestrator owns this, so it is not an author change.
- Precondition, M05-T02 merged and M02-M04 order: met through DEC-007.
- Shareable, customer_pack and explainer mask everyone in the directory records, in free text and ids: met, except required change 1. Code at output_redaction.py:1148-1478 and :1657, tests at tests/test_redaction_person_names.py:63, 119, 352, 367, 387.
- Local profile unchanged: met (tests/test_redaction_person_names.py:72).
- Masking is deterministic per run salt: met (output_redaction.py:1462, test :409).
- Matching cost stays within the budget: met (tests/test_redaction_scan_budget.py:328-373).
- Person-name tests cover narrative text, ids, exports, notify payloads, the guard and the unmatched case: met (test :182, :233, :241, :264). The cross-record case is missing, see change 1.
- D3 tests changed only where design.md names a change: met. tests/test_redaction_profiles_d3.py:307 is the change DEC-003 approved.
- Harness passes unchanged with --require-masked; benchmarks/ not edited: met.
- The verify command passes: met.
DoD items this task feeds: the peak item and the five-suite item pass. The two-provider privacy item stays open until both approve.
Scope: all 5 paths fit the files line. src/auditex/reporting.py is the `preview_report` caller named in design.md section 8.
Security: no secrets, no injection, no file-mode changes. The only new imports are the standard-library unicodedata and deque.
Required changes:
1. output_redaction.py:1309, :1334 and :1364. An identity matched in any record removes that person's "separator" entry from another record. A spelling the index accepts then stays readable with no notice: user u1 "Priya Kovalenko" plus a reference to u1 as "Kovalenko (Priya)" leaves "Updated by Kovalenko (Priya)" readable, and unmatched_names is empty. This breaks design section 6 ("Reported, never silent") and repair item 1. Fix: do not let `matched` drop entries whose reason is `separator`, in `_build_index` and in `_merge_indexes`, or mark coverage per spelling rather than per person. Add the two-record test.
2. output_redaction.py:1380. The note says every counted person's name is "too short or too common". That is false for the `separator` reason added this round, so the customer report gives a wrong reason. Fix: use wording that covers every D5_REASONS entry, such as "names that cannot be matched safely in free text". Update the test assertion at tests/test_redaction_person_names.py:290.
Suggestions (non-blocking):
- output_redaction.py:1148: let `_joins` also accept one `_D5_SEPARATORS` character followed by whitespace (". "). "John A. Smith" and "Dr. Jane Doe" would then be masked instead of counted. Each step is still one probe, so the matching budget does not change. This changes the design's separator rule, so sol needs to agree.
- For M05-T04: document the `separator` reason, and that structural mapping keys and HTML tag contents keep names.
