## RESULT REV-M05-T03-privacy
status: done
summary:
verdict: approve
reviewed: 215148d2951bd775b1b516a22ec47306e49d280c
Independent re-review of the 4-commit diff from 18350b0. Masking held in about 25 in-memory probes (case, spacing, NBSP, full-width, comma and swap forms, apostrophes, accents, paths, ids, mapping keys) in all three non-local profiles. The local profile is unchanged.
Full verify passes: 161 tests, contract-smoke, html_peak peak 658309120 against limit 699042202 (ratio about 1.083), unmasked_name_hits 0. No security, dependency or scope problems.
changes: .plan/work/REV-M05-T03-privacy/evidence.md (appended a job-3 section in the main checkout); .venv link in the read-only worktree (git-ignored); no repository files touched
verification: PYTHONPATH=src pytest of the five suites pass (161); make contract-smoke pass; html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked pass (exit 0); git diff --check pass; log at $TMPDIR/rev-m05-t03-privacy-verify/log.txt, summary in evidence.md
risks: These spellings stay readable and are not counted in the note (design limits): URL-encoded names ("Priya%20Kovalenko"), structural mapping keys ("PriyaKovalenko"), and in the final markup pass only, names split by a tag or entity. That pass runs over already redacted sections. Middle-initial and title spellings are counted as unmatched (BACKLOG).
questions_for_g: none
### Findings
Criteria (M05-T03):
- Precondition, G approved design.md: met (DEC-010 "D5 design approved as implemented", approver G, names 215148d).
- Shareable, customer_pack and explainer mask everyone in the directory records, in free text and ids: met. Code: src/azure_tenant_audit/output_redaction.py:1234, :1402 and the mapping pass at :1767-:1800. Tests: tests/test_redaction_person_names.py:63, :119, :123.
- Local profile unchanged: met (output_redaction.py:1846, test :72).
- Deterministic per run salt: met (test :501; two-run first-salt test :510).
- Matching cost within the design budget: met (tests/test_redaction_scan_budget.py: probes do not depend on directory size, at most 6 probes per token, window at most 6, no regex built from names, index built once per context).
- Person-name tests cover narrative, ids, exports, notify, the false-positive guard and the unmatched case: met (tests :223, :119, :444, :480, :182, :201, :373).
- D3 tests change only where the design names it: met. tests/test_redaction_profiles_d3.py:307 is the design section 7 / DEC-003 change.
- Harness unchanged and passing with --require-masked; benchmarks/ not edited: met (no change under benchmarks/).
- Verify command: pass.
DoD items this task feeds: the peak item and the five-suite item pass here. The design-approval item passes through DEC-010. The two-provider item needs REV-M05-T03 at this same sha; its result.md approves 215148d.
Security: no secrets, workstation paths, injection, deserialisation or file-mode changes. The only new imports are stdlib (unicodedata, collections.deque, dataclasses.replace). No dependency change, and all four commits carry a signature block. The note is html.escape'd before `</body>` (src/auditex/reporting.py:3877) and never holds a name.
Scope: all 5 paths match the files line. src/auditex/reporting.py is the `preview_report` caller named in design section 8. No bundle field, schema or CONTRACT_VERSION change.
Required changes: none.
Suggestions (non-blocking):
1. output_redaction.py:1388: "1 directory people" reads badly. Use "person" when the count is 1.
2. tests/test_redaction_person_names.py:281 and similar: rename the `codex_item_*` and `privacy_item_*` tests for the behaviour they check.
3. M05-T04 should document the 16-key cap, the comma joiner, the `separator` and `limit` reasons, and the uncounted URL-encoded, structural-key and tag-split cases above.
