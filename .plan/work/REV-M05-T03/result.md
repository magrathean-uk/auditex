## RESULT REV-M05-T03
status: done
summary:
verdict: changes-required
reviewed: c7dd5a073025684b797d94e58f26de780146cd73
Static review found silent name leakage, inaccurate unmatched-person counts and unmet prerequisites.
changes: none
verification: Not runnable: `.venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_profiles_d3.py tests/test_redaction_scan_budget.py tests/test_notify_redaction.py tests/test_redaction_export_schemas.py && make contract-smoke && .venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15 --require-masked`. First output: `zsh:1: no such file or directory: .venv/bin/python`. `git diff --check main...HEAD`: pass. Baseline metadata predicates: pass. D5-design approval predicate: fail, exit 1 without output. HEAD and clean worktree confirmed.
risks: Runtime behaviour and memory peak could not be independently verified; author's full-suite run was incomplete.
questions_for_g: none

### Findings

Criteria checklist:

- Not met - precondition: `.plan/milestones/M05-d5-name-masking.md:49`. M05-T02 is merged, but the frozen history contains no M02-M04 task merges; `.plan/DECISIONS.md:58` ends without the required D5-design approval entry.
- Not met - complete masking and unmatched reporting: `src/azure_tenant_audit/output_redaction.py:1192` and `:1255`; see required changes 1-2.
- Met by inspection - local profile remains unchanged and pseudonyms use the supplied run salt: `src/azure_tenant_audit/output_redaction.py:1747` and `:1382`.
- Met by inspection - bounded token window and directory-independent lookup: `src/azure_tenant_audit/output_redaction.py:1345`. Runtime budget proof is untestable here; tests are at `tests/test_redaction_scan_budget.py:328`.
- Met by inspection - required narrative, id, export, notification, guard and unmatched-case tests exist: `tests/test_redaction_person_names.py:63`, `:119`, `:182`, `:224`, `:295`, `:330`. The sole D3 test change matches design section 10: `tests/test_redaction_profiles_d3.py:307`. Test execution is untestable here.
- Met - harness and baseline are unchanged. Untestable - required masking and peak-ratio run: `.plan/milestones/M05-d5-name-masking.md:52`.
- DoD - design approval is not met (`.plan/milestones/M05-d5-name-masking.md:14`); committed baseline metadata is present (`benchmarks/html-peak-baseline.json:2`). Runtime claims at milestone lines 15-18 remain untestable here. Acceptance, documentation and both-provider approval at lines 19-21 remain milestone-close work.
- Scope - met. All changed paths are permitted: `src/auditex/reporting.py`, `src/azure_tenant_audit/output_redaction.py`, `tests/test_redaction_person_names.py`, `tests/test_redaction_profiles_d3.py`, `tests/test_redaction_scan_budget.py`. Out-of-scope paths: none.
- Security and maintainability - no added credentials, dependencies, executable-mode changes, injection sinks or unsafe deserialisation found. Tests generally assert observable behaviour. The privacy defects below block approval.

Required changes:

1. `src/azure_tenant_audit/output_redaction.py:1192` - `Kovalenko, Priya` becomes the accepted key `kovalenko priya` and sets `named=True`, but `:1356` rejects the comma-plus-space separator. Its exact directory spelling therefore remains readable in narrative text without an unmatched notice. Make indexing and matching agree so accepted recorded names are masked within the budget; explicitly report unsupported forms. Add a comma-form regression test.
2. `src/azure_tenant_audit/output_redaction.py:1255` - unmatched people are keyed by canonical display name. Two distinct users named `Bo` produce one unmatched person; a matched namesake can also remove another person's unmatched entry at `:1258`. Track coverage by stable person identity while retaining the canonical-name pseudonym scheme. Test distinct namesakes and repeated references to one person.
3. `.plan/milestones/M05-d5-name-masking.md:49` - required prerequisites are absent from the reviewed head. Integrate the M02-M04 predecessors, record G's actual design approval in the required decision entry, then rerun verification and review on the resulting head.

Optional suggestions: none.
