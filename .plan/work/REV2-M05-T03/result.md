## RESULT REV2-M05-T03
status: done
summary:
verdict: approve
reviewed: c7dd5a073025684b797d94e58f26de780146cd73
Shareable, customer-pack and explainer output now masks every directory person's name through a lookup table built once per context, with no regex built from names. The local profile returns before any of this runs. The 90k harness passes: peak ratio 1.024, 0 unmasked name hits (the baseline had 404,684).
No security issues, no new dependencies and no scope creep. The only D3 test change is the one design section 10 and DEC-003 name.
changes: none (review only; evidence written to .plan/work/REV2-M05-T03/evidence.md)
verification: verify pytest (5 files) pass; `PYTHONPATH=src make contract-smoke` pass; `html_peak.py --records 90000 --profile shareable --baseline ... --max-ratio 1.15 --require-masked` pass (exit 0); benchmarks/ unchanged; extra related suites (reporting, customer_pack_d3, writer_sinks_d3, notify, export stability, sarif/oscal, mcp_registry) pass
risks: DoD item 1 fails: `.plan/DECISIONS.md` has no G-approved "## DEC-nnn D5 design" entry and design.md still says "proposed"; G's answers are recorded only as DEC-003 and DEC-004 (orchestrator item, not this task's file). Ordinary words that equal a person's name are over-masked (design section 11, documented in M05-T04). The full `make test` was not run here; the merge gate covers it.
questions_for_g: Do DEC-003 and DEC-004 count as approval of the whole D5 design? If yes, record a "D5 design" entry with you as approver so DoD item 1 can pass.
### Findings
Criteria checklist (M05-T03):
- Shareable, customer-pack and explainer profiles mask everyone in the run's directory records, in free text and ids: met. `src/azure_tenant_audit/output_redaction.py:101` (`_is_directory_person`), `:196` (index built in `context_for_run`), `:1614` (pass applied to every string), `:1682` (structured name fields).
- The local profile is unchanged: met. `src/auditex/reporting.py:3925` returns before redaction; `redact_output` keeps its early return for local; `tests/test_redaction_person_names.py:72`.
- Masking is deterministic per run salt: met. Uses `pseudonym(salt, canonical)` at `output_redaction.py:522`; `tests/test_redaction_person_names.py:352`, `:361`.
- Per-record matching stays within the design budget: met. At most 6 probes per token and a window of at most 6 tokens; the probe count is the same with 10 and 100,000 people (`tests/test_redaction_scan_budget.py:328`, `:338`, `:356`, `:365`, `:373`).
- Person-name tests cover narrative text, ids, exports, notify payloads, the false-positive guard and the unmatched case: met. `tests/test_redaction_person_names.py:63`, `:119`, `:295`, `:310`, `:330`, `:182`, `:224`.
- Existing D3 tests are unchanged except the one the design names: met. Only `test_d3_group_and_role_names_mask_a_person_name_inside_lists` changed (`tests/test_redaction_profiles_d3.py:307`), per DEC-003 and design section 10.
- The harness, unchanged, passes with `--require-masked`: met. No diff under `benchmarks/`; exit 0.
- No bundle field or `CONTRACT_VERSION` change: met. Contract smoke passes.
- DoD items this task closes (harness check, masking test suite): met. DoD item 1 (D5 design approval): not met, outside this task's files (see risks).
Required changes: none.
Suggestions (non-blocking):
1. `output_redaction.py:584`: `found = _Found()` only rebinds a local name and frees nothing that is still referenced. The comment claims more than the line does; drop it or say what it actually does.
2. `output_redaction.py:422`: `_merge_indexes` keeps a person in the unmatched list from one run even when another run's index matches them. In a two-run diff report the note can overcount. Pop the canonical names that are matched in any index.
3. `Redactor.text` no longer reads `names=False` (`:1592` docstring says so). Remove the dead parameter at its call sites in a follow-up.
