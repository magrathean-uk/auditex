## RESULT REV-M04-T04
status: done
summary:
verdict: changes-required
reviewed: d719698b214f322d103e2a2f505725677756d597
The original examples are addressed, but two nearby variants still expose names by code inspection.
changes: none; read-only review; progress file skipped because writes are unavailable
verification: git status, rev-parse, diff and diff --check PASS; no tests executed, as instructed. .plan/work/CHK-M04-T04/result.md records exact-head lint, 396 tests, HTML peak and 43/43 contract digests PASS.
risks: two readable-name variants remain; HTML peak margin is thin; other-provider exact-head review remains outstanding
questions_for_g: none
### Findings

Required change 1: not fixed - src/azure_tenant_audit/output_redaction.py:1698; original two/three-initial admin-UPN cases, dotted/undotted and repeated, are masked or withheld; a shorter confirmed name defeats withholding at the window limit (B1).
Required change 2: not fixed - src/azure_tenant_audit/output_redaction.py:1253; original NFC/NFD acute-accent names and initials are masked with source offsets preserved; combining marks outside the listed blocks still split equivalent spellings (B2).
Required change 3: fixed - src/azure_tenant_audit/output_redaction.py:1408 and :1751; four-to-six-token joined recorded names are indexed; supported whole-key title/initial variants are withheld, including competing identities; suffix/product protections remain.
Required change 4: fixed - src/azure_tenant_audit/output_redaction.py:496; flat and nested given-plus-family records establish a canonical identity; their structured parts are withheld and associated narrative is masked.
Required change 5: fixed - src/azure_tenant_audit/output_redaction.py:1731; oversized keys are rejected before token allocation; incremental scanning stops at the seventh token.
Defect class 1, probe-budget exhaustion: not fixed - src/azure_tenant_audit/output_redaction.py:1698; B1 leaves a surname readable.
Defect class 2, Unicode token boundaries: not fixed - src/azure_tenant_audit/output_redaction.py:1253; B2 leaves an equivalent name readable.
Defect class 3, whole-key variants: fixed - src/azure_tenant_audit/output_redaction.py:1751; the reviewed supported variants are masked or withheld.
Defect class 4, parts-only discovery: fixed - src/azure_tenant_audit/output_redaction.py:496; both reviewed record shapes reach structured and narrative masking.
Defect class 5, unbounded whole-key allocation: fixed - src/azure_tenant_audit/output_redaction.py:1737; retained tokens and allocation are bounded.
B1 BLOCKING - src/azure_tenant_audit/output_redaction.py:1698: with directory names “Neral” and “Neral Vosk”, text “Neral A B C D E Vosk” sets best to the single-name hit, reaches width six, then bypasses withholding because best exists. Only “Neral” is replaced; initials and “Vosk” survive. Withhold unresolved initial-bearing extensions even when an earlier, shorter hit exists; add this regression without increasing either budget.
B2 BLOCKING - src/azure_tenant_audit/output_redaction.py:1253: recorded "\u0958neral Vosk" folds to "\u0915\u093cneral vosk", but the equivalent written "\u0915\u093cneral Vosk" splits at U+093C, which the token pattern excludes. No starting phrase matches and no unmatched reason is recorded. Include all relevant combining marks in source-spanned tokens and add this canonical-equivalence regression.
Criteria: masking remains unmet through B1/B2; probe/window limits remain six by inspection; keyed replacement remains at src/azure_tenant_audit/output_redaction.py:1766; changed paths and source scope match the brief; supplied execution evidence passes the required checks.
Tests in tests/test_redaction_person_names.py, every new or edited function:
:681 test_mapping_key_equal_to_a_name_is_masked_as_a_whole - asserts requested withholding; retains readable surname and suffix-key expectations under the existing protection boundary.
:814 test_two_and_three_initials_with_admin_upn_and_trailing_word_mask_or_withhold - asserts the original dotted/undotted and repeated-list repair, including absence of both name parts; misses B1.
:827 test_composed_and_decomposed_names_and_initials_share_token_boundaries - asserts the requested acute-accent equivalence in prose/markup; two parameters are unchanged guards; misses B2.
:838 test_unicode_name_matching_preserves_source_offsets_and_budgets - asserts offsets, repeated hits, separators, initials, idempotence and unchanged six-probe/window bounds; covers 80 parameters.
:867 test_whole_mapping_keys_cover_joined_names_titles_and_initials - asserts requested masking/withholding and idempotence; deliberately pins readable name-plus-mailbox suffix keys.
:875 test_whole_mapping_key_with_competing_initial_names_is_withheld - asserts the requested ambiguity-safe withholding.
:884 test_parts_only_directory_records_mask_parts_and_associated_narrative - asserts both structured shapes, narrative masking and absence of name parts.
:898 test_incomplete_name_parts_do_not_invent_a_directory_identity - valid negative guard; does not demonstrate the parts-only fix or assert output masking.
Tests in tests/test_redaction_scan_budget.py, every new or edited function:
:365 test_d5_budget_holds_for_middle_initials_and_titles - tightens readable exhaustion to withholding; retains probe/window bounds.
:387 test_d5_initial_fallback_keeps_probes_per_start_at_most_six - tightens unsuccessful-match expectations to withholding; retains per-start/window bounds.
:411 test_d5_initial_fallback_on_a_running_key_stays_at_six_probes - asserts withholding and longer-name precedence; tightens expected exhaustion probes from eleven to six; bounds remain.
:484 test_d5_oversized_whole_key_allocation_is_bounded - asserts allocation below 64 KiB and zero probes; deliberately pins the oversized repeated-name key unchanged.
:499 test_d5_whole_key_token_scan_stops_at_the_seventh_token - asserts exactly seven visited tokens and zero probes, as requested.
:518 test_d5_exhausted_initial_candidates_are_withheld_without_extra_probes - asserts withholding plus per-start, total-probe and window bounds for the original exhaustion cases; misses B1.
Non-blocking: no budget assertion was weakened. The supplied evidence says 96 offset-test parameters, whereas this head defines 80; correct that count. The passing HTML peak has little headroom.
