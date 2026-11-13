## RESULT CHK-M04-T04
status: done
summary: check: pass
checked: d719698b214f322d103e2a2f505725677756d597
Lint and the verify command both pass, and the Unicode-form fix (change 2) now holds. contract-smoke validates and all 43 digests match. Every new test fails on the 0adcc49 code except 4 negative-guard params (2 same-form Unicode, 2 incomplete-name-parts); I count the guards as not covered by the "every new test" rule, so overrule that if you read it strictly.
changes: none
verification: make lint PASS (exit 0); verify command PASS (exit 0, 396 tests passed, html_peak PASS); new tests on the 0adcc49 source in a scratch tree: all fix tests FAIL as required, 4 guard params PASS; make contract-smoke PASS (exit 0); compare-run-outputs digests PASS (43 of 43 match); git status --porcelain clean
risks: html_peak margin is under 1% in some runs: 717225984 in the verify run (limit 720352051), then 681787392 and 713818112 on reruns, against a 626393088 baseline, so the gate may flake; one test function (`test_incomplete_name_parts_do_not_invent_a_directory_identity`) passes on the old code by design; the .venv link in the worktree was left (git-ignored)
questions_for_g: none
### Findings
- Step 2, lint: `make lint` exit 0 (compileall, Ruff pin, "All checks passed!").
- Step 3, verify: PASS, exit 0, 396 tests, no failures. The earlier six NFC/NFD failures are gone. Benchmark prints `peak 717225984 limit 720352051 (ratio 1.15)`, so about 1.145x the baseline, `unmasked_name_hits` 0. Reruns peaked at 681787392 and 713818112, so the gate passes but the margin is thin.
- Step 4, change 1 (initials with admin sign-in and trailing word, exhausted candidates): `test_two_and_three_initials_with_admin_upn_and_trailing_word_mask_or_withhold` (8 params), `test_d5_exhausted_initial_candidates_are_withheld_without_extra_probes` (3 params) and the edited `test_d5_budget_holds_for_middle_initials_and_titles`, `test_d5_initial_fallback_keeps_probes_per_start_at_most_six` and `test_d5_initial_fallback_on_a_running_key_stays_at_six_probes` all fail on the old code.
- Step 4, change 2 (NFC/NFD): `test_composed_and_decomposed_names_and_initials_share_token_boundaries` fails on old code in 6 of 8 params. `test_unicode_name_matching_preserves_source_offsets_and_budgets` fails on old code in every param (96 of 96).
- Non-discriminating (change 2): 2 params of the composed/decomposed test, `[Néral Vosk-Néral Vosk]` and `[Néral É. Vosk-Néral Vosk]`, pass on the old code. They are same-form guards, as the author's comment says.
- Step 4, change 3 (whole mapping keys): `test_whole_mapping_keys_cover_joined_names_titles_and_initials` (6 params), `test_whole_mapping_key_with_competing_initial_names_is_withheld` and the edited `test_mapping_key_equal_to_a_name_is_masked_as_a_whole` all fail on the old code.
- Step 4, change 4 (parts-only directory records): `test_parts_only_directory_records_mask_parts_and_associated_narrative` (2 params) fails on the old code.
- Non-discriminating (change 4): `test_incomplete_name_parts_do_not_invent_a_directory_identity` (2 params) passes on the old code. It is a negative guard, not evidence of the fix.
- Step 4, change 5 (bounded token allocation): `test_d5_oversized_whole_key_allocation_is_bounded` and `test_d5_whole_key_token_scan_stops_at_the_seventh_token` both fail on the old code.
- Step 4, method: scratch tree from `git archive HEAD` with `src/azure_tenant_audit/output_redaction.py` replaced by the 0adcc49 version. I confirmed the import resolved to the scratch copy. The scratch tree is removed.
- Step 5, contract-smoke: exit 0, every run validated, and the projection demo ran with 102 rule rows and the bundle seal verified. `scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` reports "all 43 digests match". The fixture is unchanged since 0adcc49.
- Housekeeping: `git status --porcelain` is clean; no tracked path was changed. Scratch files and the git-ignored `outputs/` I created are removed.
