## RESULT M04-T02
status: done
summary: Re-recorded benchmarks/html-peak-baseline.json on current main with the shareable profile at 90000 records. Peak is 626393088 bytes, `unmasked_name_hits` is 0 and `person_names` is 45000. The `workload_sha256` is unchanged. `test_committed_baseline_carries_names` now asserts `person_names > 0`. Its `records == 90000` and `profile == "shareable"` asserts are kept. The contract-smoke run passed and all 43 digests match without a refresh. The earlier two commits cancel out.
changes: benchmarks/html-peak-baseline.json, tests/test_html_peak_harness.py
verification: `.venv/bin/python -m pytest tests/test_html_peak_harness.py tests/test_compare_run_outputs.py` pass. `make contract-smoke` pass. `scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` pass ("all 43 digests match"). `make lint` pass (compileall, Ruff). Run on the committed head. Negative case: none run for the changed assertion, since no new check was added. Its existing negative coverage is `test_require_masked_fails_on_local_report`, which passed.
risks: The new peak (626393088) is about 3 percent above the old 607862784. The 1.15 limit is now 720352051, so the M04 guard is slightly looser.
questions_for_g: none
