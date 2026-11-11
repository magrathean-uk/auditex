## RESULT M05-T02
status: done
summary: Review item 1 fixed. `_load_baseline` now validates all eight fields (type and range) and exits 2 with no JSON on a malformed baseline. Ten parametrised malformed-baseline tests cover this. All M05-T02 criteria are met; the committed baseline is unchanged.
changes: benchmarks/html_peak.py, tests/test_html_peak_harness.py
verification: `.venv/bin/python -m pytest tests/test_html_peak_harness.py` pass (16 tests); `.venv/bin/python benchmarks/html_peak.py --records 90000 --profile shareable --baseline benchmarks/html-peak-baseline.json --max-ratio 1.15` pass (exit 0, peak 610828288 against limit 699042202); `git status --porcelain` empty
risks: Peak RSS varies by machine, so the 1.15 ratio check may be noisy on a different host; the vocabulary-disjointness regression test from the review's non-blocking suggestion is not added.
questions_for_g: none
