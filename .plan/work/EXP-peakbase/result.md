## RESULT EXP-peakbase
status: done
summary: Answer in Findings. Nothing was changed and no progress file was written.
changes: none
verification: rg, sed and git log reads, plus one arithmetic check; no tests run
risks: Recording at 0 hits makes `--require-masked` pass before any D5 change. Inferred: current main already masks names in the shareable HTML, so M04's masking criterion is vacuous.
questions_for_g: none
### Findings
Direct answer: relax the test so it requires `person_names > 0` (the workload carries names) instead of `unmasked_name_hits > 0`. Then a baseline recorded on current main passes.

(1) What the test asserts and protects
- The test asserts `records == 90000`, `profile == "shareable"` and `unmasked_name_hits > 0` for the committed baseline (`tests/test_html_peak_harness.py:107-111`).
- It guards the baseline's provenance. The baseline was recorded before masking, when the workload's names showed up unmasked in the report. That is what gives `--require-masked` meaning.
- The committed baseline has `unmasked_name_hits` 404684, `person_names` 45000, `peak_rss_bytes` 607862784 and `commit` 457149268bac, with Python 3.14.7 (`benchmarks/html-peak-baseline.json`).
- The test and the baseline arrived together in one commit, 74177b8 "add the HTML peak harness and record the pre-D5 baseline" (M05-T02), and neither has changed since. `4571492` is the commit field recorded inside the baseline, not a commit that touched it.

(2) How the harness uses the baseline
- `--baseline` loads the file (`benchmarks/html_peak.py:334`). It exits 2 if `records`, `profile` or `workload_sha256` differ (`:344-348`). It only warns on a Python version difference (`:349`).
- The limit is `baseline["peak_rss_bytes"] * max_ratio`, and the run exits 1 if the peak exceeds it (`:379-383`). `--max-ratio` defaults to 1.15 (`:27`) and requires `--baseline` (`:331-332`).
- `--require-masked` exits 3 if the current run's `hits > 0` (`:376-378`). It looks at the live run's own hits, not the baseline's.
- Other checks that prove the workload carries names, even with a zero-hit baseline:
  - `test_require_masked_fails_on_local_report` runs the local profile at 400 records and requires exit 3 with hits above 0 (`tests/test_html_peak_harness.py:100-104`). This is the strongest proof.
  - `test_json_fields_and_types` requires `person_names == 200` for 400 records (`:43`).
  - The baseline's `person_names` of 45000 is validated only as an integer of at least 0 (`html_peak.py:288`). Nothing asserts it is positive, so the proposed change adds that.

(3) Module ownership (`.plan/ARCHITECTURE.md`)
- `benchmarks/**` belongs to misc-scripts (row 24, owner terra).
- `tests/test_html_peak_harness.py` matches no module's test glob. The import convention (row 26) would assign it to the module whose code it imports first; it imports no project module and only runs `benchmarks/html_peak.py`.
- Inferred: it therefore falls to misc-scripts. The same module then owns both the test and the baseline, so there is no cross-module conflict.

(4) Smallest change, in milestone format
- [ ] `test_committed_baseline_carries_names` asserts `baseline["person_names"] > 0` in place of `unmasked_name_hits > 0`, keeps the `records == 90000` and `profile == "shareable"` asserts, and passes against a baseline recorded on current main.
- verify: `.venv/bin/python -m pytest tests/test_html_peak_harness.py`
- files: `tests/test_html_peak_harness.py`, `benchmarks/html-peak-baseline.json`
- M04-T02 currently lists only the baseline in `files:` and says "No other change" (`.plan/milestones/M04-d5-keyed-pseudonyms.md:44,46`). Both lines need the test file added.

(5) Peak limit in bytes at ratio 1.15
- Keep the committed baseline (607862784): limit 699042201.6.
- Re-record at 650166272: limit 747691212.8, about 48.6 MB looser.
- Inferred: the 650166272 measurement is about 7 percent above the committed baseline's 607862784, so re-recording loosens the guard for the later M04 render change.

Unknowns
- I did not run the harness or the tests.
- I did not confirm why current main shows 0 hits. A single run of `benchmarks/html_peak.py --records 90000 --profile shareable` on main, compared against the changelog, would settle it.
