## RESULT REV-M03-T16
status: done
summary: verdict: approve reviewed: 5b99f74ed7e1
The verifier builds the M03-T12 lines with the same `pilot_lines` and the same bar test (band low above `win_threshold` from `bar.json`) as M03-T10. It also checks `round-gpu-hours` against the M03-T12 inventory and returns a `heldout-reads: 0` line (stricter than M03-T10). The shard join is strict, first-passing selection is recomputed, targets come from `kept_target` and `parse_output` is never run. Historical checks still protect what they protected before. Notes: .plan/work/REV-M03-T16/notes.md
changes: none in the kit or repository; review files in .plan/work/REV-M03-T16/ (notes.md, progress.md, dataround-tests.log, acceptance.log)
verification: unittest `test_check_dataround*.py` run directly, 115 tests, pass; `kit-check selftest` pass; `kit-check dataround --result` for M03-T09, M03-T10 and M03-T11 on the live kit (pilot-4 holds unlisted `scripts/` only), pass; `checks/SHA256SUMS` verifies, pass
risks: unlisted `scripts/` files are not hashed or scanned until they are listed, but scored M03-T12 needs a complete manifest; a `round-gpu-hours` over-claim is accepted, the same rule as M03-T10; M03-T07 cannot yet use a passing pilot 4 (follow-up 1)
questions_for_g: none
### Findings
Required changes: none.
1. Follow-up for the lead, outside M03-T16's scope: if pilot 4 passes, the M03-T07 check still reads pilot 3 (which failed) as the last attempt, because `verify_pilot` skips pilot-4. The train folder is also still pinned to the M02-T03 teacher. M03-T07 needs its own verifier extension before it runs.
2. Line parity: every line comes from `pilot_lines`, and `compare_lines` needs exactly one line per key with the exact value, so an edited, duplicated or missing line fails. The tests cover a wrong and a missing value for every line.
3. Join: rows must be headroom cases, each in exactly one shard, with samples 0 to 3, all four present and none twice. Each selection covers its own shard once, and the union equals the headroom list. The joined copies must equal the shard union as multisets. This matches the `round.py` and `collect.py` layout.
4. Selection: `pilot4_target` matches `generate.candidate_target` exactly. `kept_sample` must be an int or null (booleans are refused), and targets must equal `{"output": kept_target}`. A row where all four candidates fail holds sample 0's strict text, must fail the checks and counts as an unfiltered loss.
