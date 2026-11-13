## RESULT CHK-M04-T04
status: done
summary: check: pass
checked: d7b44247c103ba17d204be71b778184080691dd3
Lint, the verify command and the contract smoke all pass, and all 20 new test cases of this round fail on the d719698 matcher. The HTML peak ratio is tight at about 1.146 against the 1.15 limit, passing on the first run.
changes: none
verification: make lint pass (exit 0); verify command pass (exit 0, four test files then html_peak); new-test negative check pass (20 of 20 fail on old code); make contract-smoke pass (exit 0); compare-run-outputs.py pass (exit 0)
risks: HTML peak 717750272 against a limit of 720352051, ratio about 1.146, so little headroom; a heavy-slot neighbour could tip it, so rerun the benchmark alone if it flakes.
questions_for_g: none

### Findings
- step 2 lint: `make lint` exit 0 (compileall, then the pinned Ruff: "All checks passed!").
- step 3 verify: the four pytest files passed, no failing tests, and the benchmark exited 0 with `--require-masked` satisfied (`unmasked_name_hits` 0). The HTML peak is 717750272 bytes against a limit of 720352051 (ratio about 1.146, max 1.15). It passed on the first run, so no repeats were needed. The run went through the heavy slot (slot 1 of 2 acquired after 10 s).
- step 4 new tests: the round adds three test functions (20 parametrised cases). I ran them in a scratch tree from `git archive HEAD` with only `src/azure_tenant_audit/output_redaction.py` set to the d719698 version (import path confirmed).
  - `test_shorter_name_does_not_expose_an_unresolved_initial_extension`: 4 of 4 fail on old code.
  - `test_combining_marks_across_scripts_preserve_equivalent_names_and_source_offsets`: 12 of 12 fail on old code.
  - `test_d5_shorter_hit_does_not_bypass_initial_exhaustion`: 4 of 4 fail on old code. Sample failure: the old code returned `User db6bbbedfff09e3b A. B. C. D. E. Vosk wrote` where the placeholder was expected.
  - None of the 20 passes on the old code, and none is a negative guard.
- step 5 contract smoke: `make contract-smoke` exit 0, with the projection demo bundle seal verified. `compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract` exit 0 with "all 43 digests match". (My first attempt failed because an earlier `&&` skipped the smoke; I reran it properly.)
- cleanup: I removed the scratch tree, logs, `outputs/`, the pytest and ruff caches, and the `.venv` link. `git status --porcelain --ignored` is empty.
