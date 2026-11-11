## RESULT M02-T02b
status: done
summary: `compare-run-outputs.py` now uses the factory's `build_argument_parser` instead of calling `argparse.ArgumentParser` directly, and the unused `argparse` import is gone. `--write`, `--digests` and the RUNDIR argument are unchanged, and the digests fixture is untouched. I also registered the script in `SCRIPT_BUILDERS` in `tests/test_parser_error_privacy.py`, because the factory call-site matrix test fails without that entry.
changes: scripts/compare-run-outputs.py, tests/test_parser_error_privacy.py (commit a6d572f)
verification: pytest tests/test_parser_error_privacy.py tests/test_compare_run_outputs.py tests/test_cli_abbreviations.py - pass; make contract-smoke - pass; scripts/compare-run-outputs.py --digests tests/fixtures/contract-smoke-digests.json outputs/ci-contract - pass (43 digests match); git status --porcelain - empty
risks: tests/test_parser_error_privacy.py is outside the owned-files list, so the orchestrator should confirm that edit is acceptable. The worktree has a git-ignored `.venv` symlink to the main checkout's venv.
questions_for_g: none
