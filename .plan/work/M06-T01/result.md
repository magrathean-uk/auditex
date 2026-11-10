## RESULT M06-T01
status: done
summary: CHANGELOG [Unreleased] is now [1.4.0], covering every merged plan v3 change (model removal with `model_train`, `auditex assess`, D5 masking, reproducible `make dist`, `make acceptance`, removed paths, scanner hardening, Ruff, test and taint-scan hygiene). `CONTRACT_VERSION` and `docs/reference/output-contract.md` are untouched. `pyproject.toml` is 1.4.0. SECURITY.md supports 1.4.x, with 1.3.x and earlier upgrade-only.
changes: pyproject.toml, CHANGELOG.md, .github/SECURITY.md (commit b3cd981 on task/M06-T01-release-notes)
verification: the criteria greps pass; make test passes under run-job (22617 passed, 273 skipped, 7 deselected, 34 xfailed); make contract-smoke passes; git status is clean
risks: the heading date 2026-11-09 follows the CHANGELOG convention, but the real release date may differ, so the orchestrator should adjust it at tagging; `.venv` is a git-ignored symlink to the main checkout, and run-job logged non-fatal temp-dir cleanup warnings
questions_for_g: none
