## RESULT M04-T04
status: done
summary: B1 fixed: unresolved five-initial extensions are withheld despite shorter matches, including titles. B2 fixed: all Unicode mark categories stay within source-spanned tokens; regressions cover both directions across three scripts. Budgets and key handling unchanged. Changes left uncommitted.
changes:
src/azure_tenant_audit/output_redaction.py
tests/test_redaction_person_names.py
tests/test_redaction_scan_budget.py
verification: PYTHONPATH="$PWD/src" .venv/bin/python -m pytest tests/test_redaction_person_names.py tests/test_redaction_scan_budget.py tests/test_redaction_profiles_d3.py tests/test_redaction_keyed_pseudonyms.py PASS, 416 tests. Negative regressions: 20 failed before repair; B1 output retained “A B C D E Vosk wrote”; B2 retained “क़neral Vosk”. git diff --check PASS; git status lists only owned paths. Lint and benchmark skipped as fix-codex-3.md item 4 directs; no ci.sh exists.
risks: External lint, HTML benchmark and independent re-check remain pending. Detailed evidence: .plan/work/M04-T04/b1-b2-evidence.md.
questions_for_g: none
dispatch: committed d7b4424 on task/M04-T04-name-masking (3 paths: src/azure_tenant_audit/output_redaction.py, tests/test_redaction_person_names.py, tests/test_redaction_scan_budget.py)
