## RESULT M02-T03
status: done
summary: The three owned docs now say the deterministic template explainer ships and is wired into reports. They also say the catalogued model is parked, not evaluated as an explainer, and never decides or rewrites a verdict. The "planned and unimplemented" and "planned explainer" wording is gone, and the stale "future explainer" phrasing became "template explainer". All three criteria are met. Commit 1990223 on task/M02-T03-explainer-docs.
changes: docs/guides/ai-assessment.md, docs/guides/model-development.md, docs/reference/output-contract.md
verification: `! git grep -n -i -e 'planned and unimplemented' -e 'planned explainer' -- docs/guides docs/reference` pass (clean). `pytest tests/test_architecture_modules.py tests/test_explainer_integration.py` pass, run with the main checkout's venv because the worktree has no `.venv`. `git status --porcelain` empty.
risks: The "wired into reports" claim comes from my reading of the explainer handling in `src/auditex/reporting*`. I did not run a report end to end.
questions_for_g: none
