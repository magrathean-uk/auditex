## RESULT M02-T02
status: done
summary: fe78ee1 adds only the historical dummy-tenant snapshot (3 model-answered, 27 blocked, 72 gaps, revision 64817c8) and a note that these are not rule-only coverage. The criteria forbid model-answered counts, kit figures and live-qualification claims, so none of it lands.
summary: The current README already keeps rule availability (rules for all 102 policies) apart from evidence actually collected ("Rule availability does not guarantee a verdict"). The same paragraph says the model layer is parked and describes the template explainer as shipped.
summary: I found no internal scanner paragraph in the branch or in `.plan/work`, so nothing was added. I did not merge or delete the branch.
changes: none (no commits; worktree clean)
verification: `pytest tests/test_architecture_modules.py` passed, run with the main checkout's venv because the worktree has no `.venv`. `! git grep -n -E '/(Users|Volumes)/' -- README.md` passed with no matches.
risks: The internal scanner paragraph was not found, so that optional addition is skipped. If it exists elsewhere, point me at it.
risks: The worktree has no `.venv`, so `make install` is needed for a plain `.venv/bin/python` verify.
questions_for_g: none
