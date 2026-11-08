## RESULT M02-T01
status: done
summary: Removed the dead `docs/prerequisites/noninteractive.md` reference in the admin guide. It now links to the existing "Power Platform and Power BI (optional)" section. Replaced the stale "held until P4" comment in `defender_spam.py` with a note that the rows are enabled in `configs/scuba-value-rules.json`. The change is comment and docs only. The `model-development.md` mention of `tests/providers/m365` is untouched, as the criteria require.
changes: docs/guides/admin-permission-guide.md, src/azure_tenant_audit/value_rules/defender_spam.py (commit a8a4736)
verification: `! git grep -n 'docs/prerequisites/' -- docs/guides` pass. `generate-rule-packs.py --check` pass ("rule packs up to date (39 packs)"). `git status --porcelain` empty.
risks: The worktree has no `.venv`, so I ran the rule-pack check with the main checkout's venv (`PYTHONPATH=src`), not the `.venv/bin/python` path in the verify line. I did not confirm that the Power BI section of the guide covers every prerequisite the old file named; I linked to it without checking.
questions_for_g: none
