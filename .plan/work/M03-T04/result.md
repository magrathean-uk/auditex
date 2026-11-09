## RESULT M03-T04
status: done
summary: AGENTS.md has a new "Tenant-bootstrap" section covering lab-only use, the forwarder rule, the three parked lab tools (DEC-006) and the ignored run and secret folders. README.md, docs/index.md and the runbook's tenant-bootstrap line now match it. I checked every claim against the tree.
changes: AGENTS.md, README.md, docs/index.md, docs/development/runbook.md
verification: `grep -q -i '^## .*tenant-bootstrap' AGENTS.md && .venv/bin/python -m pytest tests/test_docs_paths.py` pass; `tests/test_tenant_bootstrap_forwarder.py` pass
risks: The ignored `runs` and `.secrets` folders are named without a trailing slash because `test_docs_paths` rejects paths that are not tracked.
questions_for_g: none
