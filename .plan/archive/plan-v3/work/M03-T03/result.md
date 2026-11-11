## RESULT M03-T03
status: done
summary: Added `tests/test_tenant_bootstrap_forwarder.py`. It runs a subprocess (`python -I`) with `tenant-bootstrap` first on `sys.path`. It checks that the `azure_tenant_audit` package resolves to the forwarder and that `cli` and `output` resolve under `src/azure_tenant_audit/`. It also checks that `main` is callable.
summary: It does not repeat the in-process checks in `tenant-bootstrap/tests/test_canonical_runtime_forwarders.py`. The review item (M03-T02 left only the forwarder `__init__.py`) is answered: confirmed by the `git ls-files` check in verify.
changes: tests/test_tenant_bootstrap_forwarder.py
verification: the full verify command from the criteria block (git ls-files check plus four test files, 16 tests) - pass. I linked `.venv` from the main checkout, which is git-ignored.
risks: none
questions_for_g: none
