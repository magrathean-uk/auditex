## RESULT SETUP-ruff
status: done
summary: Installed ruff==0.17.0 into the shared project venv. `ruff --version` prints `ruff 0.17.0`. The `pip freeze` diff shows one added line, `ruff==0.17.0`, and no other package changed.
changes: none (the venv only; no repository files touched)
verification: `pip install 'ruff==0.17.0'` pass; `.venv/bin/ruff --version` pass; `pip freeze` before and after diff pass
risks: none
questions_for_g: none
