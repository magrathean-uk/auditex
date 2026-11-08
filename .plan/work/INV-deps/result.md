## RESULT INV-deps
status: done
summary: Read-only inventory of dependencies, toolchain and supply chain. Six shell calls, no repo writes, no installs or builds. No lock file is tracked; runtime deps are ranged in pyproject.toml and duplicated in requirements.txt. No tracked CI workflow, although AGENTS.md says merges to main run make test. The runbook lists one fewer release-check step than the Makefile runs. Commit signing is user-level, not repo config.
changes: none
verification: `clean-development doctor` exit 1, WARN-only, machine-level (pass for the slice); `git ls-files | wc -l` 853 (pass); `git log --oneline | head -5` (pass); `git config --show-origin --get-regexp` for gpg/commit/user (pass); `command -v` for pip-audit, gitleaks, ruff, typos, shellcheck, shfmt (pass; pip-audit and ruff absent); `python3 --version` 3.15.2 (pass); `rg` for TODO/FIXME, CI files, provenance coverage, script references, extras usage (pass); no release-check, pytest, pip-audit or gitleaks run.
risks:
- No lock file and ranged deps: builds are not reproducible and known-vulnerability status is unknown (pip-audit absent).
- Makefile:54 uses `$$TMPDIR` under `set -eu`; if unset, release-check aborts (inferred, not run).
- If AGENTS.md is right that main merges run tests, the gate is not in this tree and may be missing.
questions_for_g:
- Should dependencies be locked (uv or pip-tools lock) or stay ranged by design?
- Is the root requirements.txt meant to exist, given pyproject.toml declares the same runtime deps?

### Findings

1. exists
- pyproject.toml:1-86. Build: setuptools>=84 (:2). Python floor >=3.11 (:10). Runtime deps requests>=2.34.2,<3 and msal>=1.39.0,<2 (:14-15). Extras: mcp<2 with a comment on the cap (:19-24); test pytest>=8, jsonschema<5 (:27-30); google (:31-35); model_train exact pins torch==2.14.1, transformers==5.20.1, trl==1.16.0, peft==0.21.2, accelerate==1.15.0, datasets==5.1.0 (:36-44). Ruff lint select E4,E7,E9,F (:51-52).
- requirements.txt:1-2 (requests, msal; same ranges as pyproject).
- tenant-bootstrap/requirements.txt:1-2 (identical content).
- No lock or constraints file tracked (`git ls-files` filter for lock, requirements, constraints, Pipfile, poetry, uv).
- Makefile:48-68 release-check chain; :70-87 contract-smoke; :30-33 install (`pip install -e ".[test]"`).
- .gitleaks.toml:1-21 (useDefault; allowlist for .venv, .secrets, outputs, generated dirs).
- .pre-commit-config.yaml:1-56. pre-commit-hooks v6.0.0 (:6); ruff-pre-commit v0.17.0 (:16); local gitleaks staged scan (:34-38); typos, shellcheck, shfmt manual-stage only (:39-56).
- .github/dependabot.yml:1-38. pip for / and /tenant-bootstrap, weekly, 7-day cooldown (:5-17); mcp major ignored (:25-27); pre-commit ecosystem (:36-).
- scripts/oss-taint-scan.sh:1-55; scripts/check-archive-wheel.py (42 lines); scripts/generate-rule-packs.py (48 lines); scripts/select-python.sh:40 (tries python3.14 down to python3.11, then python3).
- .clean-development.json:1-12 (buildDirs build; depDirs .venv).
- Vendored third-party: tests/schemas/ (SARIF 2.1.0 and OSCAL 1.1.2 schemas, licence files); src/auditex/explorer_assets/fonts/OFL.txt and LICENSE-lucide.txt; tenant-bootstrap/vendor/microsoft-skills/ (MANIFEST.md, LICENSE). Recorded in docs/provenance/provenance.csv and docs/legal/third-party-notices.md (rg hits).
- Commit signing: user-level git config sets SSH signing with commit.gpgsign=true and a 1Password signer. Not in repo; key not recorded here.

2. works
- Python 3.15.2 on PATH (`python3 --version`); meets the >=3.11 floor (pyproject.toml:10). select-python.sh itself not run.
- gitleaks, typos, shellcheck and shfmt are on PATH (`command -v`); ruff and pip-audit are not. Presence only; no scan run.
- git history: HEAD 8b3a334 "chore(plan): scaffold"; 853 tracked files (`git log`, `git ls-files`).
- Taint scan logic read (scripts/oss-taint-scan.sh:7-53); not executed.
- Makefile release-check order read (Makefile:50-68); not executed.

3. broken
- Makefile:54 `$$TMPDIR` under `set -eu`; unset TMPDIR makes the mktemp template relative and the shell aborts (inferred; not run). docs/development/runbook.md does not mention TMPDIR.
- scripts/oss-taint-scan.sh:39 prunes ./docs/taint, which does not exist (`ls` failed). Harmless but stale.
- No CI workflow is tracked (`git ls-files .github` lists only ISSUE_TEMPLATE, PULL_REQUEST_TEMPLATE, dependabot.yml and three md files).

4. dead candidates
- docs/taint (scripts/oss-taint-scan.sh:39); path absent.
- requirements.txt and tenant-bootstrap/requirements.txt: the Makefile and CONTRIBUTING install via `pip install -e .[test]`; a Makefile grep for "requirements" returned nothing. Other references not searched; references unknown.
- Makefile:54 "XXXXXX" matched TODO/FIXME/XXX; false positive, not a marker.
- No TODO/FIXME/HACK in the other slice files (rg over pyproject, Makefile, requirements, scripts, .github, pre-commit, gitleaks).
- model_train extras are referenced by src/auditex/model_training.py, model_eval.py, scripts/*.py and docs/guides/model-development.md (rg), so not dead.

5. contradictions
- docs/development/runbook.md:97 lists release-check as lint, test, contract-smoke, rule-pack drift, taint scan, gitleaks. Makefile:53-65 also runs an archive and wheel check between contract-smoke and the drift check. The runbook omits that step.
- .github/SECURITY.md:22-25 lists 1.2.x as supported and "only the latest minor". pyproject.toml:7 is 1.3.0.dev0 (inferred: 1.3 unreleased; CHANGELOG not checked).
- AGENTS.md ("Merging into main also runs make test once per batch"; "no test gate on the push itself") versus no tracked workflow under .github. Enforcement point unknown.
- Taint scan prunes ./docs/provenance and tenant-bootstrap/vendor/microsoft-skills (scripts/oss-taint-scan.sh:39-41), so vendored text there is not scanned for taint markers. Intended by design; noted for completeness.
- Makefile:18-20 and CONTRIBUTING say lint is compileall only; pre-commit ruff v0.17.0 is the only style check (inferred: not a contradiction, but ruff is not installed locally).

6. open questions
- Enforcement of "make test on merge to main": `gh workflow list` or the repo settings (read-only).
- Is TMPDIR set inside the clean-development env for make? `make -n release-check` in that env settles it.
- Do requirements.txt files have any consumer? `rg -n "requirements" --glob '!.plan/**'` settles it.
- Known vulnerabilities for requests, msal and the exact model_train pins: needs pip-audit in a throwaway venv (an install, outside this brief). I cannot confirm from here that torch==2.14.1, transformers==5.20.1 and trl==1.16.0 exist; `pip index versions` would settle it.
- Does select-python.sh pick 3.15 or 3.14 on this Mac? Run `scripts/select-python.sh` (not run).
- Neighbouring area: user-level git identity uses contact@magrathean.uk; AGENTS.md forbids contact@ only in legal and support text, so likely fine.
- Neighbouring area: doctor warnings (dot-folders, cache extras, LaunchAgent cache paths) are machine-level, outside this slice.
