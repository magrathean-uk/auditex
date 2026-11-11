## RESULT M03-T01-check
status: done
summary: 33 candidates checked. Counts: safe 0, likely safe 15, referenced 18, uncertain 0.
summary: The 16 vendored files that `cli.py` or `__main__.py` import (the cli, config and collectors chain) are `referenced`. Tests load the vendored `cli.py` with only the vendored path, so they would break.
summary: Dependabot (`.github/dependabot.yml:9`) needs `tenant-bootstrap/requirements.txt`; `docs/legal/third-party-notices.md:65` cites the root `requirements.txt`. `assets/auditex-logo.png` is unreferenced but sits in the shipped `assets/*` glob, so the wheel contents change.
summary: Per-path detail is in `.plan/work/M03-T01-check/evidence.md`.
changes: `.plan/work/M03-T01-check/evidence.md` only
verification: rg for file names, module names, `tenant-bootstrap`, `azure_tenant_audit`, `requirements`, `auditex-logo`, `benchmarks`, `tenant-audit-flow`, `populator` and `run-auditor`, run over the repo, config, docs, tests and `agent/`: pass. An AST import-chain walk over the vendored package found 10 files not reached from `cli.py`: pass. No build or test run (no cheap check; `.venv` not linked).
risks: `tenant-bootstrap/azure_tenant_audit/__init__.py:11` imports `.cli`, so removing the vendored `cli.py` leaves the forwarder reliant on the `src/` copy. The standalone kit would break, and `__init__.py` is not on the list.
risks: Removing the vendored package would need the following changed in the same task, or it fails: `tests/test_vendored_cli_abbreviations.py`, `tests/test_parser_error_privacy.py:32,715`, `tenant-bootstrap/tests/test_canonical_runtime_forwarders.py` and `agent/tenant-audit-skill.json:287`.
questions_for_g: Is the standalone tenant-bootstrap kit still a supported way to run, with its own copy of the CLI? If not, drop the 16 vendored files together with their tests and the `run-audit-collector.sh` fallback.

### Findings
- benchmarks/fake_graph_benchmark.py - likely safe (unchecked: external consumers) - no code, Makefile or CI reference; `docs/reference/security-privacy.md:195` names `benchmarks` as a directory
- scripts/tenant-audit-flow - likely safe (unchecked: external consumers) - no reference anywhere, and `tests/test_local_auth_scripts.py` does not cover it
- assets/auditex-logo.png - likely safe (unchecked: external consumers) - no reference (`explorer.py:1169` uses the `-64` file), but `assets/*` is shipped (`pyproject.toml:75`, `shipped_content.py:20`)
- requirements.txt - referenced (`docs/legal/third-party-notices.md:65`)
- tenant-bootstrap/requirements.txt - referenced (`.github/dependabot.yml:7-9` pip directory `/tenant-bootstrap`, which has no `pyproject`)
- tenant-bootstrap/scripts/auth-lab-populator.py - likely safe (unchecked: external consumers) - only its own docstring
- tenant-bootstrap/scripts/create-lab-populator-app.py - likely safe (unchecked: external consumers) - only its own docstring
- tenant-bootstrap/scripts/run-auditor.sh - likely safe (unchecked: external consumers) - only its own usage text
- tenant-bootstrap/azure_tenant_audit/__main__.py - referenced (`agent/tenant-audit-skill.json:287`; `tenant-bootstrap/scripts/run-audit-collector.sh:222-226`)
- tenant-bootstrap/azure_tenant_audit/cli.py - referenced (`__init__.py:11`; `tests/test_vendored_cli_abbreviations.py:45`; `tests/test_parser_error_privacy.py:32,715`; `tenant-bootstrap/scripts/replay-known-bad-fixtures.py:25`)
- tenant-bootstrap/azure_tenant_audit/argument_parser.py - referenced (imported by `cli.py`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/config.py - referenced (imported by `cli.py`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/graph.py - referenced (imported by `cli.py`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/output.py - referenced (imported by `cli.py`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/utils.py - referenced (imported by `cli.py`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/collectors/__init__.py - referenced (`cli.py` imports `REGISTRY`; vendored tests above)
- tenant-bootstrap/azure_tenant_audit/collectors/auth_methods.py - referenced (collector registry chain from `cli.py`)
- tenant-bootstrap/azure_tenant_audit/collectors/base.py - referenced (imported by `cli.py`)
- tenant-bootstrap/azure_tenant_audit/collectors/exchange.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/collectors/identity.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/collectors/intune.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/collectors/security.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/collectors/sharepoint.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/collectors/teams.py - referenced (collector registry chain)
- tenant-bootstrap/azure_tenant_audit/adapters/__init__.py - likely safe (unchecked: external consumers) - not in the `cli.py` import chain; `src/` shadows it in-repo; `CHANGELOG.md:655` and `security-privacy.md:192-195` describe the copy generically
- tenant-bootstrap/azure_tenant_audit/adapters/base.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/adapters/m365_cli.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/adapters/m365dsc.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/adapters/powershell_graph.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/diffing.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/findings.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/normalize.py - likely safe (unchecked: external consumers) - as above
- tenant-bootstrap/azure_tenant_audit/profiles.py - likely safe (unchecked: external consumers) - as above; `tenant-bootstrap/tests/test_audit_cli_profiles.py:16` imports `azure_tenant_audit.profiles` by name, which resolves to `src/`
- Open points: `tenant-bootstrap/azure_tenant_audit/__init__.py` is not on the list but is the forwarder for the rest. `tenant-bootstrap/tests/` (7 files) and `config.enterprise-lab-max.json` were not checked and may depend on the removed set. The root `requirements.txt` duplicates the `pyproject` dependencies and is not used by `make audit-deps`.
