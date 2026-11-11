## RESULT INV3-bootstrap
status: done
summary: tenant-bootstrap/ is a lab seeding and rehearsal kit (131 tracked files). Its azure_tenant_audit/ package forwards to src/azure_tenant_audit/ when src exists (__init__.py:7-13), so the 23 divergent copies only run if src is absent (inferred). Nothing confirmed broken. Full notes: .plan/work/INV3-bootstrap/notes.md
changes: none (notes written to .plan/work/INV3-bootstrap/notes.md only)
verification: rg, git ls-files, git log, wc, diff -q loop, find | wc, bash -n on 4 shell scripts (all pass); tests not run (slice forbids suites); no clean-development doctor run (brief forbids it, but the SessionStart hook asked for it; G to decide)
risks: standalone-kit fallback if tenant-bootstrap/ is used outside the repo root (__init__.py:6 assumes parents[1] is repo root); 3 scripts unreferenced; AGENTS.md is silent on the kit
questions_for_g: Is the standalone kit (CHANGELOG.md:655) still a shipped product? Should the divergent copies be deleted or re-synced to src? Should AGENTS.md get a tenant-bootstrap section? Should clean-development doctor be run for the failed lifecycle registration?

### Findings

1. exists
- Root: run-bootstrap-azurecli.sh, run-bootstrap.ps1, run-enterprise-audit.sh, run-enterprise-lab-max.sh, config.example.json, config.enterprise-lab-max.json, requirements.txt (requests, msal), .gitignore (runs/, audit-output/, .secrets/). (tenant-bootstrap/requirements.txt; .gitignore)
- azure_tenant_audit/: 26 .py modules, 3,181 lines (wc -l). Forwarder entry point: tenant-bootstrap/azure_tenant_audit/__init__.py:1-14.
- scripts/: 10 PowerShell (00-shared, 01-09), 9 Python, 6 shell, 25 files in total.
- configs/: 4 JSON files plus tenant-audit.example.env. policies/: 7 entra, 5 exchange, 16 intune JSON files. templates/docs/: 3 markdown files.
- tests/: 7 test files plus conftest.py, 55 test functions (rg -c "^def test_").
- vendor/microsoft-skills/: 11 SKILL.md files, MANIFEST.md, LICENSE, ALL-SKILLS-CATALOG.md.

2. works
- Forwarder mechanism: tenant-bootstrap/azure_tenant_audit/__init__.py:7-10 prepends src/azure_tenant_audit to __path__ when it exists; :13 `from .cli import main` loads the src copy (read).
- Identical to src: adapters/base.py, __main__.py, argument_parser.py (diff -q). The other 23 .py files differ, e.g. cli.py 665 vs 1193 lines, output.py 248 vs 959, normalize.py 234 vs 3219, findings.py 73 vs 4477, graph.py 296 vs 873, adapters/powershell_graph.py 20 vs 524.
- bash -n passes on run-bootstrap-azurecli.sh, run-enterprise-audit.sh, run-enterprise-lab-max.sh, scripts/run-audit-collector.sh.
- Vendored SKILL.md count is 11 (find vendor -name SKILL.md | wc -l), matching vendor/microsoft-skills/MANIFEST.md.

3. broken
- none confirmed.
- Unresolved hit: azure_tenant_audit/m365_home.py is imported by src/auditex/auth.py:16 and is not in the slice (lives under src/, inferred).
- Relative defaults that work only from the repo root: scripts/identity_seed_az.py:614 and scripts/seed-workload-az.py:3146 (tenant-bootstrap/config.example.json).
- __init__.py:6 takes the repo root as parents[1]. That holds only when tenant-bootstrap/ sits one level below the repo root (inferred; a standalone copy falls back to the divergent files).

4. dead candidates (rg outside scripts/ itself)
- scripts/auth-lab-populator.py: 0 references.
- scripts/create-lab-populator-app.py: 0 references.
- scripts/run-auditor.sh: 0 references (only its own usage line, :10).
- vendor/microsoft-skills ALL-SKILLS-CATALOG, microsoft-foundry and entra-agent-id: no code references. They appear only in docs/legal/third-party-notices.md, docs/provenance/provenance.csv, NOTICE and scripts/oss-taint-scan.sh (prune).
- Divergent azure_tenant_audit/ copies: effectively shadowed while src/ exists (inferred from __init__.py:9-10).
- Scripts 01-09 and windows365_workload.py: referenced by one or two files each; only run-bootstrap.ps1 was confirmed as a referrer, for 01-create-workload-apps.

5. contradictions
- AGENTS.md has no tenant-bootstrap section. Its only mention is AGENTS.md:19, which lists "tenant-bootstrap run and secret folders" as git-ignored; tenant-bootstrap/.gitignore lists runs/, audit-output/ and .secrets/.
- README.md:19, docs/index.md:41 and docs/development/runbook.md:118 describe the kit as lab-only and writable. AGENTS.md's boundaries cover only the audit surfaces, so the kit is not addressed there.
- CHANGELOG.md:655 says the kit carries "its own copy" of the CLI. That fits the divergence, but the forwarder now prefers src/.
- tests/test_vendored_cli_abbreviations.py:19 and tests/test_parser_error_privacy.py:32 and :715 treat tenant-bootstrap/azure_tenant_audit/cli.py as the vendored CLI under test. Whether that code runs when src is present is inferred from __init__.py.

6. open questions
- Does `PYTHONPATH=tenant-bootstrap python3 -c "import azure_tenant_audit.cli as c; print(c.__file__)"` from the repo root resolve to src/? Settles the forwarder claim; needs dependencies, so not run.
- Is the standalone kit still shipped? Check pyproject.toml data-files and `git log -- tenant-bootstrap/azure_tenant_audit`.
- Is the divergence intentional? Compare `git log --oneline -- tenant-bootstrap/azure_tenant_audit src/azure_tenant_audit`.
- Does any runtime code load the vendored skills? An rg over agent/, skills/ and src/ found only docs hits.
- Is vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt the one modified file named in docs/legal/third-party-notices.md:17? Not opened.
- Neighbour (one line): src/auditex/auth.py:16 and src/auditex/guided.py:13 depend on src/azure_tenant_audit/m365_home.py.
