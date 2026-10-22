# Auditex runbook

Use this runbook for local setup, authorized audits, and development checks. For access planning, start with the [setup guide](../guides/setup-guide.md). For the full workflow, use the [product manual](../guides/product-manual.md).

## Install and inspect

Use Python 3.11 or newer from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
auditex doctor --json
auditex --help
```

`make install` does the same in `.venv` (or the folder named by `VENV=`), creating it when missing, and never installs into a system Python. Google Workspace needs `python -m pip install -e '.[google]'`; MCP needs `python -m pip install -e '.[mcp]'`. `auditex setup` installs local tools. Its `--mcp`, `--exchange`, and `--pwsh` options install optional tooling, so use them only for the intended scope.

## Plan access and probe

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

Review the generated plan with the tenant administrator. Scope names may carry broader rights than the read calls Auditex makes; check scope risk before granting access. Keep app credentials, service-account files, and token caches in an ignored local location such as `.secrets/`.

For delegated Microsoft 365 access:

```bash
az login --allow-no-subscriptions --tenant contoso.onmicrosoft.com
auditex probe live --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --mode delegated --use-azure-cli-token
```

`make login TENANT=contoso.onmicrosoft.com` is an alternative Azure CLI login helper that selects Firefox. Azure CLI keeps its sign-in state in `AZURE_CONFIG_DIR` (default `~/.azure`), which the scripts leave untouched; set it in your shell to keep that state elsewhere. The Microsoft 365 CLI (`m365`) has no such setting, so Auditex runs it, in the shell scripts and in the Python commands alike, with `HOME` pointing at a private folder: `AUDITEX_M365_HOME` when set (an empty value keeps the `m365` default), otherwise `$XDG_DATA_HOME/auditex/m365` when `XDG_DATA_HOME` is set, otherwise no change. Run `m365` by hand with the same `HOME` to see that sign-in. Review the probe's `live-readiness.json` and `audit-plan.json` before collection. Missing scopes, roles, licenses, services, local tools, tenant policy, runtime errors, and unverified surfaces are separate blockers.

## Run an audit

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --auditor-profile global-reader --plane full --use-azure-cli-token --out outputs/live
```

`auditex guided-run` provides the interactive route. `--flow gr-audit` uses delegated access and `--flow app-audit` uses saved app credentials. `--flow ga-setup-app` performs app setup and requires explicit authority to create or change the customer-local registration; it is not an audit-only step.

Google Workspace commands and credential choices are in the [product manual](../guides/product-manual.md#google-workspace-audit-flow). Rerun a probe after changing roles or scopes.

## Offline fixtures

`auditex demo` is the guided walkthrough for demonstrations and recordings. It replays the synthetic demo tenant into `outputs/demo` (recreated on each run), pauses between steps unless `--no-pause` is given, and writes `outputs/demo/explorer.html`. `--sample` replays another offline fixture instead.

```bash
auditex run --offline --sample examples/sample_audit_bundle/sample_result.json --tenant-name demo --run-name sample --out outputs/offline
auditex run --offline --sample examples/sample_audit_bundle/known_bad_result.json --tenant-name demo --run-name known-bad --out outputs/offline-known-bad
auditex google run --offline --sample examples/google_workspace_sample.json --domain example.com --tenant-name demo --out outputs/google
```

These exercise sample processing and do not demonstrate live tenant access or completeness.

## Review and hand off

```bash
auditex report handoff <run-dir> --format md
auditex report api-calls <run-dir> --format md
auditex report permissions <run-dir> --format md
auditex report proof-table <run-dir> --format md
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
auditex report explorer <run-dir>
auditex report explorer <run-dir> --compare <previous-run-dir> --output explorer.html
```

`report explorer` writes one self-contained HTML page (default `<run-dir>/reports/explorer.html`) with seven views: Overview (risk grade, verdict, coverage, fix-first list), Findings (search, filters, paging, the evidence record behind each finding), Attack paths (hops, ATT&CK techniques, the break-it change), Detection, Baselines (framework controls and the Secure Score reconciliation), Access & data handling (data-handling assertions and every collector's status, reason and read permissions), and Before / after. Collectors that did not run or were blocked show as Not verified, never as pass or fail. `--compare` (repeatable) embeds earlier runs of the same tenant: the header switches between runs and Before / after compares the oldest with the newest. Runs of different tenants or platforms are refused. The page makes no network requests, carries a Content-Security-Policy that pins its one inline script by hash, and is byte-identical for the same input runs, so it can be checksummed. It contains tenant evidence: share it only like the run itself. `auditex demo` writes the explorer with both the original and the after-fixes run.

Use a fresh pack directory and review it for confidential information before sharing through the customer's approved channel. Integrity verification does not establish audit completeness or permission to disclose. Follow the [customer handoff guide](../guides/customer-handoff-guide.md), including expired accepted-risk checks.

```bash
auditex compare --run-dir run-a --run-dir run-b
auditex gate-drift --baseline run-a --current run-b --fail-on high
auditex export list
auditex notify send <run-dir> --sink teams
```

Comparison suppresses selected volatile timestamp changes by default; `--classic` retains them. `gate` and `gate-drift` fail closed: a missing, empty or invalid run, a contract that does not validate when recomputed, or partial coverage exits non-zero unless `--allow-partial` is given (see the product manual). Notifications are previews unless `--execute` is supplied. Sending is an external action that needs an authorized destination and reviewed content.

## Development and release checks

Install pytest for development: `python -m pip install -e . pytest`.

| Check | What it exercises |
| --- | --- |
| `make lint` | Compiles Python under `src` and `tests`; it does not check style or types. |
| `make test` | Runs pytest with the interpreter selected by `scripts/select-python.sh`. |
| `make contract-smoke` | Deletes and recreates `outputs/ci-contract`, validates an offline bundle and its evidence index. |
| `./scripts/oss-taint-scan.sh` | Checks forbidden research/derived paths and taint markers. |
| `python3 scripts/generate-rule-packs.py --check` | Fails when `configs/rule-packs.json` differs from the packs generated from the rule templates and mappings; without `--check` it rewrites the file. |
| `gitleaks dir .` | Secret scan of the working tree. `.gitleaks.toml` skips the git-ignored local and generated directories (`.venv`, `.secrets`, `outputs` and similar). |
| `make release-check` | Runs `lint`, `test`, `contract-smoke`, the rule-pack drift check, the taint scan and the gitleaks scan in that order and stops at the first failure. Needs `gitleaks` on `PATH`. |

`.pre-commit-config.yaml` runs Ruff, the trailing-whitespace and final-newline checks, a staged-file gitleaks scan and the generic file checks on every commit once the hook is installed with `pre-commit install`. The typos, shellcheck and shfmt hooks stay manual: run one with `pre-commit run --hook-stage manual <hook-id> --all-files`. Use focused tests for changed behavior. Contract changes need contract smoke. See [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) for contribution scope and check reporting.

There is no hosted CI; the repository is stored on Git and checks run locally. Before tagging a release, install the Google and MCP extras, run `make release-check`, build the wheel and source distribution, and run `bash scripts/release-smoke.sh dist /tmp/auditex-release-smoke`, which creates isolated environments for base, Google, and MCP package checks. The release tag must be `v` followed by the packaged version, which is the `version` in `pyproject.toml` and is listed with its date in [CHANGELOG.md](../../CHANGELOG.md). Update the changelog for every release, and bump `CONTRACT_VERSION` in `src/azure_tenant_audit/contracts.py` and the date in the [output contract](../reference/output-contract.md) when the bundle shape changes. The `mcp` extra is capped below 2 in `pyproject.toml` because the MCP server is only tested against a stand-in for `FastMCP`; raise the cap only together with a test that starts the real server and checks every tool's read-only annotations.

## Lab tools

`tenant-bootstrap/` seeds lab tenant data and contains writable operations. `run-enterprise-audit.sh` runs bootstrap before audit by default; it is not a production audit shortcut. Inspect its `--help` and the selected configuration before any separately authorized lab work. Keep lab credentials and outputs separate from customer audits.

The response plane is hidden by default and guarded separately. Do not enable it for an ordinary audit. Agent command templates under `agent/` include lab tools as well as audit commands; inspect the selected tool before execution.

### Entra Free directory fixtures

`tenant-bootstrap/scripts/seed-free-directory.py` is a separate lab writer for
unlicensed directory scenarios. Its fixed fixture set contains disabled users,
assigned mail-disabled security groups, single-tenant applications and disabled
service principals, with membership/ownership links between the new fixtures.
Its write operations are limited to those directory objects and links.

Print an offline plan first:

```sh
clean-development run --session session-only -- .venv/bin/python tenant-bootstrap/scripts/seed-free-directory.py \
  --tenant-id "$TENANT_ID" --domain example.onmicrosoft.com \
  --prefix auditex-lab-example --output-dir outputs/free-directory-plan
```

For an authorized lab, repeat with `--execute` and a new output directory.
Execution uses the explicitly selected tenant's Azure CLI session, checks its
verified domain, fixture-name collisions and dynamic licence assignments, and
records created IDs incrementally in a private manifest. Keep that manifest for
review of partial runs. The broader enterprise bootstrap profile is a separate
workload/licensing flow.

Use normal `auditex probe live` and `auditex run` for read-only before/after
collection. `scripts/build-lab-model-cases.py` can then export fixture-only,
unreviewed cases from the finalized audit; see [model development](../guides/model-development.md#cases-from-a-directory-lab).

To exercise a completed free-directory lab, use its private seed manifest:

```sh
clean-development run --session session-only -- .venv/bin/python tenant-bootstrap/scripts/exercise-free-directory.py \
  --seed-manifest outputs/free-directory-seed/manifest.json --action apply \
  --output-dir outputs/free-directory-change-plan
```

Add `--execute` with a fresh output directory to swap the fixture application's
owner and one member of the inner nested group. Capture a baseline first, then
the changed state, using `auditex run --collectors identity,licensing,directory_relationships`
and the same tenant, profile and collection limits. `directory_relationships`
is opt-in and records explicit link coverage. The scenario verifies all fixture
identities, disabled account state, empty app permissions/credentials, and
unlicensed assigned groups before reference-only mutations. Each operation is
journaled privately; uncertain writes are not retried.

Use `--action restore --execute` with another new output directory to restore
the exact baseline links, including after a known partial application. Capture
and compare the restored audit. Unexpected identities or link changes stop the
scenario for review; manifests retain the attempted requests.
