# Auditex runbook

Use this runbook for local setup, authorized audits, and development checks. To install Auditex as a customer (from PyPI with pipx), follow the [install guide](../guides/install-guide.md); this runbook covers the source checkout. For access planning, start with the [setup guide](../guides/setup-guide.md). For the full workflow, use the [product manual](../guides/product-manual.md).

## Install and inspect

Use Python 3.11, 3.12, 3.13 or 3.14 from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
auditex doctor --json
auditex --help
```

`make install` does the same in `.venv` (or the folder named by `VENV=`), creating it when missing, and never installs into a system Python. It installs the `test` extra too (pytest, jsonschema and the pinned setuptools that `make dist` and `make release-archive` build with), so a fresh `make test` has what the export-schema tests need. Google Workspace needs `python -m pip install -e '.[google]'`; MCP needs `python -m pip install -e '.[mcp]'`. `auditex setup` installs local tools in a source checkout; in an installed wheel or sdist it prints the manual steps instead, since the Python it runs in is already set up. Its `--mcp`, `--exchange`, and `--pwsh` options install optional tooling, so use them only for the intended scope.

## Plan access and probe

```bash
auditex setup-guide m365 --auditor-profile global-reader --collector-preset full --format md
auditex setup-guide google --collector-preset everything --format md
```

Review the generated plan with the tenant administrator. Scope names may carry broader rights than the read calls Auditex makes; check scope risk before granting access. Keep app credentials, service-account files, and token caches in an ignored local location such as `.secrets/`.

Microsoft 365 is audited as the reader app with a certificate; its setup is in [Reader app permissions](../guides/reader-app-permissions.md). Probe it first:

```bash
auditex probe live --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --mode app \
  --client-id <app-id> --certificate-path ~/audit-keys/auditex-reader.pem --certificate-thumbprint <sha1-thumbprint>
```

Review the probe's `live-readiness.json` and `audit-plan.json` before collection. Missing scopes, roles, licenses, services, local tools, tenant policy, runtime errors, and unverified surfaces are separate blockers.

## Run an audit

```bash
auditex run --tenant-name CONTOSO --tenant-id contoso.onmicrosoft.com --auditor-profile global-reader --plane full \
  --client-id <app-id> --certificate-path ~/audit-keys/auditex-reader.pem --certificate-thumbprint <sha1-thumbprint> --out outputs/live
```

`auditex guided-run` provides the interactive route: `--flow app-audit` (the default for `--flow auto`) audits as the reader app with its certificate. It creates nothing in the tenant; the app is set up by the tenant administrator.

Google Workspace commands and credential choices are in the [product manual](../guides/product-manual.md#google-workspace-audit-flow). Rerun a probe after changing roles or scopes.

## Offline fixtures

`auditex demo` is the guided walkthrough for demonstrations and recordings. It replays the synthetic demo tenant into `outputs/demo` under the current folder, which must be empty or absent (to run it again, remove the folder or pass another `--out`), pauses between steps unless `--no-pause` is given, and writes `outputs/demo/explorer.html`. `--sample` replays another offline fixture instead.

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

Comparison suppresses selected volatile timestamp changes by default; `--classic` retains them. `gate` and `gate-drift` fail closed: a missing, empty or invalid run, a contract that does not validate when recomputed, or partial coverage exits non-zero unless `--allow-partial` is given (see the product manual). `--expect-manifest-sha256` (`<run-dir>=<digest>` per run for `gate-drift` and `compare`) pins each run to the SHA-256 of its `bundle-hashes.json` taken when it was written; see the output contract, "Expected manifest digest". Notifications are previews unless `--execute` is supplied. Sending is an external action that needs an authorized destination and reviewed content.

## Development and release checks

Install the test dependencies for development: `python -m pip install -e '.[test]'` (pytest, and jsonschema, which the SARIF and OSCAL export tests use to validate against the official schemas in `tests/schemas/`).

| Check | What it exercises |
| --- | --- |
| `make lint` | Compiles Python under `src` and `tests`, then runs `ruff check .` with the rule set and target version in `pyproject.toml` (the same as the pre-commit hook) and fails on any finding. It does not check formatting or types. It needs the Ruff version pinned in the `dev` extra, found in `.venv` (`python -m pip install -e '.[dev]'`), the `make audit-deps` tool environment or on `PATH`, and stops with a message when Ruff is missing, at another version, or pinned differently from the hook. |
| `make test` | Runs pytest with the interpreter selected by `scripts/select-python.sh`. |
| `make contract-smoke` | Deletes and recreates `outputs/ci-contract`, validates an offline bundle and its evidence index, and replays a generated sample with one blocked read and one cut list, which must come out partial (exit status 1). |
| `./scripts/oss-taint-scan.sh` | Checks forbidden research/derived paths and taint markers. |
| `python3 scripts/generate-rule-packs.py --check` | Fails when `configs/rule-packs.json` differs from the packs generated from the rule templates and mappings; without `--check` it rewrites the file. |
| `gitleaks dir .` | Secret scan of the working tree. `.gitleaks.toml` skips the git-ignored local and generated directories (`.venv`, `.secrets`, `outputs` and similar). |
| `make release-archive` | Builds a wheel from `git archive HEAD` with no build isolation and no index, rejects `build/` and `egg-info` entries, and runs `scripts/check-archive-wheel.py` against the archived source. |
| `make dist` | Builds the sdist and wheel from `git archive HEAD` in a temporary folder and copies them to `dist/`. When `SOURCE_DATE_EPOCH` is unset it uses the commit time of `HEAD`, and it normalises the sdist (gzip header time, member times, owner, group, mode, order) and the file modes of the tree the wheel is built from, so with the pinned toolchain (the `setuptools` pin in the `test` extra, which it checks) the wheel and sdist bytes depend only on the commit, not on the builder's umask. Earlier `auditex-*` wheels and sdists in the output folder are removed first; `DIST_DIR=` names another folder. |
| `make audit-deps` | Resolves the base install and every extra declared in `pyproject.toml` (read from it, `local-answer` included) with `uv` for the running interpreter and platform (metadata only, no source builds) and audits the result. Needs `uv`. A pin PyPI ships only as a source archive (`llama-cpp-python`, listed in `AUDIT_DEPS_SOURCE_ONLY`) has just its metadata prepared from the sdist, which compiles nothing; every other package must resolve from a wheel. |
| `bash scripts/release-smoke.sh dist <work-dir>` | Wheel and sdist smoke: needs exactly one wheel and one sdist in `dist/`, both of the `pyproject.toml` version, and installs them into isolated environments for base, Google and MCP checks. Installed commands run from an empty folder, never the checkout, and it checks that resources come only from the installed package, that `auditex doctor` reports core ready, that `auditex setup` succeeds and that `auditex demo` runs. |
| `make dist-check` | Runs `make dist`, then `twine check --strict` on the wheel and sdist, so the metadata and the README render as PyPI will show them. Twine is in the `dev` extra; `make audit-deps` installs it into its tool environment, or name one with `TWINE=`. Nothing is uploaded. |
| `.venv/bin/python scripts/check-reproducible-build.py` | Builds the current commit twice through plain `make dist` and compares the wheel bytes and the sdist bytes; it exits non-zero and names the artefact that differs. |
| `make release-check` | Refuses to start while tracked files have uncommitted changes (the checks run on the working tree, the archive and dist builds package `HEAD`). Then runs `lint`, `test`, `contract-smoke`, `release-archive`, the rule-pack drift check, the taint scan and the gitleaks scan in that order and stops at the first failure. Needs `gitleaks` on `PATH`. |

`.pre-commit-config.yaml` runs Ruff, the trailing-whitespace and final-newline checks, a staged-file gitleaks scan and the generic file checks on every commit once the hook is installed with `pre-commit install`. The typos, shellcheck and shfmt hooks stay manual: run one with `pre-commit run --hook-stage manual <hook-id> --all-files`. Use focused tests for changed behavior. Contract changes need contract smoke. See [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) for contribution scope and check reporting.

There is no hosted CI; the repository is stored on Git and checks run locally. Before tagging a release, install the Google and MCP extras, run `make release-check`, run `make dist` to build the wheel and source distribution, then `make audit-deps`, `make dist-check`, `.venv/bin/python scripts/check-reproducible-build.py` (the `.venv` interpreter, because `make dist` checks the pinned setuptools in the interpreter it runs with) and `bash scripts/release-smoke.sh dist "$TMPDIR/auditex-release-smoke"`, which creates isolated environments for base, Google, and MCP package checks. The release tag must be `v` followed by the packaged version, which is the `version` in `pyproject.toml` and is listed with its date in [CHANGELOG.md](../../CHANGELOG.md). Update the changelog for every release, and bump `CONTRACT_VERSION` in `src/azure_tenant_audit/contracts.py` and the date in the [output contract](../reference/output-contract.md) when the bundle shape changes. The `mcp` extra is capped below 2 in `pyproject.toml` because the MCP server is only tested against a stand-in for `FastMCP`; raise the cap only together with a test that starts the real server and checks every tool's read-only annotations.

### Acceptance replays

`make acceptance` runs the full v3.9.1 value-rule replay (`-m value_rule_acceptance`), then the `explainer_acceptance` jobs from `tests/explainer_checks/README.md`, serially, and exits non-zero on any failure. `make test` deselects both through `pytest.ini`. Run it at each milestone close and at the release gate.

The replay kit is three files in one folder: `vectors.jsonl`, `a2-vectors.jsonl` and `a2-label-overrides.jsonl`. Set `AUDITEX_TEST_VALUE_RULE_VECTORS_V391` to the path of `vectors.jsonl`; the other two are read from the same folder. The target stops with a message naming the variable when it is unset or names a missing file, and the replay never skips. Before replaying, the test checks the sha256 of all three files:

| File | sha256 |
| --- | --- |
| `vectors.jsonl` | `3515b6facbac73091ef43bfa51b746e9265ac508909103ffcc016a5dab92cf4e` |
| `a2-vectors.jsonl` | `0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b` |
| `a2-label-overrides.jsonl` | `74639d1775267bb7d8e3d7cdf777b5eac4449e636ec383c16e21f79b3d8e1fa1` |

### Publication

A release is a signed `vX.Y.Z` tag plus a GitHub release carrying the wheel and sdist from `make dist` (`gh release create vX.Y.Z dist/*.whl dist/*.tar.gz`), and the same two files uploaded to PyPI under the name `auditex` (`twine upload dist/auditex-X.Y.Z-py3-none-any.whl dist/auditex-X.Y.Z.tar.gz`) after `make dist-check` passes. Customers install from PyPI with `pipx install auditex` (see the [install guide](../guides/install-guide.md)). Tagging, the release and the PyPI upload wait for G's explicit yes naming the version; a green `make release-check` is not approval.

### Internal tools

[`scubagear-export-adapter.md`](scubagear-export-adapter.md) describes an internal, experimental tool for assessing ScubaGear exports. It is not a supported product surface.

## Lab tools

`tenant-bootstrap/` seeds lab tenant data and contains writable operations. `run-enterprise-audit.sh` runs bootstrap before audit by default; it is not a production audit shortcut. Inspect its `--help` and the selected configuration before any separately authorized lab work. Keep lab credentials and outputs separate from customer audits, in the git-ignored `runs` and `.secrets` folders under `tenant-bootstrap`. Its only `azure_tenant_audit` is a forwarder to `src/azure_tenant_audit`.

The response plane is hidden by default and guarded separately. Do not enable it for an ordinary audit. Agent command templates under `agent/` include lab tools as well as audit commands; inspect the selected tool before execution.

### Pending playground checks

Offline and mock-tenant checks do not verify live provider serialisation. Before claiming live parity:

- Confirm how `Get-OrganizationConfig | Select-Object Identity,Name,AuditDisabled` serialises `Identity`.
  The `org_config` adapter withholds an unreadable identity; do not substitute an assumed name.
- Confirm unlicensed-tenant errors for the two ATP licence reads. Paired generic command failures are
  marked `licence_inferred`; the rule projection withholds them rather than asserting no licence.
- Confirm Power Platform `listTenantSettings` accepts the body-free POST with `api-version=2020-10-01`, the version Learn documents.

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
collection.

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
