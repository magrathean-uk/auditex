# Contributing to Auditex

Start with a focused change and describe the operator problem it solves. For a bug, include a minimal synthetic example and expected behavior. Keep tenant evidence and credentials out of issues, commits, fixtures, and screenshots. Report vulnerabilities using [SECURITY.md](SECURITY.md).

## Development environment

Use Python 3.11 or newer from a source checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e . pytest
```

Install `.[google]` or `.[mcp]` only when working on those integrations. The CI test job uses Python 3.13. Local tooling and optional adapters are described in [RUNBOOK.md](RUNBOOK.md).

For managing development caches across projects, consider [Clean Development](https://github.com/magrathean-uk/clean-development). It is optional; Auditex does not require its configuration or command routing.

## Make and verify the change

Keep audit and probe operations read-only with respect to production tenants. Keep message bodies and file contents outside audit collection. Lab bootstrap and guarded response paths have a separate scope; do not introduce them into normal audit flows.

Run the checks that exercise your change:

```bash
python -m pytest tests/test_cli.py
make lint
make test
make contract-smoke
./scripts/oss-taint-scan.sh
```

The first command is an example of a focused test. Select the test modules for the affected provider or behavior. `make lint` checks Python compilation, not formatting or types. `make contract-smoke` deletes and recreates `outputs/ci-contract`; use it for changes to collectors, normalization, schemas, reports, evidence references, or customer packs. Do not store valuable runs there.

For documentation-only changes, check command definitions, relative links, and agreement with the output contract. State which checks were run and which were skipped. Offline checks do not establish live tenant coverage.

## Keep contracts aligned

When public commands or artifacts change, update the relevant operator docs and tests. Permission changes need matching collector definitions, permission maps, scope catalog, generated setup guidance, and ledger behavior. Preserve the separate Google Workspace provider path.

Agent-specific rules are in [AGENTS.md](AGENTS.md). The [output contract](docs/OUTPUT_CONTRACT.md) describes required artifacts and evidence references.

## Pull requests and licensing

Explain the change, its validation, and any remaining limitation. Preserve unrelated work and existing attribution. Keep contributions compatible with the project's [Apache 2.0 license](LICENSE) and record third-party origins in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the [provenance notes](docs/provenance/provenance.md) where relevant. Do not copy code or data whose license you cannot establish.
