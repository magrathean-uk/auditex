# Auditex Release Checklist

Run this from a clean checkout before tagging or shipping a release bundle.

## Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pytest
```

Optional adapter checks remain explicit:

```bash
auditex setup --mcp
auditex setup --exchange
auditex setup --pwsh
```

## Required checks

```bash
python -m compileall -q src tests scripts
python -m pytest
auditex --help
auditex doctor --json
auditex guided-run --help
auditex setup-guide m365 --collector-preset identity-only --format json
auditex setup-guide google --collector-preset identity --format json
auditex google --help
auditex report --help
```

## Contract smoke

```bash
auditex run \
  --offline \
  --sample examples/sample_audit_bundle/sample_result.json \
  --tenant-name ci \
  --run-name contract \
  --out outputs/ci-contract

python - <<'PY'
import json
from pathlib import Path
run = Path('outputs/ci-contract/ci-contract')
validation = json.loads((run / 'validation.json').read_text(encoding='utf-8'))
manifest = json.loads((run / 'run-manifest.json').read_text(encoding='utf-8'))
assert validation['valid'], validation['issues']
assert manifest['contract_status'] == 'valid'
assert (run / 'index' / 'evidence.sqlite').exists()
assert (run / 'ai_context.json').exists()
PY
```

## Google offline smoke

```bash
auditex google run \
  --offline \
  --sample examples/google_workspace_sample.json \
  --domain example.com \
  --tenant-name ci-google \
  --run-name contract \
  --out outputs/ci-google-contract
```

## Customer pack smoke

```bash
auditex report customer-pack outputs/ci-contract/ci-contract --output-dir outputs/ci-contract/customer-pack
auditex report verify-pack outputs/ci-contract/customer-pack
```

## Probe and MCP smoke

```bash
auditex probe live --tenant-name LAB --tenant-id <tenant-id> --mode delegated --use-azure-cli-token --run-name probe-smoke

auditex-mcp --help || true
```

## Documentation checks

```bash
python scripts/build-pages-site.py /tmp/auditex-pages

python - <<'PY'
from pathlib import Path
for path in [
    Path('README.md'),
    Path('RUNBOOK.md'),
    Path('docs/README.md'),
    Path('docs/PRODUCT_MANUAL.md'),
    Path('docs/SETUP_GUIDE.md'),
    Path('docs/ADMIN_PERMISSION_GUIDE.md'),
    Path('docs/AI_OPERATOR_GUIDE.md'),
    Path('docs/GITHUB_OPERATOR_GUIDE.md'),
    Path('docs/CUSTOMER_HANDOFF_GUIDE.md'),
    Path('docs/SECURITY_PRIVACY.md'),
    Path('docs/TROUBLESHOOTING.md'),
    Path('docs/SHIP_READINESS.md'),
    Path('CHANGELOG.md'),
    Path('RELEASE_NOTES.md'),
]:
    assert path.exists(), path
    text = path.read_text(encoding='utf-8')
    for marker in ['TO' + 'DO', 'TB' + 'D', 'FIX' + 'ME']:
        assert marker not in text, path
PY
```

## Package build

```bash
python -m build
python -m pip install dist/*.whl --force-reinstall
auditex --help
auditex setup-guide google --collector-preset identity --format json
auditex setup-guide m365 --collector-preset identity-only --format json
```

## GitHub ship checks

```bash
gh api repos/magrathean-uk/auditex/pages --jq '.build_type'
gh workflow list
gh release view v1
```

## Release bundle contents

The shipped bundle must keep these aligned:

- source under `src/`
- configs under `configs/`
- profiles under `profiles/`
- schemas under `schemas/`
- agent prompts under `agent/`
- skills under `skills/`
- sample bundle under `examples/sample_audit_bundle/`
- Google Workspace sample under `examples/`
- product docs under `docs/`
- provenance docs under `docs/provenance/`
- `THIRD_PARTY_NOTICES.md`
- this checklist
