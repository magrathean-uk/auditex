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
python -m compileall -q src tests
python -m pytest
auditex --help
auditex doctor --json
auditex guided-run --help
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

## Probe, response, and MCP smoke

Use a lab tenant or saved lab auth context only.

```bash
auditex probe live --tenant-name LAB --tenant-id <tenant-id> --mode delegated --use-azure-cli-token --run-name probe-smoke

auditex response list-actions

auditex response run \
  --tenant-name LAB \
  --tenant-id <tenant-id> \
  --action message_trace \
  --target user@example.com \
  --intent "release smoke" \
  --allow-lab-response \
  --run-name response-smoke

auditex-mcp --help || true
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
- provenance docs under `docs/provenance/`
- `THIRD_PARTY_NOTICES.md`
- this checklist
