# Auditex Ship Readiness Guide

Use this guide to decide whether Auditex is ready to tag, package, or hand to a customer operator.

## Release Positioning

Auditex 1.0 is an audit-only product for Microsoft 365 and Google Workspace. The public promise is:

- read-only collection,
- no mail or file body reads,
- local evidence,
- proof-backed findings,
- explicit limitations,
- customer-verifiable handoff packs.

Do not ship a build that weakens those promises.

## Required Release Evidence

A release candidate needs evidence for:

- clean environment install,
- offline Microsoft sample run,
- offline Google sample run,
- full test suite,
- contract smoke,
- customer pack creation,
- customer pack verification,
- command help smoke,
- auth-material scan,
- docs link check,
- release checklist completion.

## Operator Acceptance

An operator should be able to:

1. Install Auditex from the repo or bundle.
2. Run `auditex doctor`.
3. Run offline Microsoft and Google samples.
4. Run Microsoft 365 probe with delegated read login.
5. Run Google Workspace doctor and probe with DWD or OAuth credentials.
6. Generate a report.
7. Generate and verify a customer pack.
8. Explain every missing permission or license blocker.

## Customer Acceptance

A customer reviewer should be able to:

1. Open the customer pack.
2. Verify pack integrity.
3. See whether the run was complete, partial, or unusable.
4. Confirm no tenant writes were recorded.
5. Confirm no mail/file content reads were recorded.
6. See every observed API call.
7. See every required and missing permission.
8. Trace every high or critical finding to saved evidence.
9. Understand exact limitations and next actions.

## Release Commands

```bash
python -m compileall -q src tests
python -m pytest -q
make contract-smoke
auditex --help
auditex doctor --json
auditex google --help
auditex report --help
auditex-mcp --help || true
```

Customer-pack smoke:

```bash
auditex report customer-pack outputs/ci-contract/ci-contract --output-dir outputs/ci-contract/customer-pack
auditex report verify-pack outputs/ci-contract/customer-pack
```

Docs placeholder scan:

```bash
python - <<'PY'
from pathlib import Path
markers = ['TO' + 'DO', 'TB' + 'D', 'FIX' + 'ME']
for path in [Path('README.md'), Path('RUNBOOK.md'), *Path('docs').rglob('*.md')]:
    text = path.read_text(encoding='utf-8')
    hits = [marker for marker in markers if marker in text]
    if hits:
        raise SystemExit(f'{path}: placeholder markers present: {hits}')
PY
```

## Release Blockers

Do not ship when:

- tests fail,
- contract smoke fails,
- customer pack does not verify,
- docs reference removed commands,
- sensitive auth material appears in shipped docs or fixtures,
- audit-plane validation allows tenant writes,
- audit-plane validation allows mail or file body reads,
- Google or Microsoft sample bundle cannot validate,
- high-severity fixture findings lack proof rows.

## Post-Release Smoke

After packaging or tagging:

1. Install into a fresh virtual environment.
2. Run `auditex doctor --json`.
3. Run both offline samples.
4. Render Markdown report.
5. Create and verify customer pack.
6. Start MCP help or server smoke.

Record outputs in release notes or the internal release log.
