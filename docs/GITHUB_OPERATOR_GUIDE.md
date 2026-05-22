# Auditex GitHub Operator Guide

Use GitHub for product work and customer-safe coordination only. Do not put raw tenant evidence or auth material in issues, pull requests, comments, artifacts, or workflow logs.

## Issue Workflow

For a setup issue, include:

- provider: Google Workspace or Microsoft 365,
- intended collector preset,
- setup-guide Markdown output,
- probe status,
- blocker classes and missing permissions,
- whether `validation.json` passed.

Do not include local auth files, raw API responses, or tenant exports.

## Pull Request Workflow

Every product PR should include:

- summary of behavior changed,
- docs updated when CLI, scopes, artifacts, or operator flows change,
- tests run,
- read-only impact statement when audit behavior changes.

## CI Smoke

Recommended local checks before pushing:

```bash
make test
make lint
make contract-smoke
auditex setup-guide google --collector-preset identity --format json
auditex setup-guide m365 --collector-preset identity-only --format json
```

For customer packs:

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

Only publish customer-safe packs after verification passes.
