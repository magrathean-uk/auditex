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
python scripts/build-pages-site.py /tmp/auditex-pages
auditex setup-guide google --collector-preset identity --format json
auditex setup-guide m365 --collector-preset identity-only --format json
```

For customer packs:

```bash
auditex report customer-pack <run-dir> --output-dir customer-pack
auditex report verify-pack customer-pack
```

Only publish customer-safe packs after verification passes.

## Website

The public website lives at `auditex.hu` outside this repository. GitHub Pages is built by the `pages` workflow only to keep the repository Pages handoff pointed at that domain.

Local handoff build:

```bash
python scripts/build-pages-site.py site
```

The repository Pages setting must use workflow builds and the custom domain `auditex.hu`. If the site is missing, create it through the GitHub Pages API with `build_type=workflow`, then set `cname=auditex.hu`.

## Releases

Version tags that start with `v` run the release workflow. The workflow runs release checks, builds package artifacts, smoke-tests the installed wheel, then publishes a GitHub release using `RELEASE_NOTES.md`.

For the v1 line:

```bash
git tag -a v1 -m "Auditex v1 enterprise release"
git push origin main v1
gh release create v1 dist/* --title "Auditex v1 Enterprise Release" --notes-file RELEASE_NOTES.md --verify-tag
```
