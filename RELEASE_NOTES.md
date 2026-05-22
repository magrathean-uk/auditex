# Auditex v1 Enterprise Release

Auditex v1 is the audit-only enterprise release for Microsoft 365 and Google Workspace.

## Highlights

- Microsoft 365 and Google Workspace audit paths share the same bundle contract, validation, reporting, export, compare, and MCP surfaces.
- Setup-guide commands tell operators what access is needed before a live run.
- Google Workspace domain-delegated and OAuth modes are supported, with coverage blockers reported as audit limitations.
- Customer packs include proof tables, limitations, API call review material, and verification checks.
- GitHub Pages publishes the operator docs from the main branch.
- GitHub release automation builds, smoke-tests, and attaches package artifacts for version tags.

## Safety

- Auditex is read-only by default.
- Live runs do not read Gmail body content, Drive file content, mail body content, or OneDrive/SharePoint file content.
- Production writes and remediation actions are out of scope for v1.
- Raw tenant evidence and auth material stay local unless an operator deliberately packages customer-safe reports.

## Verification

Run before shipping:

```bash
make test
make lint
make contract-smoke
python scripts/build-pages-site.py /tmp/auditex-pages
python -m build
```
