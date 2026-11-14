## RESULT M06-T05
status: done
summary: The published v1.5.0 release has exactly two assets (wheel and sdist), is neither draft nor pre-release, and both fresh downloads match the gated M06-T02 hashes and the M06-T04 uploaded hashes. The wheel installs into a scratch venv with its dependencies and reports 1.5.0 from both importlib.metadata and the CLIs.
changes: none in the repository; .plan/work/M06-T05/{progress.md, evidence.md, result.md}
verification: gh release view v1.5.0 (assets, isDraft, isPrerelease) pass; gh release download v1.5.0 pass; shasum -a 256 on both assets pass; comparison with M06-T02 and M06-T04 records pass; scratch venv pip install of the wheel pass; importlib.metadata.version("auditex") = 1.5.0 pass; auditex --version = 1.5.0 pass; azure-tenant-audit --version = 1.5.0 pass; scratch folders removed pass
risks: pip's exit code was hidden by a pipe, so the install is confirmed by the import and CLI checks rather than the exit code; the release digests were read from GitHub metadata only as a cross-check.
questions_for_g: none
### Findings
step1-assets: exactly two assets, auditex-1.5.0-py3-none-any.whl and auditex-1.5.0.tar.gz; isDraft false; isPrerelease false
step2-wheel-sha256: 81ea5c2f00bca2d0a880f4fe2527a7a917329396aaaba207c1da00f6ce444eba (equals M06-T02 wheel-sha256 and M06-T04 uploaded-wheel-sha256)
step2-sdist-sha256: 959e825f2bcd769222789c1b5fc3fff8f2acbfc955ba6c9473c6807563b6ee1a (equals M06-T02 sdist-sha256 and M06-T04 uploaded-sdist-sha256)
step3-importlib-version: 1.5.0
step3-auditex-version: auditex 1.5.0
step3-azure-tenant-audit-version: azure-tenant-audit 1.5.0
published-artefacts: verified
