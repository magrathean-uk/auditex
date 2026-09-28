# Microsoft Agent Skills Vendor Manifest

Source:

- Site: https://microsoft.github.io/skills/
- Repository: https://github.com/microsoft/skills
- Vendored commit recorded by the project: `33b598366fd91350f032be9b385389ff14876dcc`
- License: MIT, copied to `tenant-bootstrap/vendor/microsoft-skills/LICENSE`
- Vendored on: 2026-04-16
- Remediated packaging pass: 2026-04-18

## Layout retained in this product tree

This source package keeps a curated subset only. It does not carry the full upstream repository.

- `ALL-SKILLS-CATALOG.md`: generated catalog for the retained skills.
- `skills/`: retained core Microsoft agent skills used by the tenant-auditor workflow.
- `plugins/azure-sdk-python/skills/`: retained Python agent/authentication skills.
- `plugins/azure-skills/skills/`: retained Azure operations skills.

Retained `SKILL.md` count: 11.

## Selected skills

Core selected skills:

- `skills/microsoft-docs`
- `skills/mcp-builder`
- `skills/entra-agent-id`

Python / agent selected skills:

- `plugins/azure-sdk-python/skills/azure-identity-py`
- `plugins/azure-sdk-python/skills/m365-agents-py`
- `plugins/azure-sdk-python/skills/agent-framework-azure-ai-py`

Azure operations selected skills:

- `plugins/azure-skills/skills/entra-app-registration`
- `plugins/azure-skills/skills/azure-rbac`
- `plugins/azure-skills/skills/azure-diagnostics`
- `plugins/azure-skills/skills/azure-compliance`
- `plugins/azure-skills/skills/microsoft-foundry`

## Notice handling

The retained Microsoft material is MIT-licensed. The license text is copied in this directory and the component is listed in `NOTICE` and `docs/legal/third-party-notices.md`.

## Local modifications

- `skills/mcp-builder/scripts/requirements.txt`: MAGRATHEAN UK LTD raised the declared versions to `anthropic>=1.8.0,<2` and `mcp>=1.30.0,<2` (upstream: `anthropic>=0.39.0`, `mcp>=1.1.0`), and added a comment line marking the change.

Reapply or drop these changes after a refresh, and keep this list current.

## Refresh command

Refresh outside the product tree first, then copy only the selected subset needed by Auditex:

```bash
rm -rf /tmp/microsoft-skills
git clone --depth 1 https://github.com/microsoft/skills.git /tmp/microsoft-skills
git -C /tmp/microsoft-skills rev-parse HEAD
```

After refresh:

1. Copy only selected `SKILL.md` files and required reference files.
2. Keep `LICENSE` beside the vendored subset.
3. Regenerate `ALL-SKILLS-CATALOG.md` from retained files only.
4. Update this manifest, `NOTICE` and `docs/legal/third-party-notices.md` if the source commit, retained set or local modifications change.
