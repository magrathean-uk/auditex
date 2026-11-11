## RESULT M05-T05
status: done
summary: No code, script, test, config, data-files or shipped_content.py reference ALL-SKILLS-CATALOG, microsoft-foundry or entra-agent-id. The only link is `scripts/oss-taint-scan.sh:35`, which excludes the whole vendor directory. NOTICE and provenance.csv name only the directory, so they stay true. `docs/legal/third-party-notices.md` line 16 would become untrue. The recommendation is to remove all three entries only if G also approves a legal-text change.
changes: none
verification: git grep and rg for the three names and `microsoft-skills` across the worktree (excluding .plan) pass; find over the vendor directory pass. No tests run (read-only task).
risks: Removal also leaves `tenant-bootstrap/vendor/microsoft-skills/MANIFEST.md` stale (lines 16, 29, 43, 69), which is not owner-controlled legal text. The removal task would need to own that file. The third-party-notices line 17 claim that every other retained file matches upstream stays true after removal.
questions_for_g: Remove the three entries, and approve a change to the "Retained scope" line in `docs/legal/third-party-notices.md` (wording from G)? Or keep them so no legal text changes?

### Findings
Quoted legal lines (verbatim):
- NOTICE:7-9: "tenant-bootstrap/vendor/microsoft-skills/ — MIT — Microsoft Corporation, from microsoft/skills. The upstream licence text is copied at tenant-bootstrap/vendor/microsoft-skills/LICENSE. Magrathean modified skills/mcp-builder/scripts/requirements.txt in that subset to raise its declared dependency versions." This names the directory, LICENSE and the mcp-builder file only.
- docs/provenance/provenance.csv:23: "tenant-bootstrap/vendor/microsoft-skills/*,microsoft/skills,MIT,curated vendored subset retained with license notice,keep". This is a wildcard over the directory.
- docs/legal/third-party-notices.md:11 and :15 name the directory and its LICENSE only.
- docs/legal/third-party-notices.md:16: "Retained scope: 11 selected `SKILL.md` files plus required reference files, catalog, and manifest. The full upstream repository is not included in this package."

Code and doc references: `scripts/oss-taint-scan.sh:35` (`:!:tenant-bootstrap/vendor/microsoft-skills/**`) excludes the whole directory, not the entries. Other mentions are `.plan/` records and `MANIFEST.md` itself. Nothing in `pyproject.toml` or `src/azure_tenant_audit/shipped_content.py` mentions the vendor directory.

Path list:
tenant-bootstrap/vendor/microsoft-skills/ALL-SKILLS-CATALOG.md - remove: generated catalogue, no consumer
tenant-bootstrap/vendor/microsoft-skills/plugins/azure-skills/skills/microsoft-foundry/SKILL.md - remove: no reference, Foundry is outside the audit scope
tenant-bootstrap/vendor/microsoft-skills/plugins/azure-skills/skills/microsoft-foundry/.gitignore - remove: part of the same entry
tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/SKILL.md - remove: no reference
tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/references/known-limitations.md - remove: part of the same entry
tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/references/acceptance-criteria.md - remove: part of the same entry
tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/references/sdk-sidecar.md - remove: part of the same entry
tenant-bootstrap/vendor/microsoft-skills/skills/entra-agent-id/references/oauth2-token-flow.md - remove: part of the same entry
tenant-bootstrap/vendor/microsoft-skills/LICENSE - keep: legal notice, named by NOTICE and third-party-notices
tenant-bootstrap/vendor/microsoft-skills/MANIFEST.md - keep: needs a follow-up edit if the entries go (see risks)
tenant-bootstrap/vendor/microsoft-skills/skills/mcp-builder/scripts/requirements.txt - keep: the modified file named by NOTICE and third-party-notices

legal-text-affected: yes docs/legal/third-party-notices.md:16 ("11 selected `SKILL.md` files ... catalog" becomes untrue; NOTICE and provenance.csv are unaffected)
