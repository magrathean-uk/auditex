# Source Provenance Sheet

This is the human-readable companion to `docs/provenance/provenance.csv`.

Clean-room rule applied on 2026-04-18: GPL and no-license sources are not used as product source. High-risk surfaces were rewritten from the product requirements and current Auditex tests, not from upstream source text. Permissive projects remain at most idea-level influences unless explicitly listed as vendored or declared dependencies in `THIRD_PARTY_NOTICES.md`.

The CSV columns are:

- `file/module`
- `source repo`
- `license`
- `copied vs inspired`
- `action`

Current action summary:

| Action | Meaning |
| --- | --- |
| `rewrite` | Replaced implementation or text with Auditex-owned implementation/text. |
| `remove` | Removed competitor harvesting, direct-port records, or research pack material from the distributable product tree. |
| `keep` | Retained because it is own code, idea-level only, a declared dependency, or permissively licensed vendored material with notices. |

High-risk rewrite targets completed:

| Surface | Status |
| --- | --- |
| `src/auditex/reporting.py` | Rewritten. |
| `configs/report-sections.json` | Rewritten. |
| `src/azure_tenant_audit/friendly_names.py` | Rewritten. |
| `configs/finding-templates.json` | Rewritten. |
| `src/azure_tenant_audit/findings.py` fallback template text | Rewritten. |
| legacy source-review module | Removed from the product tree. |
| `docs/research/*` | Removed from distributable tree. |

Remaining non-code work:

- no external legal review yet
- no external similarity audit yet
