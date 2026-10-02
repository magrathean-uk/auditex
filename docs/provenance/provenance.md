# Source Provenance

This page is the human-readable companion to
`docs/provenance/provenance.csv`.

The source tree records a clean-room rule applied on 2026-04-18: GPL and
no-license sources are not used as product source. It says high-risk surfaces
were rewritten from product requirements and current Auditex tests rather than
upstream source text. Permissively licensed projects remain idea-level
influences unless they are listed as vendored or declared dependencies in
`docs/legal/third-party-notices.md`.

The CSV records the file or module, source repository, licence, whether the
relationship is copied or inspired, and the action taken.

| Action | Meaning |
| --- | --- |
| `rewrite` | Auditex replaced implementation or text. |
| `remove` | The distributable tree no longer includes the recorded material. |
| `keep` | The record identifies own code, idea-level influence, a declared dependency, or permissively licensed vendored material with notices. |

The current source record identifies rewritten reporting, report-section,
friendly-name, finding-template, and fallback-template surfaces; it also says
the legacy source-review module and distributable research material were
removed. See the CSV for the file-level record.

## Framework identifiers

`configs/framework-catalog.json` and `configs/control-mappings.json` reference
benchmark control identifiers (CIS Microsoft 365 Foundations v7.0.0, CISA SCuBA
policy ids, Microsoft Secure Score control profile ids, Microsoft cloud
security benchmark ids, and Zero Trust pillar names). Auditex stores
identifiers and short paraphrased titles only; no benchmark text is copied. The
sources used to verify each identifier are listed in the catalog and in
[Framework Mappings](../reference/framework-mappings.md).

## Run explorer icons

The run explorer (`src/auditex/explorer_assets/`) inlines SVG path data for
23 icons from Lucide (`lucide-icons/lucide`, ISC licence, Copyright (c) Lucide
Contributors), some simplified. The script carries an attribution comment, and
the explorer page loads no icon font or remote asset. The explorer's
stylesheet recreates the Industry design-system tokens from the Auditex design
handoff with system font stacks; no Barlow font files are shipped.

## Limits

The source record also states that no external legal review or external
similarity audit has been completed. It is an engineering provenance record,
not a legal opinion or proof of rights for a new contribution. Review new
third-party material before adding it, retain applicable notices, and update
the CSV and [third-party notices](../legal/third-party-notices.md) when a
material relationship changes.
