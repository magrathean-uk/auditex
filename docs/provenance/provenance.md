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

## Offline assessment interoperability

`configs/assessment-sources.json` records the repository revisions and selected
paths inspected for the external assessment integrations. The Maester,
ScubaGear and Monkey365 adapters are independent implementations of their JSON
output formats. Prowler and CIPP informed the typed reviewer interfaces;
Cartography informed tenant-scoped relationship semantics and fixtures.
EntraExporter and Microsoft365DSC informed coverage and adapter compatibility
review. The Entra AI prototypes informed evidence selection and explicit
separation of conclusions from collection gaps. No external runtime source is
vendored by these integrations, and report processing never loads a reference
checkout or executes report content.

## Model-development references

The parked model layer is removed (see [Model development](../guides/model-development.md)). Its model-sources
manifest pinned the inspected OpenAdmin and M365 Expert model artifacts, the OpenAdmin public dataset and source
pipeline, and proposed base checkpoints; the corpus staging, evaluator, case curation and training-pack writer
were independent implementations, and no upstream generator or model runtime source was vendored. Reference
models, original data and sparse source copies are retained outside the distributable tree, in the development
workspace's data and third-party areas.

## Oracle-labelled cases

| Source | Licence | Vendored subset |
| --- | --- | --- |
| ScubaGear `2446ad723b7f55031cc02c8aca244d731d468cba` | CC0 1.0 Universal | `configs/risky-delegated-permissions.json`: the resource map and delegated risky permission ids with `Name` and `RiskLevel`, from `PowerShell/ScubaGear/schemas/RiskyAppPermissions.json`; application permissions omitted. |

Oracle case builders, removed with the model layer, produced model-development
cases whose labels are the deterministic output of CISA's ScubaGear policy engine, run offline.

- **cisagov/ScubaGear**, commit `2446ad723b7f55031cc02c8aca244d731d468cba`, CC0 1.0 Universal
  (public domain dedication). Used: the Rego policies (`PowerShell/ScubaGear/Rego/`), the unit-test
  fixtures and their `json.patch` mutations (`Testing/Unit/Rego/`) and the baseline markdown
  (`baselines/*.md`). The policies are evaluated with Open Policy Agent 1.20.2 (Apache-2.0, the version
  ScubaGear pins; not redistributed) over fictional tenant configurations. The removed oracle scripts did not ship
  original ScubaGear code or fixtures; the explainer baseline extraction and test-source exception is
  documented below. They read a local checkout supplied on
  the command line, and each case recorded the commit (the 12-character short commit, in `provenance.source` and
  in the oracle reviewer; the run's `summary.json` holds the full 40-character commit), policy id, test name, OPA
  version and input hash.
  The value-rule engine (`src/azure_tenant_audit/value_rules/`) ports the reviewed
  Auditex spec v3.9.1 with addenda A1 and A2 (the catalogue is `spec_version: v3.9.1`: 102 policies, 1,084 cells),
  retaining the v2 Power BI/AAD rules and v3.9
  stages whose policy semantics did not change. The reference oracle is the pinned
  CISA-derived ScubaGear Rego at the revision above, evaluated offline with OPA 1.20.2;
  it is not a runtime dependency. Tests check the Rego file hashes against the pinned
  hash inventory in `auditex/scubagear_prune_proof.py`.
  The compressed fixtures under `tests/fixtures/value-rules/` contain 16,980 rows across
  `vectors-v2`, `vectors-v39` and `vectors-s4` to `vectors-s9` (`.jsonl.xz`), plus the 2,233-row
  `vectors-v391-sample.jsonl.xz` cut from the spec's 26,898 vectors, constructed and pack train/validation kinds only
  (every cell, with ADDENDUM-A2's three constructed vectors and exact label overrides;
  `scripts/build-value-rule-sample-v391.py`). They include
  prepared rows for the three policies that were held and are now enabled.
  Only constructed synthetic rows and model-pack train/validation rows are included;
  pack rows derive from ScubaGear fixtures under CC0 1.0 Universal. Held-out test rows,
  pilot rows and sealed AAD v2.1 freeze rows are excluded. Each vector has an id and
  origin metadata; manifests record source and compressed hashes, policy/cell counts
  and row origins. Fixture builders preserve those boundaries and replace the two
  v2 Power BI licence texts with the current constant wording.
- The `policy` evidence object quotes up to 600 characters of baseline text per policy. CISA states
  that parts of those baselines are adapted from Microsoft documentation under CC BY 4.0, so a
  dataset that keeps `baseline_text` must carry attribution to Microsoft and CISA for that prose;
  otherwise strip the field before redistribution. CISA provides the baselines "as is", TLP:CLEAR,
  and does not endorse any product: nothing here implies CISA endorsement of Auditex, the dataset or
  any model trained on it.

- **mmorris35/m365-sim**, commit `203d66163b089eec63af258d8142c171d982994c`, Apache-2.0. Reference only:
  it informed the idea of simulated tenant fixtures. No code, data or text from it is used, and it is
  not a label source.
- **prowler-cloud/prowler**, commit `f45173997b8331e6cba3deac78bc2e1043b9281d`, Apache-2.0. Used as a second labelling
  oracle by a case builder removed with the model layer: it imported the Microsoft 365 provider's pydantic service models and check
  classes from a local checkout supplied on the command line and ran the checks offline against a stub client, so ScubaGear
  labels can be compared with Prowler verdicts. No Prowler code, metadata text or check message is vendored or shipped;
  an oracle policy map held check ids with Auditex's own wording. The `status_extended` strings in the generated
  verdict files are Prowler output text, so those files stay with the other oracle outputs outside the distributable tree
  (attribute Prowler and include its Apache-2.0 licence if they are shared). Prowler's own dependencies are installed only in a
  throwaway environment under the build cache, never in the project `.venv`.
- Labels are engine output, not human judgement. The removed case tools recorded the engine and OPA version as
  reviewer; see [Model development](../guides/model-development.md#oracle-labelled-cases).

P1 serving ships `configs/scuba-policy-sections.json`: all 102 policy items and ordered
section dependencies extracted from the local v7 oracle pack (source pack SHA-256 and
ScubaGear revision recorded in the file). Policy items preserve the trained baseline
excerpts verbatim, including eight applicability statements and the intentionally empty
MS.POWERPLATFORM.2.3v1 excerpt. Baseline prose is attributed to CISA and
Microsoft: CISA SCuBA / ScubaGear, CC0 1.0 Universal, with portions adapted from
Microsoft documentation under CC BY 4.0. The source is ScubaGear's `baselines/` at
revision `2446ad723b7f55031cc02c8aca244d731d468cba`. The excerpts are unchanged;
this use implies no endorsement.

## Framework identifiers

`configs/framework-catalog.json` and `configs/control-mappings.json` reference
benchmark control identifiers (CIS Microsoft 365 Foundations v7.0.0, CISA SCuBA
policy ids, Microsoft Secure Score control profile ids, Microsoft cloud
security benchmark ids, and Zero Trust pillar names) and cite headings of the
NCSC Cyber Essentials Requirements for IT Infrastructure v3.3 under Auditex-local
requirement ids. Auditex stores identifiers, headings and short paraphrased
titles only; no benchmark or standard text is copied. NCSC content is Crown
copyright and may be reused under the [Open Government Licence
v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)
with acknowledgement of the source, as the [NCSC
terms](https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions)
state. The IASME notices used for the effective dates are IASME content, not
Crown copyright, and are cited for dates only. The
sources used to verify each identifier are listed in the catalog and in
[Framework Mappings](../reference/framework-mappings.md).

## Operating-system end-of-life dates

`configs/os-end-of-life.json` records when each Windows 10 and 11 build, macOS, iOS, iPadOS and Android
release stops receiving security updates, so a tenant audit can say which managed devices run unsupported
software. The dates are facts taken from Microsoft's Windows lifecycle and release health pages, Apple's
security release notes and the Android Security Bulletins, cross-checked against endoflife.date; every entry
lists its sources and a `verified_on` date. Apple and Google publish no end-of-life dates, so those entries are
marked `derived` and explain how the date was reached. No page text is copied.

## Run explorer icons

The run explorer (`src/auditex/explorer_assets/`) inlines SVG path data for
23 icons from Lucide (`lucide-icons/lucide`, ISC licence, Copyright (c) Lucide
Contributors), some simplified. The script carries an attribution comment, and
the explorer page loads no icon font or remote asset. The explorer's
stylesheet recreates the Industry design-system tokens (colour, type-scale,
spacing and frame values) from the run-explorer design the owner produced in
Claude Design for Auditex; no third-party stylesheet or code is copied. Barlow 400/600 and Barlow Condensed 600 (Copyright 2017 The Barlow
Project Authors, SIL Open Font License 1.1) are shipped as unmodified WOFF2
subsets from Google Fonts in `src/auditex/explorer_assets/fonts/` with their
`OFL.txt`, and embedded as data URIs so the page makes no network requests.

## Limits

The source record also states that no external legal review or external
similarity audit has been completed. It is an engineering provenance record,
not a legal opinion or proof of rights for a new contribution. Review new
third-party material before adding it, retain applicable notices, and update
the CSV and [third-party notices](../legal/third-party-notices.md) when a
material relationship changes.

## Deterministic explainer baseline prose

The explainer vendors extracted public requirements, criticalities and
Instructions in configs/explainer-baselines.json, and derived prose and source
metadata in configs/explainer-template.json. Original pinned baseline markdown
and LICENSE are retained in test fixtures for independent parsing. This qualifies
the oracle tooling's earlier no-vendored-baseline statement.

Source: CISA SCuBA / ScubaGear commit
2446ad723b7f55031cc02c8aca244d731d468cba, CC0 1.0 Universal. Portions of aad.md,
powerplatform.md and securitysuite.md adapt Microsoft documentation under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); credit both CISA and
Microsoft. TLP:CLEAR permits sharing subject to copyright and implies no
endorsement. Source links, hashes, file/line provenance, Microsoft licence links
and a statement of changes accompany the data and the
[extraction record](explainer-baselines.md). Changes include plain-text extraction,
splitting complete instructions and commands, markdown/link removal, omissions
and explicit cross-reference resolution. Owner-controlled legal files are
unchanged; this engineering record does not replace owner review.

Synthetic regression, mutation and canary test material includes no tenant evidence
and is generated, not stored: it is derived in memory from the value-rule vector
fixtures, which hold only constructed rows and model-pack train and validation rows.
The small explainer fixtures that are stored (including the pinned baseline markdown)
use lossless gzip where large. The fixture `SHA256SUMS` hashes the stored bytes,
including gzip bytes; upstream baseline hashes identify the original uncompressed
source bytes. Held-out test rows, pilot rows, sealed freeze rows and diagnostic rows
are never stored or used.
