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

`configs/model-sources.json` pins the inspected OpenAdmin and M365 Expert
model artifacts, OpenAdmin public dataset and source pipeline, and proposed
base checkpoints. Reference models, original data and sparse source copies
are retained outside the distributable tree under
`/Volumes/4TB/dev/auditex-data/` and the workspace's third-party area.
Per-file hashes and upstream revisions accompany the development kit.

Auditex's corpus staging, structured evaluator, case curation and training-pack
writer are independent implementations. The source pipeline informed separate
holdouts, completion-only training and explicit abstention checks. No upstream
generator or model runtime source is vendored. The 48 shipped Auditex cases
and two recorded-response fixtures are newly generated synthetic proposals;
they contain no tenant evidence and carry no human approval. Public source
conversations remain unreviewed, and matching text from those sources is not
shipped as Auditex training gold. No upstream evaluation result is presented
as an Auditex measurement.

## Oracle-labelled cases

`scripts/build-oracle-cases.py` and `scripts/split-oracle-cases.py` produce model-development
cases whose labels are the deterministic output of CISA's ScubaGear policy engine, run offline.

- **cisagov/ScubaGear**, commit `2446ad723b7f55031cc02c8aca244d731d468cba`, CC0 1.0 Universal
  (public domain dedication). Used: the Rego policies (`PowerShell/ScubaGear/Rego/`), the unit-test
  fixtures and their `json.patch` mutations (`Testing/Unit/Rego/`) and the baseline markdown
  (`baselines/*.md`). The policies are evaluated with Open Policy Agent 1.20.2 (Apache-2.0, the version
  ScubaGear pins; not redistributed) over fictional tenant configurations. No ScubaGear code, fixture
  or baseline file is vendored or shipped in the product; the scripts read a local checkout supplied on
  the command line, and each case records the commit (the 12-character short commit, in `provenance.source` and
  in the oracle reviewer; the run's `summary.json` holds the full 40-character commit), policy id, test name, OPA
  version and input hash.
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
  oracle by `scripts/build-prowler-cases.py`: the script imports the Microsoft 365 provider's pydantic service models and check
  classes from a local checkout supplied on the command line and runs the checks offline against a stub client, so ScubaGear
  labels can be compared with Prowler verdicts. No Prowler code, metadata text or check message is vendored or shipped;
  `configs/oracle-policy-map.json` holds check ids with Auditex's own wording. The `status_extended` strings in the generated
  verdict files are Prowler output text, so those files stay with the other oracle outputs outside the distributable tree
  (attribute Prowler and include its Apache-2.0 licence if they are shared). Prowler's own dependencies are installed only in a
  throwaway environment under the build cache, never in the project `.venv`.
- Labels are engine output, not human judgement. `scripts/split-oracle-cases.py --approve-as-oracle`
  records the engine and OPA version as reviewer so the pack preparer accepts the rows; see
  [Model development](../guides/model-development.md#oracle-labelled-cases).

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
