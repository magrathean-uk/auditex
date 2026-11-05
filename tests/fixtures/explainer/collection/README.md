# Collection wording fixtures

Offline contract fixtures for the product-owned collection wording (`configs/explainer-what-to-collect.json`). No tenant
records, model outputs, credentials, baseline prose or reference implementation are copied; product-authored contract
data under the repository's Apache 2.0 licence.

- `reconciliation.json.gz` pins the source files, every complete inherited S entry (sha256 digests of the 919 original
  wording and dependency entries, in the `sha256:<hex>` form so that key-like cell ids are not read as credentials), the
  product collection data and the independent catalogue pin. The catalogue contract is the spec's byte-exact v3.9.1 cell
  catalogue in `../renderer/catalogue-v391-fixture.json.gz`; it is not duplicated here.
- The citation cases are not stored: `tests/test_explainer_collection.py` derives them at test time from the allowed
  value-rule vector pool (every distinct policy, cell and cited-sections value the pool exercises) plus each cell's
  catalogue citation and null.

The original 919 entries comprise 761 applicable entries across 122 distinct cell ids, 148 met and ten not_applicable
entries. The 165 absent catalogue cells are all not_met; the product table adds inactive entries for them. Inactive
entries have explicit null text and rerun_text, empty placeholders and catalogue provenance. Customer wording and
dependency mappings remain byte-for-byte those of S; tests reconstruct and hash all 919 entries independently of the
runtime loader. Altering wording or dependency mappings requires review and an intentional pin update. The review status
is `pending_owner_review`: this data is not asserted to be product-approved.

Optional `cell_inventory` and `policy_sections` metadata supplement the shared CollectionData fields. They let the loader
reject missing shipped entries and restrict substitution to a policy's fixed section names. Null citations use the full
policy section order; an explicit empty citation list is rejected for applicable entries; supplied citations keep their
order, including the three A1 out-of-order cases.

Both shared reasons are deliberately absent from ordinary cells. Callers dispatch `rule_evaluation_failed` and
`rule_not_implemented` before collection lookup; a null or sentinel cell raises KeyError here and never fabricates a
collection request. The pinned ScubaGear commit is `2446ad723b7f55031cc02c8aca244d731d468cba`; this directory copies no
baseline prose.
