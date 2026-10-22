# Vendored export schemas

These files are the official JSON Schemas that `tests/test_sarif_oscal_exports.py` validates the
SARIF and OSCAL exports against. They are test fixtures: fetched once on 2026-10-22, committed
unmodified, never fetched during a test run, in the public repository and not part of the wheel.

| File | Standard | Source | SHA-256 |
| --- | --- | --- | --- |
| `sarif-schema-2.1.0.json` | OASIS Static Analysis Results Interchange Format (SARIF) Version 2.1.0, Errata 01 | https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| `oscal_assessment-results_schema-1.1.2.json` | NIST OSCAL 1.1.2, Assessment Results model | https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_assessment-results_schema.json (renamed here to carry the version) | `d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d` |
| `LICENSE-SARIF.md` | OASIS copyright notice for the SARIF schema, copied from Appendix B of the specification | https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html | not applicable: the notice is reproduced, not copied as a file |
| `LICENSE-OSCAL.md` | Licence of the NIST OSCAL repository at v1.1.2 | https://raw.githubusercontent.com/usnistgov/OSCAL/v1.1.2/LICENSE.md | `63407ac41abc46911bc9759fc0c19fd0ba7f66c59bb6746e51d85e2f2f3244b1` |

## Licence notes

- **OSCAL.** A work of NIST employees: public domain in the United States, and dedicated to the
  public domain worldwide under CC0 1.0 Universal. NIST is the source of the schema; the licence
  text is in `LICENSE-OSCAL.md`, including NIST's request to acknowledge NIST as the source of the
  data.
- **SARIF.** Published by the OASIS SARIF Technical Committee and governed by the OASIS
  Intellectual Property Rights Policy (RF on RAND Terms mode). The OASIS Notices require the
  copyright notice to accompany copies, so `LICENSE-SARIF.md` reproduces it word for word from
  Appendix B of the specification. The schema file itself carries no notice and is kept byte for
  byte as published.
- **Distribution.** These files are in the public Auditex repository. They are test fixtures and are
  not part of the Auditex wheel.

## Using them

The SARIF schema is JSON Schema draft-04 and the OSCAL schema is draft-07. The OSCAL schema's
`token` pattern uses the Unicode property escapes `\p{L}` and `\p{N}`, which Python's `re` does not
support; the test translates only those two escapes (to `[^\W\d_]` and `\d`) in memory before
validating, and leaves every other rule as published. To update a schema, fetch the new version,
replace the file, update the hash above and this note, and rerun the export tests.
