# Checker fixtures

These fixtures are test-only. There is no runtime dependency on this package, model, network, tenant data or credentials.
Tests never write fixture files.

- `baseline-expectations.json.gz`: S/A's 109 requirement/complete Instructions results, including all 16 resolved XREF
  ranges. The independent reader checks the raw markdown in `../baselines/raw`, including target order and nested children.
- `train-identifiers.json.gz`: 2,516 sorted synthetic identifier tokens of the model pack's training prompts, for check d's
  memorisation test only (training split only).
- `source-pins.json`: SHA-256s of the pinned baseline markdown and the authoritative rule sources.
- `english-words.txt` and `WORDLIST-NOTICE.md`: the ordinary-word heuristic vocabulary and its licence and hash.
- There are no stored resources, pairs or prompts: `tests/explainer_checks/support.py` assembles the checker resources at
  test time from the raw baselines (parsed by this package's own reader) and the shipped template and collection configs,
  and `tests/explainer_checks/corpus.py` generates the pairs, mutants and twins.

Baseline attribution: CISA SCuBA / ScubaGear and Microsoft. Pinned commit:
2446ad723b7f55031cc02c8aca244d731d468cba. Original baseline files and their linked
sources: https://github.com/cisagov/ScubaGear/tree/2446ad723b7f55031cc02c8aca244d731d468cba/PowerShell/ScubaGear/baselines .
ScubaGear's repository licence is CC0 1.0 Universal:
https://github.com/cisagov/ScubaGear/blob/2446ad723b7f55031cc02c8aca244d731d468cba/LICENSE .
The aad.md, powerplatform.md and securitysuite.md headers attribute portions to
Microsoft M365/Azure documentation under CC BY 4.0:
https://creativecommons.org/licenses/by/4.0/ . Original Microsoft licences:
https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE and
https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE . TLP:CLEAR does not
remove copyright obligations. See part 1's raw fixtures for the full headers,
individual Microsoft source links and notices. No legal file is altered here.

Changes to baseline prose: plain-text extraction, whitespace/markdown removal,
instruction splitting, selection of named target ranges and omission of other
sections. The checker parser remains independent of the runtime parser. The
fixtures are not standalone baseline guidance or customer output.
