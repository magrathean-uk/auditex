# Explainer baseline extraction

`configs/explainer-baselines.json` vendors requirements, criticalities and own
Instructions for all 109 active policies in CISA SCuBA / ScubaGear at commit
[`2446ad723b7f55031cc02c8aca244d731d468cba`](https://github.com/cisagov/ScubaGear/tree/2446ad723b7f55031cc02c8aca244d731d468cba/PowerShell/ScubaGear/baselines).
This includes policies outside the 102 rule policies. Power Platform 2.3 has no
baseline policy at this pin; absent ids return empty requirement/instructions
and null criticality rather than invented prose.

CISA's repository [LICENSE](https://github.com/cisagov/ScubaGear/blob/2446ad723b7f55031cc02c8aca244d731d468cba/LICENSE)
is [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
The aad.md, powerplatform.md and securitysuite.md headers explicitly attribute
portions to Microsoft documentation under
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/):
[Microsoft 365](https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/LICENSE)
and [Azure](https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE).
Credit CISA SCuBA / ScubaGear and Microsoft for this baseline prose. TLP:CLEAR
permits sharing subject to copyright; it does not replace those licences.
The source is provided as is, without CISA or Microsoft endorsement of Auditex.

The JSON records the full commit and SHA-256 of all eight baseline files and
LICENSE, source URLs at that commit, the original linked sources, notices,
licence references and a statement of changes. Each instruction unit retains
its source filename, inclusive line range and policy id. Source filenames are
relative to `PowerShell/ScubaGear/baselines/`; there are no machine paths.
Original markdown (gzip-compressed; the decompressed bytes are unchanged) and LICENSE are
retained under `tests/fixtures/explainer/baselines/` for independent parsing and attribution
review; these are test fixtures, not runtime input.

Changes: extract only policy requirements, criticalities and Instructions;
remove prose markdown, images and link destinations; keep link labels; fold
en/em dashes to hyphens; collapse whitespace; join PowerShell continuation
lines; keep each executable code block as one step, preserving comments on their own
lines and bypassing prose splitting/semicolon joins, without changing command
wildcards, underscores, quotes or operators. A command's provenance covers its
original block. Omit other sections and removed policies from the runtime
policy index. The extraction/parser and cleaning rules are adapted from frozen
explainer S/A/baselines.py. `source-reader.json` independently preserves that
reader's exact output as acceptance data, with its source hash recorded.

The 16 cross-reference records are explicit data, resolved once in baseline
order after the requesting policy's own units. Label ranges include nested
children. SECURITYSUITE.1.2's erroneous self-pointer explicitly resolves to
SECURITYSUITE.1.1. AAD 7.2 includes AAD 7.1's introductory counting paragraph
and both numbered steps. Power Platform 1.2 resolves 1-3 of 1.1; 2.2 resolves
1-11 of 2.1; 3.2 resolves 1-2 of 3.1. Targets are not recursively expanded.
Source pointer text is retained, including the corrected self-pointer's
original wording. The renderer owns later preamble/orientation omissions and
29-versus-30 occurrence accounting; the baseline reader drops none.

The default cap of 6,000 counts characters in the canonical JSON array of
instruction text strings (sorted keys, compact separators, Unicode unescaped),
including brackets, quotes, escapes and commas, as in S. It excludes provenance
metadata. Only whole trailing units can be dropped; own units have priority.
`cap_report` returns counts and canonical sizes on a cap hit, otherwise null.
No pinned policy hits this cap. Synthetic tests check exact boundaries,
including Unicode, quotes, backslashes and the two-character empty array.

Runtime `load_baselines(read_text)` reads only
`configs/explainer-baselines.json`; supply the existing
`azure_tenant_audit.resources.open_text_resource` reader. Load resources once
outside rendering. `requirement(index, policy_id)`, `criticality(index, policy_id)`,
`instructions(index, policy_id, *, cap=6000)` and
`cap_report(index, policy_id, *, cap=6000)` never mutate input data.
Instructions return dictionaries, not strings; consumers use each unit's
`text` and preserve its source metadata. The index stores only own instructions;
the accessor appends resolved targets. This avoids accidental double expansion.

Regenerate offline with the repository venv:

```sh
.venv/bin/python -B -I scripts/generate-explainer-baselines.py \
  --checkout /path/to/pinned/ScubaGear --output configs/explainer-baselines.json
```

The generator requires an explicit checkout, verifies the full HEAD and every
input's bytes against that commit, and writes deterministic UTF-8 JSON with a
final newline. Without `--output` it prints the same JSON. It does not modify
the checkout, use the network or load a model. `build_baselines(read_text)` is
the build-time extraction function used by the generator and fixture-only
tests; callers supply paths relative to the upstream repository root.

Integration owns installed-wheel resource discovery and changes to existing
provenance.md, provenance.csv and legal notices. In particular, qualify the
existing assertion that no complete baseline file is vendored: complete raw
files now exist in tests, and extracted prose is shipped in the runtime JSON.
Owner-controlled legal files have not been edited by Part 1. Report output
redaction remains the integration owner's responsibility; these public
baseline commands and example addresses are preserved before that boundary.

R4 preserves entire executable pre blocks as indivisible units, exempt only
from the 30-word step limit (the six-step cap stays in force). Navigation pre
blocks retain prose limits. Template limits, runtime validation and independent
S/e/e3 checks enforce the same rule; exact old/new step deltas live in
tests/fixtures/explainer/integration/command-steps-change.json. Frozen baseline
reader and source pins remain historical evidence; reviewed command units are
recorded separately. PowerShell Parser AST tests verify the shown blocks against
the pinned original source without executing commands.
