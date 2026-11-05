# Pinned public baseline fixtures

`raw/*.md.gz` are gzip-compressed, byte-for-byte copies (the decompressed bytes are the originals and carry the pinned hashes) of all eight files in
`PowerShell/ScubaGear/baselines/` at ScubaGear commit
`2446ad723b7f55031cc02c8aca244d731d468cba`. `removedpolicies.md` is retained
for the source/attribution audit and excluded from the active index.
`LICENSE.scubagear.txt` is the unmodified upstream repository licence.
`manifest.json` records original relative paths, hashes and licence scopes.
These files are public reference documents, with no tenant evidence.

`source-reader.json.gz` is a separately frozen extraction produced by the original
S/A/baselines.py reader, not by the port or its tests. It pins all 109 policy
requirements, criticalities and own instruction units, including command text
and file/line metadata. Its reader hash is recorded inside it; its own hash is
in the fixture manifest. Tests also independently scan raw markdown for every
policy and all 16 target ranges. Tests never regenerate these expected values.

CISA SCuBA / ScubaGear uses CC0 1.0 Universal. The aad, powerplatform and
securitysuite headers identify portions adapted from Microsoft documentation
under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Original notices
and source links remain in the raw files; the generated index carries them as
metadata. The extracted snapshot removes markdown and joins code continuations,
as described in [the provenance record](../../../../docs/provenance/explainer-baselines.md).
TLP:CLEAR remains subject to copyright. Provided as is; no endorsement implied.

The raw fixture directory is also available to Part 4's independent baseline
parser. No live ScubaGear checkout is required to run the tests.
