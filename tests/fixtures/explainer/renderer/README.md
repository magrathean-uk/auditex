Renderer fixtures are small, independent pins. They do not stand in for the shipped resources under `configs/`, which the
tests read directly (there are no stored copies of the shipped baselines or collection).

- `catalogue-v391-fixture.json.gz`: the exact v3.9.1 cell catalogue from the spec (canonical JSON, gzip): inventory, closed
  text, the A1 two-code pairing, variable citations and three order exceptions.
- `source-step-pins.json.gz`: SHA-256 of canonical shown/full text arrays for every frozen S cell. These pin inherited
  remediation independently of generation.
- `fault-vectors.jsonl`: the two constructed malformed-lifetime vectors from the fault note. Tests render their expected
  records without depending on an interpreter's digit limit or executing the reference implementation.
- `provenance.json`: upstream hashes, fixture hashes (of the decompressed bytes), historical drop counts and the explicit
  shared-contract note.

Baseline extraction removes markdown and source URLs from customer prose, splits complete command lines and retains
relative file and line provenance. CISA's ScubaGear LICENSE is CC0 1.0 Universal; the aad, powerplatform and securitysuite
headers identify adapted Microsoft M365/Azure documentation under CC BY 4.0. The complete notices, Microsoft source licence
links, author attribution and statement of changes are carried in `configs/explainer-baselines.json` and copied into the
template metadata. TLP:CLEAR remains subject to copyright.

A1 governs both shared reasons: the fault adapter accepts only the exact A1 record (null cell), and the earlier cell named
after the reason code is rejected. `render_full` is outside the compact six-step schema.
