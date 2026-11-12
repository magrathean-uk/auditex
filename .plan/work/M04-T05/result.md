## RESULT M04-T05
status: done
summary: security-privacy.md now describes the keyed scheme, key sources, key modes, masking boundary (T04 limits), oracle boundary and the design section 17 limits. The salt and confirm-a-guess text is gone. CHANGELOG has one entry under `[Unreleased]`, the manual has one `prepare-key` line, and the adapter key lines match `scubagear_export.py`.
changes: docs/reference/security-privacy.md, CHANGELOG.md, docs/guides/product-manual.md, docs/development/scubagear-export-adapter.md
verification: verify greps PASS (`result.md` read from the main checkout copy); make lint PASS; tests/test_docs_paths.py, tests/test_mcp_registry.py, tests/test_redaction_profiles_d3.py PASS (no make test)
risks: masking-boundary text follows task/M04-T04-name-masking@0adcc49 and needs a touch-up if the Codex review changes it; design limit L5 (pair writer against `.gitignore`) is not documented because I could not verify it; same-vendor review only
questions_for_g: none
### Findings
read-through: complete
masking-boundary-source: task/M04-T04-name-masking@0adcc49
1 I checked the limits against the code, not the notes, by probing the 0adcc49 matcher in a scratch copy. One or two middle initials, listed titles and `john.a.smith.adm` are masked. `A. Smith`, `Smith, Dr. John`, `Smith, John A.` and `John A. B. C. D. Smith` (beside a four-initial sign-in path) stay readable. A bare `Jane Doe` also stays readable when only `Capt. Jane Doe` is recorded, and the unmatched note is empty. The brief's "two middle initials beside many similar sign-in names" did not reproduce, so I documented the window limit with the four-initial example.
2 I reworded the vocabulary description. The `vocabulary` row now includes a product field name. A new limit says a person named `Break Glass` keeps the key `break_glass`, is counted as vocabulary, and is still masked in values and free text. The note's own fixed wording ("left as written") is in `output_redaction.py` and is unchanged.
3 Survivors of the removed terms: "salt" remains only as "no salt" and as the 1.4.0 reader limit. The 1.4.0 CHANGELOG section keeps its historical "run-path salt".
