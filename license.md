# Licensing

Auditex is distributed under the Apache License, Version 2.0. The complete,
controlling licence text is in [LICENSE](LICENSE). The package metadata in
`pyproject.toml` also declares `Apache-2.0` and includes that file in package
licence files.

Copyright 2026 Magrathean UK Ltd.

This page explains the repository layout. It does not alter the licence or add
terms.

## Third-party material

The repository retains a curated vendored subset of Microsoft Skills under
`tenant-bootstrap/vendor/microsoft-skills/`. Its MIT licence is kept with that
material. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) identifies it and
the declared Python dependencies, and records provenance-only references that
are not retained as code or text.

The optional `google` dependency group in `pyproject.toml` also declares
`google-auth`, `google-auth-oauthlib`, and `google-api-python-client`.
They are not currently listed in `THIRD_PARTY_NOTICES.md`. This refresh does
not infer their licence terms or add a notice without a dependency-specific
review.

Retain the notices and licences that apply to any redistributed components or
bundled dependencies. The root `LICENSE` is the only root licence text in the
reviewed tree; this document is not a replacement for it.

## Trademarks

[TRADEMARKS.md](TRADEMARKS.md) identifies the project and third-party marks
used in the repository and states the product's independence from Microsoft
and Google.

## Provenance

[docs/provenance/provenance.md](docs/provenance/provenance.md) and its CSV
companion record the project’s stated source-provenance review. They do not
replace a licence review for a new contribution or distribution.
