# License - auditex

## This Project

Auditex is open-source software released under the Apache License, Version 2.0.

> See `LICENSE` for the full Apache-2.0 licence text.
> Copyright 2026 Magrathean UK Ltd.

A machine-readable record of third-party components is maintained in
`THIRD_PARTY_NOTICES.md`. The summary below is derived from that file and from the
project's declared dependencies.

---

## Third-Party Dependencies

### Vendored component

| Component | License | Location |
|-----------|---------|----------|
| `microsoft/skills` (curated subset of SKILL.md files) | **MIT** | `tenant-bootstrap/vendor/microsoft-skills/` — licence at `tenant-bootstrap/vendor/microsoft-skills/LICENSE` |

### Python runtime — `pyproject.toml` / `requirements.txt`

| Package | License | Declared in |
|---------|---------|-------------|
| `requests` | Apache-2.0 | `pyproject.toml`, `requirements.txt` |
| `msal` | MIT | `pyproject.toml`, `requirements.txt` |
| `mcp` *(optional)* | MIT | `pyproject.toml` |

### Python build tooling — `pyproject.toml`

| Package | License | Declared in |
|---------|---------|-------------|
| `setuptools` | MIT | `pyproject.toml` |

### Tenant-bootstrap tooling — `tenant-bootstrap/requirements.txt`

| Package | License | Declared in |
|---------|---------|-------------|
| `requests` | Apache-2.0 | `tenant-bootstrap/requirements.txt` |
| `msal` | MIT | `tenant-bootstrap/requirements.txt` |

### Research references (no code retained)

The following upstream projects were studied for ideas. No source code, templates, or
documentation text was copied. Recorded in `THIRD_PARTY_NOTICES.md` for provenance.

| Project | License | Status |
|---------|---------|--------|
| `ThomasKur/M365Documentation` | GPLv3+ | Rewritten; no code retained |
| `System-Admins/m365assessment` | No visible licence | Rewritten; no code retained |
| `cisagov/ScubaGear` | CC0-1.0 | Idea-level only |
| `maester365/maester` | MIT | Idea-level only |
| `microsoft/EntraExporter` | MIT | Idea-level only |
| `dirkjanm/ROADtools` | MIT | Idea-level only |
| `CompliantSec/M365SAT` | MIT | Idea-level only |

---

## License Obligations Summary

| License | Action required |
|---------|----------------|
| Apache-2.0 (this project) | Retain licence and notice text when redistributing covered source or binaries; see `LICENSE` |
| MIT (vendored microsoft-skills) | Licence text retained at `tenant-bootstrap/vendor/microsoft-skills/LICENSE` |
| MIT (msal, mcp) | Retain copyright notice and licence text when redistributing bundled wheels |
| Apache-2.0 (requests) | Retain NOTICE file (if any) and licence text when redistributing bundled wheels |
