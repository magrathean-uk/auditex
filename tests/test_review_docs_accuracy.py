"""Docs accuracy review (lane docs-accuracy): each shipped doc statement checked against the code it describes.

Expected values come from the code and configs (profiles, presets, CLI parsers, collectors), never from the doc
itself, so a doc that drifts from the behaviour fails here.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _doc(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """The text with line breaks folded, so a phrase wrapped across lines still matches."""
    return re.sub(r"\s+", " ", text)


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation dropped except hyphens, spaces to hyphens."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(markdown: str) -> set[str]:
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        match = None if in_fence else re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match:
            slug = _slug(match.group(1))
            count = seen.get(slug, 0)
            anchors.add(slug if count == 0 else f"{slug}-{count}")
            seen[slug] = count + 1
    return anchors


# R148 ------------------------------------------------------------------------------------------------------------


def test_docs_index_anchors_resolve_and_explainer_is_not_planned():
    index = ROOT / "docs/index.md"
    broken = []
    for target in re.findall(r"\]\(([^)\s]+)\)", index.read_text(encoding="utf-8")):
        if "#" not in target or "://" in target:
            continue
        path, anchor = target.split("#", 1)
        page = index.parent / path if path else index
        if anchor not in _anchors(page.read_text(encoding="utf-8")):
            broken.append(target)
    assert not broken, f"docs/index.md links to missing anchors: {broken}"
    # The explainer ships and is wired into reports; the index must not call it planned.
    assert "planned explainer" not in _doc("docs/index.md").lower()


# R144 ------------------------------------------------------------------------------------------------------------


def test_security_policy_supports_the_released_minor():
    version = tomllib.loads(_doc("pyproject.toml"))["project"]["version"]
    minor = ".".join(version.split(".")[:2]) + ".x"
    policy = _doc(".github/SECURITY.md")
    rows = dict(re.findall(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", policy, re.MULTILINE))
    assert rows.get(minor) == "Yes", f"SECURITY.md must list {minor} as supported; rows: {rows}"
    supported = [name for name, answer in rows.items() if answer == "Yes"]
    assert supported == [minor], f"only the latest minor is supported, got {supported}"
    # Every upgrade hint names the supported minor, never an older one.
    hints = re.findall(r"upgrade to the latest ([0-9.]+x)", policy)
    assert hints and set(hints) == {minor}, hints


# R074 ------------------------------------------------------------------------------------------------------------

_NUMBER_WORDS = {5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten"}


def _section(markdown: str, heading: str) -> str:
    start = markdown.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    rest = markdown[start + len(heading):]
    end = re.search(rf"(?m)^#{{1,{level}}} ", rest)
    return rest[: end.start()] if end else rest


def test_admin_guide_teams_section_matches_the_collector_and_adapter():
    from auditex.scuba_adapters_teams import CERTIFICATE_AUTH_MARKER
    from azure_tenant_audit.collectors.teams_policy import APP_SETTINGS_OPERATION, TEAMS_OPERATIONS

    operations = len(TEAMS_OPERATIONS) + (APP_SETTINGS_OPERATION not in TEAMS_OPERATIONS)
    section = _flat(_section(_doc("docs/guides/admin-permission-guide.md"), "### Teams policy reads in app-only runs"))
    # Without a certificate token every operation the collector records is skipped.
    skipped_counts = re.findall(r"all (\w+) operations are `skipped`", section)
    assert skipped_counts == [_NUMBER_WORDS[operations]], f"collector skips {operations} operations: {skipped_counts}"
    assert APP_SETTINGS_OPERATION in section
    # The adapter supplies ScubaGear's certificate marker on the certificate skip and decides TEAMS 5.1-5.3.
    assert "no certificate marker is synthesised" not in section
    assert "TEAMS 5.1-5.3 remain not assessed" not in section
    (marker,) = CERTIFICATE_AUTH_MARKER
    assert marker in section


# R076 ------------------------------------------------------------------------------------------------------------


def _profiles_with(collector: str) -> list[str]:
    from azure_tenant_audit.profiles import PROFILES

    return [name for name, profile in PROFILES.items() if collector in profile.default_collectors]


def _presets_with(collector: str) -> list[str]:
    presets = json.loads(_doc("configs/collector-presets.json"))
    presets = presets.get("presets", presets)
    return [name for name, preset in presets.items() if collector in (preset.get("include") or [])]


def test_ai_assessment_guide_states_dns_posture_default_selection():
    profiles, presets = _profiles_with("dns_posture"), _presets_with("dns_posture")
    assert profiles and presets, "dns_posture is a default collector; this test would be vacuous otherwise"
    guide = _flat(_doc("docs/guides/ai-assessment.md"))
    assert "opt-in `dns_posture`" not in guide
    assert "`dns_posture` remains outside default collector sets" not in guide
    paragraph = guide[guide.index("**DNS evidence for EXO") :]
    paragraph = paragraph[: paragraph.index("The value-rule test vectors")]
    for name in [*profiles, *presets]:
        assert f"`{name}`" in paragraph, f"the DNS evidence paragraph must name `{name}`, which selects dns_posture"
    assert "--exclude dns_posture" in paragraph
    assert "setup-guide.md#default-exchange-and-public-dns-collection" in paragraph


def test_ai_assessment_guide_names_the_current_assessment_schema():
    from auditex.rule_assessment import SCHEMA_VERSION

    guide = _flat(_doc("docs/guides/ai-assessment.md"))
    sentence = guide[guide.index("the cell inventory and reason codes") :][:220]
    assert f"`{SCHEMA_VERSION}`" in sentence, sentence


# R147 ------------------------------------------------------------------------------------------------------------


def test_setup_guide_names_every_preset_that_drops_the_exchange_and_dns_defaults():
    presets = json.loads(_doc("configs/collector-presets.json"))
    presets = presets.get("presets", presets)
    dropping = [
        name for name, preset in presets.items()
        if not {"exchange_policy", "dns_posture"} & set(preset.get("include") or [])
    ]
    assert dropping, "no preset drops the defaults; the test would be vacuous"
    section = _flat(_section(_doc("docs/guides/setup-guide.md"), "## Default Exchange and public DNS collection"))
    opening = section[: section.index("A default run opens")]
    for name in dropping:
        assert f"`{name}`" in opening, f"setup guide must say the `{name}` preset omits exchange_policy and dns_posture"
    assert "Only an explicit `--collectors` list or the `config-only` and `power-platform` presets change that" not in opening


# R145 ------------------------------------------------------------------------------------------------------------


def test_reader_app_guide_says_app_readonly_full_needs_ediscovery():
    from azure_tenant_audit.profiles import PROFILES

    full = PROFILES["app-readonly-full"]
    assert "ediscovery" in full.default_collectors and "eDiscovery.Read.All" in full.app_escalation_permissions
    guide = _flat(_doc("docs/guides/reader-app-permissions.md"))
    optional = guide[guide.index("## Optional collectors") :]
    optional = optional[: optional.index("Related reading")]
    assert "A full audit does not use these collectors and does not need their permissions." not in optional
    assert "`app-readonly-full`" in optional, "the optional table must say app-readonly-full selects ediscovery"
    assert "eDiscovery.Read.All" in optional
    # setup-guide.md presents app-readonly-full as including the defaults: it must also say what it adds.
    setup = _flat(_section(_doc("docs/guides/setup-guide.md"), "## Default Exchange and public DNS collection"))
    extra = sorted(set(full.default_collectors) - set(PROFILES["global-reader"].default_collectors))
    for name in extra:
        assert f"`{name}`" in setup, f"setup guide must say app-readonly-full adds `{name}`"
    assert "eDiscovery.Read.All" in setup


# R146 ------------------------------------------------------------------------------------------------------------


def test_api_catalogue_lists_every_dns_posture_query_and_scopes_the_lookup_cap():
    from azure_tenant_audit.collectors.dns_posture import MAX_PUBLIC_LOOKUP_DOMAINS

    source = _doc("src/azure_tenant_audit/dns_lookup.py")
    body = source[source.index("def collect_domain_posture") :]
    prefixes = [p for p in re.findall(r'resolver\.query\(f"([^"{]*)\{domain\}"', body) if p]
    assert {"_dmarc.", "_mta-sts.", "default._bimi."} <= set(prefixes), prefixes
    catalogue = _flat(_doc("docs/reference/api-call-catalog.md"))
    for prefix in prefixes:
        assert f"TXT {prefix}<domain>" in catalogue, f"api-call-catalog.md has no dns_posture row for TXT {prefix}<domain>"
    # The cap applies to the OpenID discovery reads only; MTA-STS policy reads cover every eligible domain.
    assert f"for the audited tenant (at most {MAX_PUBLIC_LOOKUP_DOMAINS})" not in catalogue
    paragraph = catalogue[catalogue.index("Public HTTPS lookups target only domains") :][:900]
    assert f"first {MAX_PUBLIC_LOOKUP_DOMAINS}" in paragraph and "OpenID" in paragraph
    assert "MTA-STS" in paragraph and "every" in paragraph
