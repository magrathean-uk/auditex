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


# R127 ------------------------------------------------------------------------------------------------------------


def test_product_manual_sends_client_output_through_the_shareable_route(monkeypatch):
    import auditex.cli as cli
    import auditex.exporters as exporters
    import auditex.reporting as reporting
    from azure_tenant_audit.output_redaction import PROFILE_LOCAL, PROFILE_SHAREABLE

    seen: dict[str, object] = {}

    def capture(**kwargs):
        seen["profile"] = kwargs["profile"]
        return {"output_path": "x"}

    monkeypatch.setattr(reporting, "render_report", capture)
    cli.render_report(run_dir="r", format_name="html")
    assert seen["profile"] == PROFILE_LOCAL
    monkeypatch.setattr(exporters, "render_report", capture)
    exporters.run_exporter(name="html", run_dir="r")
    assert seen["profile"] == PROFILE_SHAREABLE

    section = _section(_doc("docs/guides/product-manual.md"), "## Render Reports")
    for line in section.splitlines():
        if line.startswith("auditex report render"):
            assert "client" not in line, f"report render is the unredacted local view, not client output: {line}"
    assert re.search(r"(?m)^auditex export run html <run-dir> --output \S*client", section)
    flat = _flat(section)
    assert "`auditex report render`" in flat and "local" in flat and "unredacted" in flat


# R128 ------------------------------------------------------------------------------------------------------------


def _notify_sinks() -> tuple[str, ...]:
    import argparse

    from auditex.cli import _build_notify_parser

    parser = _build_notify_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    send = sub.choices["send"]
    return tuple(next(a for a in send._actions if "--sink" in a.option_strings).choices)


def test_every_notification_sink_its_settings_and_calls_are_documented():
    sinks = _notify_sinks()
    assert {"smtp", "jira", "github"} <= set(sinks)
    source = _doc("src/auditex/notify.py")
    env_vars = sorted(set(re.findall(r'"(AUDITEX_[A-Z_]+)"', source)))
    paths = sorted(set(re.findall(r"(/rest/api/3/[a-z/]+|/search/issues|/comments|/issues)\"", source)))
    assert env_vars and paths
    privacy = _flat(_doc("docs/reference/security-privacy.md"))
    section = privacy[privacy.index("## Notifications") :]
    section = section[: section.index(" ## ")] if " ## " in section else section
    for sink in sinks:
        assert f"`{sink}`" in section, f"security-privacy.md notifications section must name the {sink} sink"
    for name in env_vars:
        assert f"`{name}`" in section, f"security-privacy.md must document {name}"
    for path in paths:
        assert path in section, f"security-privacy.md must list the {path} call"
    assert "public" in section and "TLS" in section
    manual = _flat(_section(_doc("docs/guides/product-manual.md"), "## Notifications"))
    for sink in sinks:
        assert f"`{sink}`" in manual, f"product-manual.md must name the {sink} sink"
    assert "security-privacy.md#notifications" in manual


# R166 ------------------------------------------------------------------------------------------------------------


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).hostname or ""


def test_security_reference_lists_the_real_processes_and_outbound_destinations():
    from auditex.local_answer import HUB
    from azure_tenant_audit.adapters.teams_admin_rest import TEAMS_ADMIN_BASE
    from azure_tenant_audit.collectors.exchange_policy import EXCHANGE_ONLINE_SCOPE
    from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT
    from azure_tenant_audit.graph import GRAPH_ROOT
    from azure_tenant_audit.power_bi import POWERBI_ROOT
    from azure_tenant_audit.power_platform import POWER_PLATFORM_ROOT

    # No code path starts the Azure CLI, so the reference must not say the probe does.
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))
    assert not re.search(r"""\[\s*["']az["']""", sources), "src starts az after all; revisit this test"
    privacy = _flat(_doc("docs/reference/security-privacy.md"))
    assert "start `pwsh` or `az`" not in privacy
    section = privacy[privacy.index("## Outbound destinations") :]
    section = section[: section.index(" ## ", 5)] if " ## " in section[5:] else section
    hosts = {
        _host(GRAPH_ROOT),
        "login.microsoftonline.com",
        _host(EXCHANGE_ONLINE_SCOPE),
        "ps.compliance.protection.outlook.com",
        *(_host(url) for url in TEAMS_ADMIN_BASE.values()),
        _host(POWERBI_ROOT),
        _host(POWER_PLATFORM_ROOT),
        _host(DEFAULT_DOH_ENDPOINT),
        "www.googleapis.com",
        _host(HUB),
    }
    for host in sorted(hosts):
        assert host in section, f"security-privacy.md outbound destinations must list {host}"
    for marker in ("mta-sts.<domain>", "-admin.sharepoint.com", "--sink", "AUDITEX_DOH_ENDPOINT"):
        assert marker in section, marker


# R083 / R164 -----------------------------------------------------------------------------------------------------


def test_doh_resolver_choice_is_disclosed_for_m365_and_google():
    from auditex.google_workspace.run import PRESETS
    from azure_tenant_audit.cli import build_parser
    from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DOH_ENDPOINT_ENV

    assert any("--doh-endpoint" in action.option_strings for action in build_parser()._actions)
    google_presets = [name for name, selected in PRESETS.items() if "google_dns_posture" in selected]
    assert google_presets
    privacy = _flat(_doc("docs/reference/security-privacy.md"))
    lookups = privacy[privacy.index("## External lookups") :]
    lookups = lookups[: lookups.index(" ## ", 5)]
    catalogue = _flat(_doc("docs/reference/api-call-catalog.md"))
    for name, text in (("security-privacy.md External lookups", lookups), ("api-call-catalog.md", catalogue)):
        for needle in (DOH_ENDPOINT_ENV, "--doh-endpoint", DEFAULT_DOH_ENDPOINT, "google_dns_posture"):
            assert needle in text, f"{name} must disclose {needle}"
    for preset in google_presets:
        assert f"`{preset}`" in lookups, f"External lookups must name the Google `{preset}` preset"
    assert "--exclude google_dns_posture" in lookups and "`dns_resolver`" in lookups
    assert re.search(r"\| `google_dns_posture` \| DoH ", catalogue), "api-call-catalog.md needs a google_dns_posture row"


# L6 --------------------------------------------------------------------------------------------------------------


def test_setup_guide_names_the_google_dns_notice_and_how_to_turn_it_off():
    from auditex.google_workspace.run import PRESETS
    from azure_tenant_audit.dns_lookup import DOH_ENDPOINT_ENV

    google = _flat(_section(_doc("docs/guides/setup-guide.md"), "## Google Workspace"))
    for preset, selected in PRESETS.items():
        if "google_dns_posture" in selected:
            assert f"`{preset}`" in google, f"setup guide must say the `{preset}` preset sends domain names to DoH"
    assert "--exclude google_dns_posture" in google and DOH_ENDPOINT_ENV in google
    # The Microsoft 365 notice names the configurable resolver, not Cloudflare alone.
    m365 = _flat(_section(_doc("docs/guides/setup-guide.md"), "## Default Exchange and public DNS collection"))
    assert DOH_ENDPOINT_ENV in m365 and "--doh-endpoint" in m365
