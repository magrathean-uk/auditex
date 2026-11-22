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
