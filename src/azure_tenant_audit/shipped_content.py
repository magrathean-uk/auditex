from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ShippedContentArea:
    name: str
    directory: str
    package_target: str
    package_patterns: tuple[str, ...]
    release_label: str


SHIPPED_CONTENT_AREAS: tuple[ShippedContentArea, ...] = (
    ShippedContentArea("configs", "configs", "auditex/configs", ("configs/*.json",), "configs under `configs/`"),
    ShippedContentArea("assets", "assets", "auditex/assets", ("assets/*",), "product assets under `assets/`"),
    ShippedContentArea("profiles", "profiles", "auditex/profiles", ("profiles/*.md",), "profiles under `profiles/`"),
    ShippedContentArea("schemas", "schemas", "auditex/schemas", ("schemas/*.json",), "schemas under `schemas/`"),
    ShippedContentArea(
        "docs_improvement",
        "docs/improvement",
        "auditex/docs/improvement",
        ("docs/improvement/*.md",),
        "product docs under `docs/`",
    ),
    ShippedContentArea(
        "docs_provenance",
        "docs/provenance",
        "auditex/docs/provenance",
        ("docs/provenance/*.md", "docs/provenance/*.csv"),
        "provenance docs under `docs/provenance/`",
    ),
    ShippedContentArea("docs", "docs", "auditex/docs", ("docs/*.md",), "product docs under `docs/`"),
    ShippedContentArea("agent", "agent", "auditex/agent", ("agent/*.md", "agent/*.json"), "agent prompts under `agent/`"),
    ShippedContentArea(
        "skills_app_readonly_escalation",
        "skills/app-readonly-escalation",
        "auditex/skills/app-readonly-escalation",
        ("skills/app-readonly-escalation/SKILL.md",),
        "skills under `skills/`",
    ),
    ShippedContentArea(
        "skills_auditex_operator",
        "skills/auditex-operator",
        "auditex/skills/auditex-operator",
        ("skills/auditex-operator/SKILL.md",),
        "skills under `skills/`",
    ),
    ShippedContentArea(
        "skills_delegated_auth",
        "skills/delegated-auth",
        "auditex/skills/delegated-auth",
        ("skills/delegated-auth/SKILL.md",),
        "skills under `skills/`",
    ),
    ShippedContentArea(
        "skills_evidence_pack",
        "skills/evidence-pack",
        "auditex/skills/evidence-pack",
        ("skills/evidence-pack/SKILL.md",),
        "skills under `skills/`",
    ),
    ShippedContentArea(
        "sample_bundle",
        "examples/sample_audit_bundle",
        "auditex/examples/sample_audit_bundle",
        ("examples/sample_audit_bundle/*.json",),
        "sample bundle under `examples/sample_audit_bundle/`",
    ),
    ShippedContentArea(
        "google_workspace_sample",
        "examples",
        "auditex/examples",
        ("examples/google_workspace_sample.json",),
        "Google Workspace sample under `examples/`",
    ),
)


def shipped_directories() -> tuple[str, ...]:
    return tuple(area.directory for area in SHIPPED_CONTENT_AREAS)


def data_file_manifest() -> dict[str, list[str]]:
    return {area.package_target: list(area.package_patterns) for area in SHIPPED_CONTENT_AREAS}


def release_content_labels() -> tuple[str, ...]:
    labels = []
    seen: set[str] = set()
    for area in SHIPPED_CONTENT_AREAS:
        if area.release_label not in seen:
            labels.append(area.release_label)
            seen.add(area.release_label)
    return tuple(labels)


def area_for_path(path: str | Path) -> ShippedContentArea | None:
    text = Path(path).as_posix()
    for area in SHIPPED_CONTENT_AREAS:
        directory = area.directory.rstrip("/")
        if text == directory or text.startswith(f"{directory}/"):
            return area
    return None
