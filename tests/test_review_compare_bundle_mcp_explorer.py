"""Review lane compare-bundle-mcp: the explorer's accessible labels make no assurance claim (legal item L3)."""

from __future__ import annotations

from pathlib import Path

EXPLORER = Path(__file__).resolve().parents[1] / "src" / "auditex" / "explorer_assets" / "explorer.html"


def test_the_explorer_run_list_is_labelled_run_checks_not_guarantees() -> None:
    html = EXPLORER.read_text(encoding="utf-8")

    assert 'aria-label="Run checks"' in html
    assert "guarantees" not in html.lower().replace("ax-guarantees", "")
