"""``model_assessment_prompts.jsonl`` is no longer written, but a bundle that carries it still validates."""
from __future__ import annotations

from pathlib import Path

from gate_support import offline_run

from azure_tenant_audit.bundle_integrity import (
    is_post_finalization_output,
    verify_bundle_hashes,
)

LEGACY = "model_assessment_prompts.jsonl"


def test_no_current_writer_names_the_prompts_file() -> None:
    root = Path(__file__).resolve().parents[1] / "src"
    assert not [p for p in root.rglob("*.py") if LEGACY in p.read_text(encoding="utf-8") and p.name != "bundle_integrity.py"]


def test_a_bundle_carrying_the_legacy_prompts_file_still_validates(tmp_path: Path) -> None:
    run = offline_run(tmp_path)
    assert is_post_finalization_output(LEGACY)
    (run / LEGACY).write_text('{"prompt": "x"}\n', encoding="utf-8")

    result = verify_bundle_hashes(run)

    assert result["status"] == "verified"
    assert LEGACY in result["unlisted"]
    assert result["unexpected"] == []


def test_an_unnamed_extra_file_at_the_same_place_is_still_unexpected(tmp_path: Path) -> None:
    run = offline_run(tmp_path)
    (run / "model_assessment_prompts_copy.jsonl").write_text("{}\n", encoding="utf-8")

    result = verify_bundle_hashes(run)

    assert result["status"] == "mismatch"
    assert result["unexpected"] == ["model_assessment_prompts_copy.jsonl"]
