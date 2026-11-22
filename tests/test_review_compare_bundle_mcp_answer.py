"""Review lane compare-bundle-mcp: the local answer: catalogue coverage and model licences (R096, L5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

# R096: catalogue coverage of the local answer


def _assessment_row(policy_id: str, met: bool) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "claims": [
            {"id": "requirement_met", "status": "confirmed", "value": met, "evidence_ids": ["e0"]},
            {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]},
        ],
        "limitations": [], "recommendations": [], "reason": "rule_precheck", "validation_status": "valid",
        "rule_precheck": {"class": "value_rule", "rule_id": f"{policy_id}.rule", "section": ["s"], "field": None,
                          "value": None, "cell": "c", "reason_code": "code", "reason_text": f"Reason for {policy_id}."},
    }


def _answer_for(policy_ids: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    from auditex import local_answer as la
    from auditex.answer_digest import digest_from_assessment

    digest = digest_from_assessment({"run_id": "synthetic", "policies": [_assessment_row(pid, True) for pid in policy_ids]})
    answer = la.assemble_answer(digest, {}, None, model=None, runtime=None, reason="runtime_missing")
    return digest, answer


def test_an_answer_over_part_of_the_catalogue_says_how_much_was_assessed() -> None:
    from azure_tenant_audit.value_rules.catalogue import catalogue

    total = len(catalogue()["policies"])
    digest, answer = _answer_for(["MS.AAD.8.1v1", "MS.AAD.7.1v1", "MS.AAD.2.1v1"])

    assert digest["catalogue"] == {"policies": total, "assessed": 3}
    assert f"Partial: the rules assessed 3 of the {total} SCuBA checks in the shipped catalogue" in answer["text"]


def test_the_structured_run_summary_also_says_the_answer_is_partial() -> None:
    # Repair round 1 (R096): a caller that reads only summary.text sees the catalogue denominator too.
    from azure_tenant_audit.value_rules.catalogue import catalogue

    total = len(catalogue()["policies"])
    _, answer = _answer_for(["MS.AAD.8.1v1", "MS.AAD.7.1v1", "MS.AAD.2.1v1"])

    note = f"Partial: the rules assessed 3 of the {total} SCuBA checks in the shipped catalogue"
    assert answer["summary"]["text"].startswith(note)
    assert answer["text"].count(note) == 1


def test_a_stored_summary_without_the_partial_note_fails_its_check_against_the_run() -> None:
    from auditex import local_answer as la

    digest, answer = _answer_for(["MS.AAD.8.1v1"])
    kept = [line for line in answer["summary"]["text"].split("\n") if not line.startswith("Partial:")]
    stored = {**answer, "summary": {**answer["summary"], "text": "\n".join(kept)}}

    with pytest.raises(la.LocalAnswerError):
        la.verify_answer(stored, digest)


def test_a_stored_answer_without_the_partial_note_fails_its_check_against_the_run() -> None:
    import pytest as _pytest

    from auditex import local_answer as la

    digest, answer = _answer_for(["MS.AAD.8.1v1"])
    stored = dict(answer)
    stored["text"] = "\n".join(line for line in answer["text"].split("\n") if not line.startswith("Partial:"))

    with _pytest.raises(la.LocalAnswerError):
        la.verify_answer(stored, digest)


def test_an_answer_over_the_whole_catalogue_carries_no_partial_note() -> None:
    from azure_tenant_audit.value_rules.catalogue import catalogue

    _, answer = _answer_for(sorted(catalogue()["policies"]))

    assert "Partial:" not in answer["text"]


# L5: model licences


def test_every_pinned_model_names_its_licence_and_the_download_notice_states_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import dataclasses
    import hashlib

    import requests

    from auditex import local_answer as la

    assert "licence" not in {field.name for field in dataclasses.fields(la.ModelSpec) if field.default is not dataclasses.MISSING}
    assert all(spec.licence for spec in la.MODELS.values())
    data = b"pretend gguf"
    spec = dataclasses.replace(la.MODELS["mistral"], size=len(data), sha256=hashlib.sha256(data).hexdigest())

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def raise_for_status(self) -> None:
            return None

        def iter_content(self, chunk_size: int = 0):
            yield data

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: Response())
    lines: list[str] = []
    la.fetch_model(spec, tmp_path / spec.file, progress=lines.append)

    assert f"licensed by its publisher under {spec.licence}; one time only, then Auditex answers offline." in lines[0]


def _model_answer() -> tuple[dict[str, Any], dict[str, Any]]:
    from auditex import local_answer as la
    from auditex.answer_digest import digest_from_assessment

    digest = digest_from_assessment({"run_id": "synthetic", "policies": [_assessment_row("MS.AAD.8.1v1", True)]})
    answer = la.assemble_answer(digest, {}, None, model=la.MODELS["mistral"], runtime=la.RUNTIME_VERSION, reason=None)
    return digest, answer


def test_a_saved_model_answer_records_the_models_licence_and_passes_its_schema() -> None:
    # Repair round 1 (L5): the licence is written into the answer record, not only the download notice.
    from auditex import local_answer as la

    digest, answer = _model_answer()

    assert answer["model"]["licence"] == la.MODELS["mistral"].licence
    la.validate_answer(answer)
    assert la.verify_answer(answer, digest)["model"]["licence"] == la.MODELS["mistral"].licence


def test_a_saved_model_answer_without_a_licence_asks_for_a_new_answer() -> None:
    from auditex import local_answer as la

    digest, answer = _model_answer()
    stored = {**answer, "model": {key: value for key, value in answer["model"].items() if key != "licence"}}

    with pytest.raises(la.LocalAnswerError, match="another Auditex version"):
        la.verify_answer(stored, digest)
