"""Demo console metadata cannot precede the transient target-list boundary."""
from __future__ import annotations

import io
import json

import pytest

from auditex import demo


CANARY = "zq-canary@unlisted-canary.invalid"


@pytest.mark.parametrize("provenance", [
    {"fixture_id": json.dumps({"TargetedUsersToProtect": [CANARY]})},
    {"fixture_id": CANARY, "TargetedUsersToProtect": [CANARY]},
    {"fixture_id": CANARY, "detail": {"TargetedUsersToProtect": [CANARY]}},
])
def test_demo_header_uses_only_sanitised_fixture_metadata(tmp_path, monkeypatch, provenance):
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"_fixture_provenance": provenance}))
    original = sample.read_bytes()
    stream = io.StringIO()
    monkeypatch.setattr(demo, "_step_plan", lambda console: None)
    monkeypatch.setattr(demo, "_step_run", lambda *args: None)
    assert demo.run_demo(demo.DemoOptions(out_dir=tmp_path / "demo", sample=sample,
                                         pause=False, html=False, stream=stream)) == 1
    assert CANARY not in stream.getvalue()
    assert "TargetedUsersToProtect" not in stream.getvalue()
    assert sample.read_bytes() == original


def test_demo_header_keeps_safe_fixture_metadata(tmp_path, monkeypatch):
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"_fixture_provenance": {"fixture_id": "safe-synthetic-fixture"}}))
    stream = io.StringIO()
    monkeypatch.setattr(demo, "_step_plan", lambda console: None)
    monkeypatch.setattr(demo, "_step_run", lambda *args: None)
    demo.run_demo(demo.DemoOptions(out_dir=tmp_path / "demo", sample=sample,
                                   pause=False, html=False, stream=stream))
    assert "fixture safe-synthetic-fixture" in stream.getvalue()


def test_demo_header_minimises_target_bearing_organisation_before_printing(tmp_path, monkeypatch):
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"identity": {"organization": {"value": [
        {"displayName": CANARY, "TargetedUsersToProtect": [CANARY]}
    ]}}}))
    original = sample.read_bytes()
    stream = io.StringIO()
    monkeypatch.setattr(demo, "_step_plan", lambda console: None)
    monkeypatch.setattr(demo, "_step_run", lambda *args: None)
    demo.run_demo(demo.DemoOptions(out_dir=tmp_path / "demo", sample=sample,
                                   pause=False, html=False, stream=stream))
    assert CANARY not in stream.getvalue()
    assert sample.read_bytes() == original
