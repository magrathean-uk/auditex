"""Area adapter registration uses synthetic modules and evidence only."""
import sys
from types import ModuleType

import pytest

from auditex import scuba_projection
from test_scuba_projection import EXPECTED, complete_bundle


def test_empty_area_modules_leave_projection_unchanged(complete_bundle, monkeypatch):
    assert scuba_projection.AREA_ADAPTER_MODULES == ()
    before = scuba_projection.project_run(complete_bundle, redact=False)

    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", ())
    after = scuba_projection.project_run(complete_bundle, redact=False)

    assert after == before
    assert after.report == before.report
    assert after.views == before.views
    assert after.rule_sections == before.rule_sections
    assert after.rule_views == before.rule_views
    for section, value in EXPECTED.items():
        assert after[section] == value


def test_area_adapter_is_used_for_its_section(complete_bundle, monkeypatch):
    module = ModuleType("test_area_adapter")
    expected = [{"Name": "Area adapter", "DomainName": "area.invalid"}]
    calls = []

    def adapter(bundle):
        calls.append(bundle)
        bundle.read("run-manifest.json")
        return expected

    module.ADAPTERS = {"accepted_domains": adapter}
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", (module.__name__,))

    projected = scuba_projection.project_run(complete_bundle, redact=False)

    assert len(calls) == 1
    assert isinstance(calls[0], scuba_projection.Bundle)
    assert projected["accepted_domains"] == expected
    assert projected.report["sections"]["accepted_domains"]["status"] == "projected"


def test_area_module_without_adapters_raises(complete_bundle, monkeypatch):
    module = ModuleType("test_area_missing_adapters")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", (module.__name__,))

    with pytest.raises(RuntimeError, match="test_area_missing_adapters.*has no ADAPTERS"):
        scuba_projection.project_run(complete_bundle)


def test_area_adapter_cannot_override_builtin(complete_bundle, monkeypatch):
    module = ModuleType("test_area_collision")
    module.ADAPTERS = {"SPO_tenant": lambda bundle: pytest.fail("Duplicate adapter was called")}
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", (module.__name__,))

    with pytest.raises(RuntimeError, match="test_area_collision.*duplicate adapter keys.*SPO_tenant"):
        scuba_projection.project_run(complete_bundle)
