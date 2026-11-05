"""Area adapter registration uses synthetic modules and evidence only."""
from hashlib import sha256
import json
import sys
from types import ModuleType

import pytest

from auditex import scuba_projection
from auditex.model_serving import canonical
from test_scuba_projection import EXPECTED, complete_bundle


def register_modules(monkeypatch, *modules):
    for module in modules:
        monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", tuple(m.__name__ for m in modules))


@pytest.mark.parametrize("redact", [False, True])
def test_empty_area_modules_leave_projection_unchanged(complete_bundle, monkeypatch, redact):
    # Golden output re-pinned at the rebase onto main da9d06c (sharing_policy is no longer withheld unconditionally there), originally from b41cb97: in a scratch subprocess, AST-replace the sole
    # `for name in AREA_ADAPTER_MODULES` iterator with (), then project complete_bundle
    # with each redaction mode. Hash canonical([dict(result), report, views, rule_sections,
    # rule_views]). This freezes the hook-disabled output, including private rule inputs,
    # without depending on Git history or comparing the implementation with itself.
    expected = {
        False: 'c6fb3e1976f02e018beed37452f9c60ec64d486b84c2dcd3a69af98a320e69c6',
        True: 'c21cf938c6a67ba6fe585cd6d38156a94534d73f6ae0624a6560123e0504732f',
    }
    monkeypatch.setattr(scuba_projection, "AREA_ADAPTER_MODULES", ())
    after = scuba_projection.project_run(complete_bundle, redact=redact)

    output = [dict(after), after.report, after.views, after.rule_sections, after.rule_views]
    assert sha256(canonical(output).encode()).hexdigest() == expected[redact]
    if not redact:
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

    module.ADAPTERS = {"remote_domains": adapter}
    register_modules(monkeypatch, module)

    projected = scuba_projection.project_run(complete_bundle, redact=False)

    assert len(calls) == 1
    assert isinstance(calls[0], scuba_projection.Bundle)
    assert projected.rule_sections["remote_domains"] == expected
    assert projected.report["sections"]["remote_domains"]["source"] == ["run-manifest.json"]


@pytest.mark.parametrize("redact", [False, True])
def test_unseen_area_shape_reaches_rules_but_is_withheld_from_model(complete_bundle, monkeypatch, redact):
    before = scuba_projection.project_run(complete_bundle, redact=redact)
    module = ModuleType("test_area_unseen_shape")
    expected = [{"AreaContact": "synthetic.person@area.invalid"}]
    module.ADAPTERS = {"remote_domains": lambda bundle: expected}
    register_modules(monkeypatch, module)
    monkeypatch.delitem(scuba_projection.PACK_SHAPE_DIGESTS, "remote_domains", raising=False)

    projected = scuba_projection.project_run(complete_bundle, redact=redact)

    assert projected.rule_sections["remote_domains"] == expected
    catalogue = json.loads(scuba_projection.open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    readers = [pid for pid, policy in catalogue.items() if "remote_domains" in policy["sections"]]
    assert readers
    for policy_id in readers:
        assert scuba_projection.rule_policy_section(projected, policy_id, "remote_domains") == expected
        assert scuba_projection.policy_section(projected, policy_id, "remote_domains") == scuba_projection.NOT_COLLECTED
    # Only scuba_config has policy-specific rule_views; area sections use rule_sections via the reader above.
    assert projected.rule_views == before.rule_views
    assert projected.rule_views
    for policy_id, views in projected.rule_views.items():
        assert set(views) == {"scuba_config"}
        assert scuba_projection.rule_policy_section(projected, policy_id, "scuba_config") == views["scuba_config"]
    assert projected["remote_domains"] == scuba_projection.NOT_COLLECTED
    detail = projected.report["sections"]["remote_domains"]
    assert detail["status"] == "not_collected"
    assert detail["reason"] == "incomplete_shape"
    assert detail["detail"] == {"field": "$", "kind": "unseen_shape"}


def test_all_unadapted_catalogue_sections_are_accepted(complete_bundle, monkeypatch):
    catalogue = json.loads(scuba_projection.open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    sections = {section for policy in catalogue.values() for section in policy["sections"]}
    builtins = {"SPO_tenant", "conditional_access_policies", "authorization_policies", "service_plans",
                "privileged_users", "privileged_roles", "sharing_policy", "scuba_config", "tenant_id",
                "dmarc_records", "spf_records", "dkim_records"} | scuba_projection.PS_SECTIONS.keys()
    area_sections = sections - builtins
    assert {"remote_domains", "transport_rule", "tenant_app_settings", "anti_malware_policies",
            "powerbi_tenant_settings", "environment_creation"} <= area_sections
    module = ModuleType("test_area_catalogue")
    module.ADAPTERS = {section: lambda bundle, key=section: [{"Area": key}] for section in area_sections}
    register_modules(monkeypatch, module)

    projected = scuba_projection.project_run(complete_bundle)

    for section in area_sections:
        assert projected.rule_sections[section] == [{"Area": section}]


def test_area_module_without_adapters_raises(complete_bundle, monkeypatch):
    module = ModuleType("test_area_missing_adapters")
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match="test_area_missing_adapters.*has no ADAPTERS"):
        scuba_projection.project_run(complete_bundle)


@pytest.mark.parametrize("section", ["SPO_tenant", *scuba_projection.PS_SECTIONS,
                                     "dmarc_records", "spf_records", "dkim_records"])
def test_area_adapter_cannot_override_builtin(complete_bundle, monkeypatch, section):
    module = ModuleType("test_area_collision")
    module.ADAPTERS = {section: lambda bundle: pytest.fail("Duplicate adapter was called")}
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match=f"test_area_collision.*duplicate adapter keys.*{section}"):
        scuba_projection.project_run(complete_bundle)


def test_area_adapters_cannot_override_each_other(complete_bundle, monkeypatch):
    first = ModuleType("test_area_first")
    second = ModuleType("test_area_second")
    for module in (first, second):
        module.ADAPTERS = {"remote_domains": lambda bundle: pytest.fail("Duplicate adapter was called")}
    register_modules(monkeypatch, first, second)

    with pytest.raises(RuntimeError, match="test_area_second.*duplicate adapter keys.*remote_domains"):
        scuba_projection.project_run(complete_bundle)


@pytest.mark.parametrize("adapters", [[], None, ("remote_domains",)])
def test_adapters_must_be_a_dict(complete_bundle, monkeypatch, adapters):
    module = ModuleType("test_area_invalid_mapping")
    module.ADAPTERS = adapters
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match="test_area_invalid_mapping.*ADAPTERS must be a dict"):
        scuba_projection.project_run(complete_bundle)


def test_adapter_must_be_callable(complete_bundle, monkeypatch):
    module = ModuleType("test_area_non_callable")
    module.ADAPTERS = {"remote_domains": 5}
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match="test_area_non_callable.*non-callable.*remote_domains"):
        scuba_projection.project_run(complete_bundle)


@pytest.mark.parametrize("section", ["scuba_config", "tenant_id"])
def test_reserved_adapter_key_is_rejected(complete_bundle, monkeypatch, section):
    module = ModuleType("test_area_reserved")
    module.ADAPTERS = {section: lambda bundle: pytest.fail("Reserved adapter was called")}
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match=f"test_area_reserved.*reserved adapter key.*{section}"):
        scuba_projection.project_run(complete_bundle)


@pytest.mark.parametrize("section", ["not_a_section", "remote_domians", 123])
def test_unknown_adapter_key_is_rejected(complete_bundle, monkeypatch, section):
    module = ModuleType("test_area_unknown")
    module.ADAPTERS = {section: lambda bundle: pytest.fail("Unknown adapter was called")}
    register_modules(monkeypatch, module)

    with pytest.raises(RuntimeError, match=f"test_area_unknown.*unknown adapter key.*{section}"):
        scuba_projection.project_run(complete_bundle)
