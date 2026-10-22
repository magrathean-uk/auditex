from __future__ import annotations

from pathlib import Path

from azure_tenant_audit.config import CollectorConfig, RunConfig
from azure_tenant_audit.profiles import get_profile


def test_selected_collectors_respects_include_exclude():
    config_path = Path("configs/collector-definitions.json")
    CollectorConfig.from_path(config_path)
    run = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        collectors=["identity", "security"],
        excluded_collectors=["security"],
        include_exchange=True,
        default_collectors=("identity", "security"),
    )
    available = ["identity", "security", "intune", "teams", "exchange"]
    selected = run.selected_collectors(available)
    assert selected == ["identity", "exchange"]


def test_selected_collectors_includes_exchange_only_when_explicitly_requested():
    cfg = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    profile = get_profile("global-reader")
    run_default = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        default_collectors=profile.default_collectors,
        include_exchange=False,
    )
    available = [name for name in cfg.default_order if cfg.collectors[name].enabled]
    available.append("exchange")
    selected_without_exchange = run_default.selected_collectors(available)
    assert "exchange" not in selected_without_exchange

    run_include_exchange = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        default_collectors=profile.default_collectors,
        include_exchange=True,
    )
    selected_with_exchange = run_include_exchange.selected_collectors(available)
    assert "exchange" in selected_with_exchange


def test_selected_collectors_prefers_explicit_over_profile_defaults():
    CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    run = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        collectors=["security"],
        default_collectors=("identity", "security", "exchange"),
    )
    selected = run.selected_collectors(["identity", "security", "exchange"])
    assert selected == ["security"]


def test_selected_collectors_uses_profile_defaults_when_no_collectors_set():
    cfg = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    available = [name for name in cfg.default_order if cfg.collectors[name].enabled]
    profile = get_profile("global-reader")
    run = RunConfig(
        tenant_name="test",
        output_dir=Path("/tmp"),
        default_collectors=profile.default_collectors,
    )
    selected = run.selected_collectors(available)
    assert selected == list(profile.default_collectors)
