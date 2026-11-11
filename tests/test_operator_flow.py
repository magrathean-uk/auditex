from __future__ import annotations

from pathlib import Path

from auditex.guided import build_guided_parser
from auditex.operator_flow import (
    documented_operator_commands,
    flow_choices,
    flow_plan,
    guided_choice_options,
    resolve_auto_flow,
)

ROOT = Path(__file__).resolve().parents[1]


def test_operator_flow_module_owns_guided_mode_names() -> None:
    assert flow_choices() == ("auto", "gr-audit", "ga-setup-app", "app-audit")
    assert guided_choice_options() == (
        ("gr-audit", "GR audit"),
        ("ga-setup-app", "GA one-time app setup"),
        ("app-audit", "App audit"),
    )

    for flow_name in flow_choices():
        assert build_guided_parser().parse_args(["--flow", flow_name]).flow == flow_name


def test_operator_flow_plans_capture_run_behavior() -> None:
    gr_plan = flow_plan("gr-audit")
    app_plan = flow_plan("app-audit")
    setup_plan = flow_plan("ga-setup-app")

    assert gr_plan.auth_mode == "delegated"
    assert gr_plan.tenant_default == "organizations"
    assert gr_plan.requires_real_tenant is False
    assert gr_plan.requires_app_credentials is False

    assert app_plan.auth_mode == "app"
    assert app_plan.requires_real_tenant is True
    assert app_plan.requires_app_credentials is True

    assert setup_plan.include_exchange is True
    assert setup_plan.requires_real_tenant is True


def test_operator_flow_renders_documented_commands() -> None:
    commands = documented_operator_commands()

    assert commands == (
        "auditex guided-run",
        "auditex guided-run --flow gr-audit --include-exchange",
        "auditex guided-run --flow ga-setup-app",
        "auditex guided-run --flow app-audit",
    )

    for command in commands[1:]:
        args = build_guided_parser().parse_args(command.split()[2:])
        assert args.flow in flow_choices()


def test_operator_docs_and_skill_use_module_commands() -> None:
    commands = documented_operator_commands()
    docs = "\n".join(
        [
            (ROOT / "README.md").read_text(encoding="utf-8"),
            (ROOT / "agent" / "agent-prompt.md").read_text(encoding="utf-8"),
            (ROOT / "skills" / "delegated-auth" / "SKILL.md").read_text(encoding="utf-8"),
        ]
    )

    for command in commands:
        assert command in docs

    assert "auditex run --tenant-name <label> --tenant-id <tenant> --use-azure-cli-token" in docs


def test_auto_flow_resolution_is_centralized() -> None:
    assert resolve_auto_flow(auth_mode="delegated", non_interactive=True) == "gr-audit"
    assert resolve_auto_flow(auth_mode="app", non_interactive=True) == "app-audit"
    assert resolve_auto_flow(auth_mode="app", non_interactive=False) is None
