from __future__ import annotations

from pathlib import Path

import pytest

from auditex.guided import build_guided_parser
from auditex.operator_flow import (
    documented_operator_commands,
    flow_choices,
    flow_plan,
)

ROOT = Path(__file__).resolve().parents[1]


def test_operator_flow_module_owns_the_one_guided_flow() -> None:
    assert flow_choices() == ("auto", "app-audit")
    for flow_name in flow_choices():
        assert build_guided_parser().parse_args(["--flow", flow_name]).flow == flow_name


def test_auto_resolves_to_the_reader_app_flow_and_removed_flows_are_unknown() -> None:
    plan = flow_plan("auto")
    assert plan is flow_plan("app-audit")
    assert plan.requires_real_tenant is True
    for removed in ("gr-audit", "ga-setup-app"):
        with pytest.raises(ValueError, match="unknown operator flow"):
            flow_plan(removed)
        with pytest.raises(SystemExit):
            build_guided_parser().parse_args(["--flow", removed])


def test_operator_flow_renders_documented_commands() -> None:
    commands = documented_operator_commands()

    assert commands == ("auditex guided-run", "auditex guided-run --flow app-audit")
    for command in commands:
        args = build_guided_parser().parse_args(command.split()[2:])
        assert args.flow in flow_choices()


def test_operator_docs_use_module_commands() -> None:
    commands = documented_operator_commands()
    docs = "\n".join(
        [
            (ROOT / "README.md").read_text(encoding="utf-8"),
            (ROOT / "agent" / "agent-prompt.md").read_text(encoding="utf-8"),
        ]
    )

    for command in commands:
        assert command in docs

    prompt = (ROOT / "agent" / "agent-prompt.md").read_text(encoding="utf-8")
    assert "--certificate-path" in prompt and "--certificate-thumbprint" in prompt
    assert "docs/guides/reader-app-permissions.md" in prompt
    assert "--use-azure-cli-token" not in prompt
