from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

FlowName = Literal["app-audit"]


@dataclass(frozen=True)
class OperatorFlowPlan:
    """The guided run's one flow: the reader app with a certificate (DEC-107)."""

    name: FlowName
    prompt_label: str
    documented_command: tuple[str, ...]
    requires_real_tenant: bool = True

    def render_command(self) -> str:
        return " ".join(self.documented_command)


_GUIDED_COMMAND = ("auditex", "guided-run")

_FLOW_PLANS: tuple[OperatorFlowPlan, ...] = (
    OperatorFlowPlan(
        name="app-audit",
        prompt_label="Reader app audit (certificate)",
        documented_command=(*_GUIDED_COMMAND, "--flow", "app-audit"),
    ),
)

_FLOW_BY_NAME = {plan.name: plan for plan in _FLOW_PLANS}


def flow_choices() -> tuple[str, ...]:
    return ("auto", *tuple(plan.name for plan in _FLOW_PLANS))


def flow_plan(name: str) -> OperatorFlowPlan:
    plan = _FLOW_BY_NAME.get("app-audit" if name == "auto" else name)
    if plan is None:
        raise ValueError(f"unknown operator flow: {name}")
    return plan


def documented_operator_commands() -> tuple[str, ...]:
    return (" ".join(_GUIDED_COMMAND), *tuple(plan.render_command() for plan in _FLOW_PLANS))
