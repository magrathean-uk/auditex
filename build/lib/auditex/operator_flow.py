from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


AuthMode = Literal["delegated", "app"]
FlowName = Literal["gr-audit", "ga-setup-app", "app-audit"]


@dataclass(frozen=True)
class OperatorFlowPlan:
    name: FlowName
    prompt_label: str
    auth_mode: AuthMode
    documented_command: tuple[str, ...]
    include_exchange: bool = False
    requires_real_tenant: bool = False
    requires_app_credentials: bool = False
    tenant_default: str | None = None

    def render_command(self) -> str:
        return " ".join(self.documented_command)


_GUIDED_COMMAND = ("auditex", "guided-run")

_FLOW_PLANS: tuple[OperatorFlowPlan, ...] = (
    OperatorFlowPlan(
        name="gr-audit",
        prompt_label="GR audit",
        auth_mode="delegated",
        documented_command=(*_GUIDED_COMMAND, "--flow", "gr-audit", "--include-exchange"),
        tenant_default="organizations",
    ),
    OperatorFlowPlan(
        name="ga-setup-app",
        prompt_label="GA one-time app setup",
        auth_mode="delegated",
        documented_command=(*_GUIDED_COMMAND, "--flow", "ga-setup-app"),
        include_exchange=True,
        requires_real_tenant=True,
    ),
    OperatorFlowPlan(
        name="app-audit",
        prompt_label="App audit",
        auth_mode="app",
        documented_command=(*_GUIDED_COMMAND, "--flow", "app-audit"),
        requires_real_tenant=True,
        requires_app_credentials=True,
    ),
)

_FLOW_BY_NAME = {plan.name: plan for plan in _FLOW_PLANS}


def flow_choices() -> tuple[str, ...]:
    return ("auto", *tuple(plan.name for plan in _FLOW_PLANS))


def guided_choice_options() -> tuple[tuple[str, str], ...]:
    return tuple((plan.name, plan.prompt_label) for plan in _FLOW_PLANS)


def flow_plan(name: str) -> OperatorFlowPlan:
    plan = _FLOW_BY_NAME.get(name)
    if plan is None:
        raise ValueError(f"unknown operator flow: {name}")
    return plan


def resolve_auto_flow(*, auth_mode: str, non_interactive: bool) -> str | None:
    if not non_interactive:
        return None
    return "app-audit" if auth_mode == "app" else "gr-audit"


def documented_operator_commands() -> tuple[str, ...]:
    return (" ".join(_GUIDED_COMMAND), *tuple(plan.render_command() for plan in _FLOW_PLANS))
