"""Offline deterministic explanations of existing rule decisions.

The reporting caller must redact evidence before build_view and pass every returned
string through the report's output redaction before display or serialisation.
"""
from functools import lru_cache

from ..resources import open_text_resource
from .adapter import adapt_record
from .baselines import load_baselines
from .collection import load_collection
from .generate import generate_template
from .render import _validate_output, load_templates, render, render_full
from .view import build_view

__all__ = ["generate_template", "load_templates", "build_view", "render", "render_full",
           "explain", "ExplainerError"]


class ExplainerError(ValueError):
    """Explanation unavailable; callers suppress it and retain the rule verdict."""


@lru_cache(maxsize=1)
def _resources():
    return (load_baselines(open_text_resource), load_collection(open_text_resource),
            load_templates(open_text_resource))


def explain(record, redacted_sections, section_order):
    """Return a validated compact Explainer from already redacted evidence.

    Only fixed cited sections reach the View; null citations mean the policy read
    set, never all supplied sections. No inference, network or rule evaluation.
    Product must redact the complete result before serialisation or display.
    """
    try:
        baselines, collection, templates = _resources()
        adapted = adapt_record(record, templates=templates)
        view = build_view(adapted, redacted_sections, section_order,
                          baselines=baselines, collection=collection)
        result = render(adapted, view, templates=templates)
        _validate_output(result, adapted["verdict"], command_units=templates["policies"][adapted["policy_id"]]["command_units"])
        by_section = {item["section"]: item["id"] for item in view["evidence"]}
        refs = ["e0"] + [by_section[s] for s in adapted["cited_sections"] if s in by_section]
        if result["evidence_refs"] != refs:
            raise ValueError("invalid evidence reference order or membership")
        return result
    except Exception:
        # Do not include exception messages or evidence in customer-visible errors.
        raise ExplainerError("Explanation unavailable.") from None

