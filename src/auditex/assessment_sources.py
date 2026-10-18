"""Versioned reference metadata for the offline assessment integrations."""
from __future__ import annotations

import json
from typing import Any

from azure_tenant_audit.resources import resolve_resource_path


def list_assessment_sources() -> dict[str, Any]:
    """Describe supported imports and inspected sources without fetching them."""
    path = resolve_resource_path("configs/assessment-sources.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        raise ValueError("Invalid assessment source catalogue.")
    return payload
