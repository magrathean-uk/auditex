"""Pinned reference inventory; listing it never fetches or executes sources."""
from __future__ import annotations

import json
from typing import Any

from azure_tenant_audit.resources import resolve_resource_path


def list_model_sources() -> dict[str, Any]:
    path = resolve_resource_path("configs/model-sources.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        raise ValueError("Invalid model source catalogue.")
    return payload
