from __future__ import annotations

import os
from collections.abc import Mapping


RESPONSE_ENABLE_ENV = "AUDITEX_ENABLE_RESPONSE"


def response_enabled(env: Mapping[str, str] | None = None) -> bool:
    values = os.environ if env is None else env
    return str(values.get(RESPONSE_ENABLE_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def response_disabled_message() -> str:
    return f"response plane is disabled; set {RESPONSE_ENABLE_ENV}=1 for lab-only development"
