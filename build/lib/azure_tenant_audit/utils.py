from __future__ import annotations

import os
from pathlib import Path


def parse_csv_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    result = [item.strip() for item in value.split(",") if item.strip()]
    return result or None


def load_env_file(path: Path | None) -> None:
    if path is None or not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() not in os.environ:
            os.environ[key.strip()] = value.strip()
