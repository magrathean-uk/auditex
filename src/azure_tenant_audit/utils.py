from __future__ import annotations

import os
from pathlib import Path


def parse_csv_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    result = [item.strip() for item in value.split(",") if item.strip()]
    return result or None


def load_env_file(path: Path | None, *, guarded: bool = False) -> None:
    if path is None:
        return
    if guarded:
        from .guarded_io import UnsafeRunFileError, read_guarded_bytes
        invalid = False
        try:
            text = read_guarded_bytes(path, field="env").decode("utf-8")
        except FileNotFoundError:
            return
        except UnicodeError:
            invalid = True
        if invalid:
            raise UnsafeRunFileError("env") from None
    else:
        if not path.exists():
            return
        text = path.read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() not in os.environ:
            os.environ[key.strip()] = value.strip()
