#!/usr/bin/env python3
"""Check that a wheel contains exactly the archived source package files."""

import sys
from pathlib import Path
from zipfile import ZipFile


def check_wheel(src: Path, wheel: Path) -> None:
    packages = {p.name for p in src.iterdir() if p.is_dir() and (p / "__init__.py").is_file()}
    if not packages:
        raise ValueError("No source packages found")
    source = {
        p.relative_to(src).as_posix(): p.read_bytes()
        for package in packages
        for p in (src / package).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    with ZipFile(wheel) as archive:
        names = [
            name for name in archive.namelist()
            if not name.endswith("/")
            and not name.partition("/")[0].endswith((".dist-info", ".data"))
        ]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate package files in wheel")
        actual = {name: archive.read(name) for name in names}
    missing = sorted(source.keys() - actual.keys())
    extra = sorted(actual.keys() - source.keys())
    changed = sorted(name for name in source.keys() & actual.keys() if source[name] != actual[name])
    if missing or extra or changed:
        raise ValueError(f"Wheel differs from source: missing={missing}, extra={extra}, changed={changed}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: check-archive-wheel.py SRC WHEEL")
    try:
        check_wheel(Path(sys.argv[1]), Path(sys.argv[2]))
    except ValueError as exc:
        sys.exit(str(exc))
    print("Wheel package files match archived source")
