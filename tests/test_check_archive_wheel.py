import importlib.util
from pathlib import Path
from zipfile import ZipFile

import pytest

spec = importlib.util.spec_from_file_location(
    "check_archive_wheel", Path(__file__).resolve().parents[1] / "scripts/check-archive-wheel.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_wheel_package_files_match_source(tmp_path):
    src = tmp_path / "src"
    package = src / "example"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"original")
    wheel = tmp_path / "example.whl"

    def write_wheel(files):
        with ZipFile(wheel, "w") as archive:
            for name, contents in files.items():
                archive.writestr(name, contents)

    write_wheel({"example/__init__.py": b"original", "example-1.dist-info/METADATA": b"metadata"})
    module.check_wheel(src, wheel)
    for files in ({}, {"example/__init__.py": b"stale"},
                  {"example/__init__.py": b"original", "example/extra.py": b"extra"}):
        write_wheel(files)
        with pytest.raises(ValueError, match="Wheel differs from source"):
            module.check_wheel(src, wheel)
