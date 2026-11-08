"""Check references in tracked first-party Markdown against the working tree."""

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
# Vendor text is upstream; tests contain fixtures and schema licences; plan records
# can name work which has not yet been created.
EXCLUDED = ("tenant-bootstrap/vendor/", "tests/", ".plan/")
EXEMPTIONS = {
    ("docs/guides/model-development.md", "tests/providers/m365"): "upstream sparse-checkout path",
}


def test_public_doc_paths_exist():
    files = subprocess.check_output(["git", "ls-files", "*.md"], cwd=ROOT, text=True).splitlines()
    tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
    roots = {name.split("/", 1)[0] for name in tracked if "/" in name}
    missing = []
    for name in files:
        if name.startswith(EXCLUDED):
            continue
        content = (ROOT / name).read_text(encoding="utf-8")
        if name == "CHANGELOG.md":
            # Released sections describe historical trees, not the current one.
            content = re.split(r"(?m)^## \[(?!Unreleased\])", content, maxsplit=1)[0]
        for number, line in enumerate(content.splitlines(), 1):
            for raw in re.findall(r"`([^`]+)`", line):
                path = raw.rstrip("/")
                if "/" not in path or path.split("/", 1)[0] not in roots:
                    continue
                if not re.fullmatch(r"[\w.\-/]+", path):
                    continue
                if (name, path) not in EXEMPTIONS and not (ROOT / path).exists():
                    missing.append(f"{name}:{number}: {raw}")
            for raw in re.findall(r"!?\[[^]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)", line):
                target = urlsplit(raw)
                if target.scheme or target.netloc or not target.path:
                    continue
                path = unquote(target.path)
                if not (ROOT / name).parent.joinpath(path).exists():
                    missing.append(f"{name}:{number}: {raw}")
    assert not missing, "Missing documentation paths:\n" + "\n".join(missing)
