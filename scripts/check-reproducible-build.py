#!/usr/bin/env python3
"""Compare two plain `make dist` builds of the current Git commit, or normalise an sdist."""
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalise_sdist(path: Path, epoch: int) -> None:
    """Rewrite an sdist so its bytes depend only on member names, contents, exec bits and epoch."""
    with tarfile.open(path, 'r:gz') as archive:
        members = sorted(archive.getmembers(), key=lambda m: m.name)
        payload = [(m, archive.extractfile(m).read() if m.isfile() else None) for m in members]
        fmt = archive.format
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=fmt) as out:
        for member, data in payload:
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            member.pax_headers = {}
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            out.addfile(member, io.BytesIO(data) if data is not None else None)
    with open(path, 'wb') as handle:
        with gzip.GzipFile(filename='', mode='wb', fileobj=handle, compresslevel=9, mtime=epoch) as stream:
            stream.write(raw.getvalue())


def sdist_members(path: Path) -> list[tuple[str, str]]:
    with tarfile.open(path, 'r:gz') as archive:
        members = []
        for member in archive.getmembers():
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f'Cannot read {member.name}')
                value = digest(stream.read())
            else:
                value = digest(f'{member.type!r}:{member.linkname}'.encode())
            members.append((member.name, value))
        return sorted(members)


def build(root: Path) -> tuple[Path, Path]:
    """Run plain `make dist` (no SOURCE_DATE_EPOCH) in a fresh clone of HEAD; return its wheel and sdist."""
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    clone = root / 'clone'
    subprocess.run(['git', 'clone', '--quiet', '--no-checkout', '--no-hardlinks', str(ROOT), str(clone)], check=True)
    subprocess.run(['git', 'checkout', '--quiet', '--detach', head], cwd=clone, check=True)
    env = {k: v for k, v in os.environ.items() if k != 'SOURCE_DATE_EPOCH'}
    subprocess.run(['make', 'dist', f'PYTHON={sys.executable}'], cwd=clone, env=env, check=True, stdout=sys.stderr)
    output = clone / 'dist'
    wheels = list(output.glob('*.whl'))
    sdists = list(output.glob('*.tar.gz'))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError('Expected exactly one wheel and one sdist')
    return wheels[0], sdists[0]


def differences(wheel1: Path, wheel2: Path, sdist1: Path, sdist2: Path) -> list[str]:
    """Name each artefact whose bytes differ between the two builds."""
    found = []
    for label, a, b in (('wheel', wheel1, wheel2), ('sdist', sdist1, sdist2)):
        if a.name != b.name:
            found.append(f'{label} name: {a.name} != {b.name}')
        elif digest(a.read_bytes()) != digest(b.read_bytes()):
            found.append(f'{label} bytes differ: {a.name}')
    return found


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == '--normalise-sdist':
        normalise_sdist(Path(argv[1]), int(argv[2]))
        return 0
    if argv:
        print('usage: check-reproducible-build.py [--normalise-sdist PATH EPOCH]', file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix='auditex-repro-', dir=os.environ.get('TMPDIR') or tempfile.gettempdir()) as tmp:
        first = Path(tmp) / 'first'
        second = Path(tmp) / 'second'
        first.mkdir()
        second.mkdir()
        wheel1, sdist1 = build(first)
        wheel2, sdist2 = build(second)
        for artifact in (wheel1, wheel2, sdist1, sdist2):
            print(f'{artifact.parent.parent.parent.name}/{artifact.name} sha256={digest(artifact.read_bytes())}')
        found = differences(wheel1, wheel2, sdist1, sdist2)
        if found:
            for line in found:
                print(f'MISMATCH {line}')
            if sdist1.name == sdist2.name and sdist_members(sdist1) == sdist_members(sdist2):
                print('diagnostic: sdist members are identical; only archive framing differs')
            print('reproducible build mismatch')
            return 1
        print('reproducible build ok')
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
