#!/usr/bin/env python3
"""Compare two builds of the current Git commit."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def build(root: Path, epoch: str) -> tuple[Path, Path]:
    source = root / 'source'
    source.mkdir()
    archive = subprocess.run(['git', 'archive', 'HEAD'], cwd=ROOT, check=True, stdout=subprocess.PIPE).stdout
    with tempfile.TemporaryFile() as stream:
        stream.write(archive)
        stream.seek(0)
        with tarfile.open(fileobj=stream) as tar:
            tar.extractall(source, filter='data')
    output = root / 'dist'
    output.mkdir()
    env = dict(os.environ, SOURCE_DATE_EPOCH=epoch)
    for method in ('build_wheel', 'build_sdist'):
        subprocess.run([sys.executable, '-c', f'import setuptools.build_meta as b; b.{method}({str(output)!r})'], cwd=source, env=env, check=True)
    wheels = list(output.glob('*.whl'))
    sdists = list(output.glob('*.tar.gz'))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError('Expected exactly one wheel and one sdist')
    return wheels[0], sdists[0]


def main() -> int:
    epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=ROOT, text=True).strip()
    with tempfile.TemporaryDirectory(prefix='auditex-repro-', dir=os.environ.get('TMPDIR') or tempfile.gettempdir()) as tmp:
        first = Path(tmp) / 'first'
        second = Path(tmp) / 'second'
        first.mkdir()
        second.mkdir()
        wheel1, sdist1 = build(first, epoch)
        wheel2, sdist2 = build(second, epoch)
        for artifact in (wheel1, wheel2, sdist1, sdist2):
            print(f'{artifact.parent.parent.name}/{artifact.name} sha256={digest(artifact.read_bytes())}')
        same = wheel1.name == wheel2.name and digest(wheel1.read_bytes()) == digest(wheel2.read_bytes())
        same = same and sdist1.name == sdist2.name and sdist_members(sdist1) == sdist_members(sdist2)
        print('reproducible build ok' if same else 'reproducible build mismatch')
        return 0 if same else 1


if __name__ == '__main__':
    sys.exit(main())
