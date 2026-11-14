import gzip
import importlib.util
import io
import tarfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('repro', Path(__file__).parents[1] / 'scripts/check-reproducible-build.py')
repro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repro)


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))


def gz_archive(path, entries, mtime, mode=0o644, owner=0, member_mtime=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = mtime if member_mtime is None else member_mtime
            info.mode = mode
            info.uid = info.gid = owner
            tar.addfile(info, io.BytesIO(content))
    with open(path, 'wb') as handle:
        with gzip.GzipFile(filename='', mode='wb', fileobj=handle, mtime=mtime) as stream:
            stream.write(raw.getvalue())


def test_identical_members_with_different_gzip_headers_are_different_bytes(tmp_path):
    a, b = tmp_path / 'x' / 'a.tar.gz', tmp_path / 'y' / 'a.tar.gz'
    a.parent.mkdir()
    b.parent.mkdir()
    gz_archive(a, [('a', b'one')], mtime=1, member_mtime=0)
    gz_archive(b, [('a', b'one')], mtime=2, member_mtime=0)
    assert repro.sdist_members(a) == repro.sdist_members(b)
    assert repro.differences(a, a, a, b) == [f'sdist bytes differ: {a.name}']
    assert repro.differences(a, a, a, a) == []


def test_wheel_difference_is_named(tmp_path):
    w1, w2, s = tmp_path / 'p' / 'w.whl', tmp_path / 'q' / 'w.whl', tmp_path / 's.tar.gz'
    for path, data in ((w1, b'1'), (w2, b'2'), (s, b'3')):
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
    assert repro.differences(w1, w2, s, s) == ['wheel bytes differ: w.whl']


def test_normalise_makes_framing_irrelevant(tmp_path):
    a, b = tmp_path / 'a.tar.gz', tmp_path / 'b.tar.gz'
    gz_archive(a, [('z', b'two'), ('a', b'one')], mtime=5, mode=0o600, owner=501)
    gz_archive(b, [('a', b'one'), ('z', b'two')], mtime=9, mode=0o664, owner=0)
    assert a.read_bytes() != b.read_bytes()
    repro.normalise_sdist(a, 100)
    repro.normalise_sdist(b, 100)
    assert a.read_bytes() == b.read_bytes()
    with tarfile.open(a) as tar:
        assert [m.name for m in tar.getmembers()] == ['a', 'z']
        assert {(m.mtime, m.uid, m.gid, m.uname, m.gname, m.mode) for m in tar} == {(100, 0, 0, '', '', 0o644)}


def test_normalise_keeps_exec_bit(tmp_path):
    a = tmp_path / 'a.tar.gz'
    gz_archive(a, [('run', b'#!')], mtime=1, mode=0o775)
    repro.normalise_sdist(a, 7)
    with tarfile.open(a) as tar:
        assert tar.getmember('run').mode == 0o755


def test_sdist_comparison_ignores_order_but_detects_content_and_names(tmp_path):
    a, b = tmp_path / 'a.tar.gz', tmp_path / 'b.tar.gz'
    archive(a, [('a', b'one'), ('b', b'two')])
    archive(b, [('b', b'two'), ('a', b'one')])
    assert repro.sdist_members(a) == repro.sdist_members(b)
    archive(b, [('a', b'changed'), ('b', b'two')])
    assert repro.sdist_members(a) != repro.sdist_members(b)
    archive(b, [('a', b'one'), ('c', b'two')])
    assert repro.sdist_members(a) != repro.sdist_members(b)
