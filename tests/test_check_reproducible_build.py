import importlib.util
import io
from pathlib import Path
import tarfile


spec = importlib.util.spec_from_file_location('repro', Path(__file__).parents[1] / 'scripts/check-reproducible-build.py')
repro = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repro)


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))


def test_sdist_comparison_ignores_order_but_detects_content_and_names(tmp_path):
    a, b = tmp_path / 'a.tar.gz', tmp_path / 'b.tar.gz'
    archive(a, [('a', b'one'), ('b', b'two')])
    archive(b, [('b', b'two'), ('a', b'one')])
    assert repro.sdist_members(a) == repro.sdist_members(b)
    archive(b, [('a', b'changed'), ('b', b'two')])
    assert repro.sdist_members(a) != repro.sdist_members(b)
    archive(b, [('a', b'one'), ('c', b'two')])
    assert repro.sdist_members(a) != repro.sdist_members(b)
