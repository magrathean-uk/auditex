"""Size limits and fail-closed discovery, using synthetic and sparse files."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_reporting import _write_run

from azure_tenant_audit import output_redaction as redaction


def _sparse_run(root: Path, sizes: tuple[int, ...]) -> None:
    normalized = root / "normalized"
    normalized.mkdir(parents=True)
    for index, size in enumerate(sizes):
        with (normalized / f"private-name-{index}.json").open("wb") as stream:
            stream.truncate(size)


def test_shareable_preview_preserves_local_structure_after_redaction(tmp_path: Path) -> None:
    from auditex.reporting import preview_report

    root = tmp_path / "run"
    _write_run(root)
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"]["owner"] = "private content"
    payload["executive_summary"]["ordinary_count"] = 42
    report.write_text(json.dumps(payload))
    options = {"run_dir": str(root), "format_name": "json", "include_sections": ["executive_summary"]}
    local = preview_report(**options, profile="local")
    shareable = preview_report(**options, profile="shareable")
    local_sections = json.loads(local["content"])["sections"]
    expected = redaction.settle_citations(redaction.redact_output(local_sections, context=redaction.context_for_run(root)))
    assert json.loads(shareable["content"]) == {"sections": expected, "pseudonym_notice": redaction.TEMPORARY_KEY_NOTICE}
    assert "private content" not in shareable["content"]
    assert expected["executive_summary"]["ordinary_count"] == 42


@pytest.mark.parametrize("sizes", [
    (46_281_912, 41_546_181),  # the largest files of the synthetic 90k-user run
    (48 * 1024 * 1024,) * 3,  # more than the old aggregate limit
])
def test_scan_accepts_large_synthetic_file_sizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sizes: tuple[int, ...]
) -> None:
    root = tmp_path / "run"
    _sparse_run(root, sizes)
    assert redaction._MAX_FILE_BYTES == 64 * 1024 * 1024
    assert redaction._MAX_SCAN_BYTES == 256 * 1024 * 1024
    # NUL-filled sparse files are not JSON. Exercise the real reader and budget, skipping only parsing.
    read_sizes: list[int] = []
    monkeypatch.setattr(redaction._Scan, "collect", lambda self, parts, data: read_sizes.append(len(data)))
    assert len(redaction.snapshot_run(root)) == len(sizes)
    context = redaction.context_for_run(root)
    assert not context.incomplete, context.incomplete_reasons
    assert read_sizes == list(sizes)
    for profile in (redaction.PROFILE_SHAREABLE, redaction.PROFILE_CUSTOMER_PACK, redaction.PROFILE_EXPLAINER):
        assert redaction.redact_output({"owner": "private"}, profile=profile, context=context)["owner"] == "<redacted-text>"


@pytest.fixture
def low_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redaction, "_MAX_FILE_BYTES", 100)
    monkeypatch.setattr(redaction, "_MAX_SCAN_BYTES", 150)


def _message(exc: pytest.ExceptionInfo[redaction.ContextIncompleteError], root: Path) -> str:
    message = str(exc.value)
    assert "shareable output" in message.lower()
    assert "100 bytes" in message and "150 bytes" in message
    assert "private-name" not in message and str(root) not in message
    assert "private content" not in message
    return message


@pytest.mark.usefixtures("low_limits")
def test_scan_accepts_exact_file_and_aggregate_limits(tmp_path: Path) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (100, 50))
    for path, size in zip(sorted((root / "normalized").iterdir()), (100, 50), strict=False):
        path.write_bytes(b'{"pad":"' + b'x' * (size - 10) + b'"}')
    assert len(redaction.snapshot_run(root)) == 2
    assert len(redaction.read_normalized_sections(root)) == 2
    assert not redaction.context_for_run(root).incomplete


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("sizes", [(101,), (80, 80)])
def test_over_budget_refuses_all_profiles_without_naming_files(tmp_path: Path, sizes: tuple[int, ...]) -> None:
    root = tmp_path / "run"
    _sparse_run(root, sizes)
    # For the aggregate case each file is valid JSON and individually within the file cap.
    if len(sizes) > 1:
        for path in (root / "normalized").iterdir():
            path.write_bytes(b'{"pad":"' + b'x' * 70 + b'"}')
            assert path.stat().st_size == 80
    with pytest.raises(redaction.ContextIncompleteError) as snapshot_error:
        redaction.snapshot_run(root)
    expected = _message(snapshot_error, root)
    with pytest.raises(redaction.ContextIncompleteError) as sections_error:
        redaction.read_normalized_sections(root)
    assert _message(sections_error, root) == expected
    context = redaction.context_for_run(root)
    for profile in (redaction.PROFILE_SHAREABLE, redaction.PROFILE_CUSTOMER_PACK, redaction.PROFILE_EXPLAINER):
        with pytest.raises(redaction.ContextIncompleteError) as output_error:
            redaction.redact_output({"owner": "private content"}, profile=profile, context=context)
        assert _message(output_error, root) == expected


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("command", ["export", "analyze"])
def test_cli_over_budget_prints_only_the_safe_refusal(tmp_path: Path, command: str) -> None:
    root = tmp_path / "private-run"
    _write_run(root)
    (root / "normalized" / "private-name.json").write_text('{"text":"private content' + 'x' * 100 + '"}')
    script = (
        "import sys; from azure_tenant_audit import output_redaction as r; "
        "r._MAX_FILE_BYTES=100; r._MAX_SCAN_BYTES=150; "
        "from auditex.cli import main; "
        "main({'export': ['export', 'run', 'json', sys.argv[1]], "
        "'analyze': ['report', 'analyze', sys.argv[1]]}[sys.argv[2]])"
    )
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-B", "-c", script, str(root), command], env=env, capture_output=True, text=True, timeout=10)
    expected = str(redaction.ContextIncompleteError((("<ignored>", redaction.REASON_OVERSIZE),)))
    assert result.returncode != 0 and result.stdout == ""
    assert result.stderr == expected + "\n"
    assert str(root) not in result.stderr and "private content" not in result.stderr
    assert not (root / "reports" / "rendered-report.json").exists()


@pytest.mark.usefixtures("low_limits")
def test_size_refusal_survives_truncated_and_multi_run_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (101,))
    (root / "normalized" / "aaa.json").write_text("not JSON")
    other = tmp_path / "other"
    _sparse_run(other, (101,))
    monkeypatch.setattr(redaction, "_MAX_REASONS", 1)
    context = redaction.context_for_runs([root, other])
    assert context.incomplete_omitted
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    assert str(other) not in _message(error, root)


@pytest.mark.usefixtures("low_limits")
def test_failed_partial_read_debits_budget_and_refuses_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90, 90, 90))
    inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_read = os.read
    total = 0

    def fail_after_partial_read(fd: int, count: int) -> bytes:
        nonlocal total
        assert os.fstat(fd).st_ino == inode  # later files no longer fit the remaining budget
        if total:
            raise OSError("private content")
        data = original_read(fd, min(count, 70))
        total += len(data)
        return data

    monkeypatch.setattr(redaction.os, "read", fail_after_partial_read)
    context = redaction.context_for_run(root)
    assert total == 70 and len(context.incomplete_files) == 3
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
def test_failed_close_after_read_debits_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90, 90, 90))
    inodes = {(root / "normalized" / f"private-name-{index}.json").stat().st_ino for index in range(3)}
    first_inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_read, original_close = os.read, os.close
    total = 0

    def count_read(fd: int, count: int) -> bytes:
        nonlocal total
        data = original_read(fd, count)
        if os.fstat(fd).st_ino in inodes:
            total += len(data)
        return data

    def fail_close(fd: int) -> None:
        inode = os.fstat(fd).st_ino
        original_close(fd)
        if inode == first_inode:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(redaction.os, "read", count_read)
    monkeypatch.setattr(redaction.os, "close", fail_close)
    context = redaction.context_for_run(root)
    assert total == 90 and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("inside", [False, True])
def test_json_symlink_is_refused_without_reading_its_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside: bool,
) -> None:
    root = tmp_path / "run"
    normalized, targets = root / "normalized", root / "targets"
    normalized.mkdir(parents=True)
    targets.mkdir()
    target = (targets if inside else tmp_path) / "target.json"
    target.write_bytes(b'{"pad":"' + b'x' * 80 + b'"}')
    other = normalized / "b.json"
    other.write_bytes(b'{"pad":"' + b'x' * 60 + b'"}')
    (normalized / "a.json").symlink_to(target)
    target_inode, other_inode = target.stat().st_ino, other.stat().st_ino
    original_read = os.read
    other_bytes = 0

    def count_reads(fd: int, count: int) -> bytes:
        nonlocal other_bytes
        inode = os.fstat(fd).st_ino
        assert inode != target_inode, "the symlink target was opened"
        data = original_read(fd, count)
        if inode == other_inode:
            other_bytes += len(data)
        return data

    monkeypatch.setattr(redaction.os, "read", count_reads)
    context = redaction.context_for_run(root)
    assert other_bytes == 70 and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    assert "non-regular" in str(error.value) and str(root) not in str(error.value)


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("close_fails", [False, True])
def test_file_close_failure_preserves_prior_oversize_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                          close_fails: bool) -> None:
    root = tmp_path / "run"
    _sparse_run(root, (90,))
    inode = (root / "normalized" / "private-name-0.json").stat().st_ino
    original_fstat, original_close = os.fstat, os.close

    def grew_before_open(fd: int) -> os.stat_result:
        info = original_fstat(fd)
        if info.st_ino == inode:
            fields = list(info)
            fields[6] = 101
            return os.stat_result(fields)
        return info

    def fail_file_close(fd: int) -> None:
        close_inode = original_fstat(fd).st_ino
        original_close(fd)
        if close_inode == inode:
            raise OSError("synthetic close failure")

    monkeypatch.setattr(redaction.os, "fstat", grew_before_open)
    if close_fails:
        monkeypatch.setattr(redaction.os, "close", fail_file_close)
    context = redaction.context_for_run(root)
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    _message(error, root)


@pytest.mark.usefixtures("low_limits")
@pytest.mark.parametrize("target_size", [90, 101])
def test_refused_json_symlink_does_not_consume_scan_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_size: int,
) -> None:
    root = tmp_path / "run"
    normalized, targets = root / "normalized", root / "targets"
    normalized.mkdir(parents=True)
    targets.mkdir()
    target, other = targets / "target.json", normalized / "b.json"
    target.write_bytes(b'x' * target_size)
    other.write_bytes(b'{"pad":"' + b'x' * 60 + b'"}')
    (normalized / "a.json").symlink_to("../targets/target.json")
    original_reader = redaction._read_file_at
    other_caps: list[int] = []

    def record_budget(parent_fd: int, name: str, info: os.stat_result, cap: int) -> bytes:
        assert name != "target.json", "the symlink target was opened"
        other_caps.append(cap)
        return original_reader(parent_fd, name, info, cap)

    monkeypatch.setattr(redaction, "_read_file_at", record_budget)
    context = redaction.context_for_run(root)
    assert other_caps == [150] and context.incomplete
    with pytest.raises(redaction.ContextIncompleteError) as error:
        redaction.redact_output({}, context=context)
    assert "non-regular" in str(error.value) and str(root) not in str(error.value)


# -- D5: bounded person-name matching (design M05-T01, section 4) ---------------------------------------------------


def _d5_people(count: int) -> list[tuple]:
    letters = "bdgkmrtv"
    people = []
    for index in range(count):
        given = "".join(letters[(index >> shift) & 7] + "aeiou"[(index >> shift) % 5] for shift in (0, 3, 6, 9, 12, 15))
        family = given[::-1].capitalize() + "x"
        name = f"{given.capitalize()} {family}"
        people.append((name, (name,), "", "", (f"{given}.{family.lower()}@bench.example",), ()))
    return people


def _d5_matcher(people: list[tuple]) -> redaction._NameMatcher:
    return redaction._NameMatcher(redaction._build_index(people, frozenset()).table, bytes(32))


_D5_TEXT = ("The audit found that the shared mailbox for finance forwards to an external address; review owner, "
            "policy MS.EXO.4.1v1 and https://contoso-my.sharepoint.com/personal/site_contoso_com/Documents. ") * 400
_D5_TEXT = _D5_TEXT[: 64 * 1024]


_D5_INITIALS_TEXT = "Dr. A. B. Bodatix met Prof. Dr. C. Kemuraz; Mx Q Lorem, Ipsum D. E. F. G. H. Dolor. " * 300


def test_d5_probe_count_is_independent_of_directory_size() -> None:
    probes = []
    initials_probes = []
    for count in (10, 100_000):
        matcher = _d5_matcher(_d5_people(count))
        assert matcher.mask(_D5_TEXT) is _D5_TEXT  # nothing matched: the same object comes back
        probes.append(matcher.probes)
        matcher.probes = 0
        assert matcher.mask(_D5_INITIALS_TEXT) is _D5_INITIALS_TEXT  # initials and titles alone match nothing
        initials_probes.append(matcher.probes)
    tokens = len(redaction._D5_WORD_RE.findall(_D5_TEXT))
    assert probes[0] == probes[1] <= tokens * redaction._D5_MAX_KEY_TOKENS
    initials_tokens = len(redaction._D5_WORD_RE.findall(_D5_INITIALS_TEXT))
    assert initials_probes[0] == initials_probes[1] <= initials_tokens * redaction._D5_MAX_KEY_TOKENS


def test_d5_probes_per_token_and_window_are_bounded() -> None:
    six = "Ab Cd Ef Gh Ij Kl"
    matcher = _d5_matcher([(six, (six,), "", "", (), ())])
    for text in ("ab cd ef gh ij kx " * 500, "ab cd ef gh ij kl " * 500, "ab ab ab ab ab ab ab " * 500,
                 "ab.cd_ef-gh'ij’kl " * 500, "ab, cd,ef,  gh ij kl, " * 500, "ab, ab, ab, ab, ab, ab, " * 500):
        matcher.probes = matcher.widest = 0
        matcher.mask(text)
        tokens = len(redaction._D5_WORD_RE.findall(text))
        assert 0 < matcher.probes <= tokens * redaction._D5_MAX_KEY_TOKENS
        assert matcher.widest <= redaction._D5_MAX_KEY_TOKENS
    matcher.probes = 0
    matcher.mask("ab " * 10)
    plain = matcher.probes
    matcher.probes = 0
    matcher.mask("x" * 65 + " " + "ab " * 10 + "ab" + "c" * 70)
    assert matcher.probes == plain  # a token over 64 characters is never probed and breaks the chain


def test_d5_budget_holds_for_middle_initials_and_titles() -> None:
    six = "Ab Cd Ef Gh Ij Kl"
    matcher = _d5_matcher([(six, (six,), "", "", (), ()), ("Ab Cd", ("Ab Cd",), "", "", (), ())])
    for text in ("ab x cd y ef z gh w ij v kl " * 500, "Ab A B C D E F Cd " * 500, "Ab A. B. C. D. E. Cd " * 500,
                 "Dr. Prof. Mr. Ms. Ab Cd " * 500, "Dr Ab x. Cd y. Ef z. Gh " * 500, "ab cd ef gh ij k " * 500):
        matcher.probes = matcher.widest = 0
        matcher.mask(text)
        tokens = len(redaction._D5_WORD_RE.findall(text))
        assert 0 < matcher.probes <= tokens * redaction._D5_MAX_KEY_TOKENS, text[:24]
        assert matcher.widest <= redaction._D5_MAX_KEY_TOKENS, text[:24]
    # An initial takes its place in the window: six tokens ``ab`` and five initials never reach ``cd``.
    assert matcher.mask("Ab A B C D E Cd") == redaction.TEXT_PLACEHOLDER
    assert matcher.mask("Ab A B C D Cd").startswith("User ")
    # A title run costs no probe of its own beyond the one every token has.
    counts = []
    for lead in ("Dr. Prof.", "Zz. Yy."):
        matcher.probes = 0
        matcher.mask(f"{lead} Ab Cd")
        counts.append(matcher.probes)
    assert counts[0] == counts[1]


def test_d5_initial_fallback_keeps_probes_per_start_at_most_six(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``ab x`` ... ``ab x y z w`` are prefixes of another person's key, so the path takes the initials and the fallback
    # probe of the phrase without them runs; each start (a one-token probe) and what follows it costs at most six.
    people = [(n, (n,), "", "", (), ()) for n in ("Ab Cd", "Ab X Y Z W Ef", "Ab Cd Ef Gh Ij Kl")]
    matcher = _d5_matcher(people)
    seen: list[str] = []
    real = redaction._NameMatcher._probe
    monkeypatch.setattr(redaction._NameMatcher, "_probe", lambda self, phrase: seen.append(phrase) or real(self, phrase))
    for text, masked in (("Ab X Cd", True), ("Ab X Y Z Cd", True), ("Ab X Y Z W Cd", False), ("Ab X Cd Ef Gh Ij", True),
                         ("Ab X Y Z W V Cd", False), ("Ab X Cd " * 500, True), ("Ab X Y Cd Ef Gh Ij Kl " * 500, True)):
        seen.clear()
        matcher.widest = 0
        out = matcher.mask(text)
        assert (out.startswith("User ") if masked else out == redaction.TEXT_PLACEHOLDER), text[:24]
        per_start: list[int] = []
        for phrase in seen:
            if " " in phrase:
                per_start[-1] += 1
            else:
                per_start.append(1)
        assert max(per_start) <= redaction._D5_MAX_KEY_TOKENS, text[:24]
        assert matcher.widest <= redaction._D5_MAX_KEY_TOKENS, text[:24]


def test_d5_initial_fallback_on_a_running_key_stays_at_six_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``ab x cd`` is only a prefix of a longer key: the walk keeps the longer path at the full window and ``ab cd`` is
    # tried after it, only where no longer hit was found and only with probes left; each start costs at most six
    # probes, and a six-token key with an initial (``ab x cd ef gh ij``) is still reached.
    seen: list[str] = []
    real = redaction._NameMatcher._probe
    monkeypatch.setattr(redaction._NameMatcher, "_probe", lambda self, phrase: seen.append(phrase) or real(self, phrase))
    short = redaction.pseudonym(bytes(32), "Ab Cd")
    five, six = (redaction.pseudonym(bytes(32), n) for n in ("Ab X Cd Ef Gh", "Ab X Cd Ef Gh Ij"))
    for longer, text, owner, probes in (
        ("Ab X Cd Ef Gh", "Ab X Cd", short, 4), ("Ab X Cd Ef Gh", "Ab X Cd Ef", short, 7),
        ("Ab X Cd Ef Gh", "Ab X Cd Ef Gh", five, 5), ("Ab X Cd Ef Gh", "Ab X Cd Ef Gh Zz", five, 7),
        ("Ab X Cd Ef Gh", "Ab X Cd Ef Gh Ab X Cd", five, 10), ("Ab X Cd Ef Gh", "Ab X Cd zz " * 500, short, 3500),
        ("Ab X Cd Ef Gh Ij", "Ab X Cd Ef Gh Ij", six, 6),
        ("Ab X Cd Ef Gh Ij", "Ab X Cd Ef Gh Zz", None, 6),  # six probes spent: withhold without scanning further
    ):
        matcher = _d5_matcher([(n, (n,), "", "", (), ()) for n in ("Ab Cd", longer)])
        seen.clear()
        out = matcher.mask(text)
        assert out.startswith(f"User {owner}" if owner else redaction.TEXT_PLACEHOLDER), text[:24]
        per_start: list[int] = []
        for phrase in seen:
            if " " in phrase:
                per_start[-1] += 1
            else:
                per_start.append(1)
        assert max(per_start) <= redaction._D5_MAX_KEY_TOKENS, text[:24]
        assert len(seen) == probes, text[:24]
        assert matcher.widest <= redaction._D5_MAX_KEY_TOKENS, text[:24]


def test_d5_budget_mapping_key_is_one_probe_and_long_keys_none() -> None:
    matcher = _d5_matcher([("Ab Cd", ("Ab Cd",), "", "", (), ())])
    for key, probes in (("ab_cd", 1), ("AbCd", 1), ("kemi_rotax", 1), ("display_name", 0), ("break_glass", 0),
                        ("a_b_c_d_e_f_g", 0), ("x" * 65 + "_ab", 0), ("user-0123456789abcdef", 0)):
        matcher.probes = 0
        matcher.whole(key)
        assert matcher.probes == probes, key
    assert matcher.whole("ab_cd").startswith("user-") and matcher.whole("AbCd").startswith("User ")


def test_d5_matcher_holds_no_regex_built_from_names() -> None:
    matcher = _d5_matcher(_d5_people(50))
    held = [getattr(matcher, slot) for slot in redaction._NameMatcher.__slots__]
    assert not any(isinstance(value, re.Pattern) for value in held)
    patterns = [value for value in vars(redaction).values() if isinstance(value, re.Pattern)]
    assert not any("bdg" in pattern.pattern.lower() for pattern in patterns)
    assert all(isinstance(key, str) and isinstance(value, str) for key, value in matcher.table.items())


def test_d5_keys_per_person_are_capped() -> None:
    ids = tuple(f"bodatix.kemuraz{n}@d{n}.example" for n in range(12))
    person = ("Bodatix Kemuraz", ("Bodatix Kemuraz", "Bodatix Q Kemuraz"), "Bodatix", "Kemurazo", ids, ())
    keys, reason = redaction._person_keys(person, frozenset())
    assert reason == "limit" and len(keys) == redaction._D5_MAX_KEYS_PER_PERSON == 16
    assert keys[:4] == ["bodatix kemuraz", "bodatix q kemuraz", "bodatix kemurazo", "kemurazo bodatix"]  # required first
    assert all(len(key.split(" ")) <= redaction._D5_MAX_KEY_TOKENS for key in keys)


def test_d5_index_is_built_once_per_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "run"
    _write_run(root)
    (root / "normalized" / "users.json").write_text(json.dumps({"records": [
        {"kind": "user", "display_name": "Bodatix Kemuraz", "principal_name": "bodatix.kemuraz@bench.example"}]}))
    context = redaction.context_for_run(root)
    builds = []
    original = redaction._build_index
    monkeypatch.setattr(redaction, "_build_index", lambda *a, **k: builds.append(1) or original(*a, **k))
    for _ in range(3):
        assert redaction.redact_output("Bodatix Kemuraz", context=context).startswith("User ")
    assert builds == []  # strings carry no person records, so no per-call overlay either


def test_d5_oversized_whole_key_allocation_is_bounded() -> None:
    import tracemalloc

    matcher = _d5_matcher([("Neral Vosk", ("Neral Vosk",), "", "", (), ())])
    key = "neral_" * 200_000 + "vosk"
    tracemalloc.start()
    try:
        assert matcher.whole(key) is key
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 64 * 1024, f"whole-key token allocation: {peak} bytes"
    assert matcher.probes == 0


def test_d5_whole_key_token_scan_stops_at_the_seventh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    matcher = _d5_matcher([("Neral Vosk", ("Neral Vosk",), "", "", (), ())])
    real = redaction._D5_WORD_RE
    visited = []

    class CountedTokens:
        def finditer(self, text):
            for match in real.finditer(text):
                visited.append(match[0])
                yield match

    monkeypatch.setattr(redaction, "_D5_WORD_RE", CountedTokens())
    key = "aa_bb_cc_dd_ee_ff_gg_hh_ii"
    assert matcher.whole(key) == key
    assert len(visited) == 7
    assert matcher.probes == 0


@pytest.mark.parametrize("text", ["Neral A B Vosk wrote", "Neral A B C Vosk wrote", "Neral A B C D Vosk"])
def test_d5_exhausted_initial_candidates_are_withheld_without_extra_probes(
    monkeypatch: pytest.MonkeyPatch, text: str,
) -> None:
    matcher = _d5_matcher([(
        "Neral Vosk", ("Neral Vosk",), "", "", ("neral.a.vosk.adm@example.invalid",), (),
    )])
    seen = []
    real = redaction._NameMatcher._probe
    monkeypatch.setattr(redaction._NameMatcher, "_probe", lambda self, phrase: seen.append(phrase) or real(self, phrase))
    out = matcher.mask(text)
    assert out == redaction.TEXT_PLACEHOLDER
    per_start = []
    for phrase in seen:
        if " " in phrase:
            per_start[-1] += 1
        else:
            per_start.append(1)
    assert max(per_start) <= 6
    assert len(seen) <= len(redaction._D5_WORD_RE.findall(text)) * 6
    assert matcher.widest <= 6


@pytest.mark.parametrize("title", ["", "Dr. "])
@pytest.mark.parametrize("initials", ["A B C D E", "A. B. C. D. E."])
def test_d5_shorter_hit_does_not_bypass_initial_exhaustion(
    monkeypatch: pytest.MonkeyPatch, title: str, initials: str,
) -> None:
    matcher = _d5_matcher([(n, (n,), "", "", (), ()) for n in ("Neral", "Neral Vosk")])
    seen = []
    real = redaction._NameMatcher._probe
    monkeypatch.setattr(redaction._NameMatcher, "_probe", lambda self, phrase: seen.append(phrase) or real(self, phrase))
    text = f"{title}Neral {initials} Vosk wrote"
    assert matcher.mask(text) == redaction.TEXT_PLACEHOLDER
    per_start = []
    for phrase in seen:
        if " " in phrase:
            per_start[-1] += 1
        else:
            per_start.append(1)
    assert max(per_start) <= 6
    assert len(seen) <= len(redaction._D5_WORD_RE.findall(text)) * 6
    assert matcher.widest <= 6
