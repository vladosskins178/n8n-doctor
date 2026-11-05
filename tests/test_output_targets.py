"""Output files replace regular files only: a rename over a device, fifo, socket or folder would destroy it."""

from __future__ import annotations

import json
import os
import socket
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from n8n_doctor import files
from n8n_doctor.cli import main
from n8n_doctor.files import check_writable, open_atomic

from .conftest import trigger, workflow

WORKFLOW_TEXT = json.dumps(workflow([trigger()]))

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs fifos, sockets and symlinks")


def make_fifo(path: Path) -> None:
    os.mkfifo(path)


def make_device(path: Path) -> None:
    try:
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, 3))
    except PermissionError:
        pytest.skip("creating a device node is not permitted here")


def make_socket(path: Path) -> None:
    with socket.socket(socket.AF_UNIX) as sock:  # a relative path: the length of a socket path is limited
        sock.bind(path.name)


def make_folder(path: Path) -> None:
    path.mkdir()


MAKERS: list[Callable[[Path], None]] = [make_fifo, make_device, make_socket, make_folder]


@pytest.fixture(params=[False, True], ids=["direct", "symlink"])
def special(request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[Callable[[Path], None]], Path]]:
    monkeypatch.chdir(tmp_path)

    def build(make: Callable[[Path], None]) -> Path:
        real = tmp_path / "real"
        make(real)
        if not request.param:
            return real
        (tmp_path / "link").symlink_to(real)
        return tmp_path / "link"

    yield build


def source(tmp_path: Path) -> Path:
    src = tmp_path / "wf.json"
    src.write_text(json.dumps(workflow([trigger()], pinData={"Start": [{"json": {}}]})))
    return src


def assert_untouched(target: Path, tmp_path: Path, before: os.stat_result, is_link: bool) -> None:
    assert target.is_symlink() == is_link
    after = (tmp_path / "real").stat()
    assert (after.st_mode, after.st_ino) == (before.st_mode, before.st_ino)
    assert not [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


@pytest.mark.parametrize("make", MAKERS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("fmt", ["text", "github", "json", "sarif"])
def test_lint_refuses_what_is_not_a_regular_file(
    make: Callable[[Path], None], fmt: str, special: Callable[[Callable[[Path], None]], Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = special(make)
    before = (tmp_path / "real").stat()
    assert main(["lint", "--no-config", "-f", fmt, "-o", str(target), str(source(tmp_path))]) == 2
    assert f"cannot write {target}: not a regular file" in capsys.readouterr().err
    assert_untouched(target, tmp_path, before, target.name == "link")


@pytest.mark.parametrize("make", MAKERS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("force", [False, True], ids=["plain", "force"])
def test_fix_write_refuses_what_is_not_a_regular_file(
    make: Callable[[Path], None], force: bool, special: Callable[[Callable[[Path], None]], Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = special(make)
    before = (tmp_path / "real").stat()
    argv = ["fix", "--no-config", "--write", "-o", str(target), str(source(tmp_path))]
    assert main(argv + (["--force"] if force else [])) == 2
    assert f"cannot write {target}: not a regular file" in capsys.readouterr().err  # never "use --force"
    assert_untouched(target, tmp_path, before, target.name == "link")


@pytest.mark.parametrize("make", [make_fifo, make_device, make_socket], ids=lambda m: m.__name__)
def test_skill_install_refuses_what_is_not_a_regular_file(
    make: Callable[[Path], None], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    make(tmp_path / "SKILL.md")
    before = (tmp_path / "SKILL.md").stat()
    assert main(["skill", "install", "--dest", str(tmp_path)]) == 2
    assert f"cannot write {tmp_path / 'SKILL.md'}: not a regular file" in capsys.readouterr().err
    after = (tmp_path / "SKILL.md").stat()
    assert (after.st_mode, after.st_ino) == (before.st_mode, before.st_ino)


def test_open_atomic_refuses_before_creating_the_temporary_file(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(OSError, match="not a regular file"), open_atomic(fifo):
        pytest.fail("the block must not run")
    assert [p.name for p in tmp_path.iterdir()] == ["pipe"]


def test_open_atomic_refuses_a_target_that_changed_while_writing(tmp_path: Path) -> None:
    target = tmp_path / "out"
    with pytest.raises(OSError, match="not a regular file"), open_atomic(target) as handle:
        handle.write("x")
        os.mkfifo(target)
    assert stat.S_ISFIFO(target.lstat().st_mode)
    assert [p.name for p in tmp_path.iterdir()] == ["out"]


def test_a_symlink_to_an_open_stream_is_refused_even_when_the_stream_is_a_file(tmp_path: Path) -> None:
    # how /dev/stdout looks with stdout redirected to a file: the rename would replace the link itself
    with (tmp_path / "stream").open("w") as stream:
        link = tmp_path / "stdout"
        link.symlink_to(f"/proc/self/fd/{stream.fileno()}")
        second = tmp_path / "second"
        second.symlink_to(link)
        for target in (link, second):
            with pytest.raises(OSError, match="not a regular file"):
                check_writable(target)
            assert target.is_symlink()


@pytest.mark.parametrize("kind", ["regular", "pipe", "tty", "closed"])
@pytest.mark.parametrize("command", ["lint", "fix"])
def test_a_symlink_into_proc_self_fd_is_never_replaced(kind: str, command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = source(tmp_path)
    fds: list[int] = []
    if kind == "regular":
        fds = [os.open(tmp_path / "stream", os.O_WRONLY | os.O_CREAT, 0o600)]
    elif kind == "pipe":
        fds = list(os.pipe())
    elif kind == "tty":
        fds = list(os.openpty())
    link = tmp_path / "stdout"
    link.symlink_to(f"/proc/self/fd/{fds[0] if fds else 99999}")  # "closed": a dangling link, as with stdout closed
    argv = (
        ["lint", "--no-config", "-f", "sarif", "-o", str(link), str(src)]
        if command == "lint"
        else ["fix", "--no-config", "--write", "--force", "-o", str(link), str(src)]
    )
    try:
        assert main(argv) == 2
    finally:
        for fd in fds:
            os.close(fd)
    assert "not a regular file" in capsys.readouterr().err
    assert link.is_symlink() and str(link.readlink()).startswith("/proc/self/fd/")
    assert not [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_a_relative_dangling_symlink_into_proc_is_never_replaced(tmp_path: Path) -> None:
    link = tmp_path / "out"
    link.symlink_to("../" * len(tmp_path.parts) + "proc/self/fd/99999")
    with pytest.raises(OSError, match="not a regular file"):
        check_writable(link)
    assert link.is_symlink()


def test_regular_targets_are_still_replaced(tmp_path: Path) -> None:
    src = source(tmp_path)
    plain = tmp_path / "plain.json"
    plain.write_text("old")
    assert main(["fix", "--no-config", "--write", "--force", "-o", str(plain), str(src)]) == 0
    assert json.loads(plain.read_text())
    dangling = tmp_path / "dangling.sarif"
    dangling.symlink_to(tmp_path / "missing")
    main(["lint", "--no-config", "-f", "sarif", "-o", str(dangling), str(src)])
    assert not dangling.is_symlink() and json.loads(dangling.read_text())
    assert not (tmp_path / "missing").exists()


def test_a_symlink_loop_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    assert main(["lint", "--no-config", "-o", str(loop), str(source(tmp_path))]) == 2
    assert f"cannot write {loop}" in capsys.readouterr().err and loop.is_symlink()


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_lint_output_dash_is_stdout(fmt: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    src = source(tmp_path)
    monkeypatch.chdir(tmp_path)
    code = main(["lint", "--no-config", "--color", "never", "-f", fmt, "-o", "-", str(src)])
    out, err = capsys.readouterr()
    main(["lint", "--no-config", "--color", "never", "-f", fmt, str(src)])
    assert code in (0, 1) and "wrote" not in err and out == capsys.readouterr().out and out
    assert not (tmp_path / "-").exists()


def test_a_file_named_dash_can_be_written_as_a_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = source(tmp_path)
    monkeypatch.chdir(tmp_path)
    main(["lint", "--no-config", "-f", "sarif", "-o", "./-", str(src)])
    assert json.loads((tmp_path / "-").read_text())


def test_fix_write_to_dash_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    src = source(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["fix", "--no-config", "--write", "-o", "-", str(src)]) == 2
    assert "--write -o - " in capsys.readouterr().err
    assert not (tmp_path / "-").exists()


@pytest.mark.parametrize("name", ["nul", "stdoutt", "regular"])
def test_a_file_directly_under_the_device_folder_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    fake_dev = tmp_path / "dev"
    fake_dev.mkdir()
    (fake_dev / "regular").write_text("x")
    monkeypatch.setattr(files, "_DEVICE_FOLDER", fake_dev)
    with pytest.raises(OSError, match="device folder"):
        check_writable(fake_dev / name)
    with pytest.raises(OSError, match="device folder"):
        check_writable(fake_dev / ".." / "dev" / name)
    (tmp_path / "link").symlink_to(fake_dev)
    with pytest.raises(OSError, match="device folder"):
        check_writable(tmp_path / "link" / name)
    (fake_dev / "shm").mkdir()
    check_writable(fake_dev / "shm" / name)  # a real folder below it, such as /dev/shm, is ordinary storage
    check_writable(tmp_path / name)


def test_cli_refuses_a_file_directly_under_the_device_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fake_dev = tmp_path / "dev"
    fake_dev.mkdir()
    monkeypatch.setattr(files, "_DEVICE_FOLDER", fake_dev)
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(workflow([trigger()])))
    assert main(["lint", "--no-config", "-o", str(fake_dev / "nul"), str(path)]) == 2
    assert not (fake_dev / "nul").exists() and "device folder" in capsys.readouterr().err


@pytest.mark.parametrize("fmt", ["json", "sarif", "text"])
def test_lint_refuses_to_replace_a_workflow_of_the_folder_it_checks(tmp_path: Path, fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    folder = tmp_path / "fold"
    folder.mkdir()
    target = folder / "a.json"
    target.write_text(WORKFLOW_TEXT, encoding="utf-8")
    assert main(["lint", "--no-config", "-f", fmt, "-o", str(target), str(folder)]) == 2
    assert target.read_text(encoding="utf-8") == WORKFLOW_TEXT
    assert "input file" in capsys.readouterr().err


def test_lint_refuses_to_replace_a_checked_workflow_by_another_spelling_or_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "fold"
    folder.mkdir()
    target = folder / "a.json"
    target.write_text(WORKFLOW_TEXT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["lint", "--no-config", "-o", "fold/../fold/a.json", "fold"]) == 2
    link = tmp_path / "report.json"
    link.symlink_to(target)
    assert main(["lint", "--no-config", "-o", str(link), "fold"]) == 2
    hard = tmp_path / "hard.json"
    hard.hardlink_to(target)
    assert main(["lint", "--no-config", "-o", str(hard), "fold"]) == 2
    assert target.read_text(encoding="utf-8") == WORKFLOW_TEXT


def test_lint_may_keep_its_report_in_the_folder_it_checks(tmp_path: Path) -> None:
    folder = tmp_path / "fold"
    folder.mkdir()
    (folder / "a.json").write_text(WORKFLOW_TEXT, encoding="utf-8")
    report = folder / "report.json"
    for _ in range(2):  # the second run skips the report of the first: it is no workflow
        assert main(["lint", "--no-config", "--fail-on", "never", "-f", "json", "-o", str(report), str(folder)]) == 0
    assert "findings" in json.loads(report.read_text(encoding="utf-8"))


# --- permissions of what is written --------------------------------------------------------------------------------


def _fixable(path: Path, mode: int) -> None:
    path.write_text(
        json.dumps(
            workflow([trigger(), {"name": "S", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [0, 0], "parameters": {"a": "{{ $json.x }}"}}])
        )
    )
    path.chmod(mode)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_fix_write_gives_a_new_file_the_mode_of_the_source(mode: int, tmp_path: Path) -> None:
    source = tmp_path / "w.json"
    _fixable(source, mode)
    assert main(["fix", str(source), "--write", "--no-config"]) == 0
    assert stat.S_IMODE((tmp_path / "w.fixed.json").stat().st_mode) == mode


def test_fix_write_force_keeps_the_mode_of_the_target(tmp_path: Path) -> None:
    source, target = tmp_path / "w.json", tmp_path / "t.json"
    _fixable(source, 0o644)
    target.write_text("{}")
    target.chmod(0o600)
    assert main(["fix", str(source), "--write", "-o", str(target), "--force", "--no-config"]) == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600 and "nodes" in target.read_text()


def test_open_atomic_keeps_the_mode_of_the_target_and_takes_the_given_one_for_a_new_file(tmp_path: Path) -> None:
    target = tmp_path / "x"
    target.write_text("old")
    target.chmod(0o640)
    with open_atomic(target) as handle:
        handle.write("new")
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    fresh = tmp_path / "y"
    with open_atomic(fresh, mode=0o600) as handle:
        handle.write("new")
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o600


# --- what lint -o may replace ---------------------------------------------------------------------------------------


def _folder(tmp_path: Path) -> Path:
    (tmp_path / "ok.json").write_text(WORKFLOW_TEXT)
    return tmp_path


@pytest.mark.parametrize("name", ["broken.json", "package.json", "fixed.fixed.json", "sub/empty.json"])
def test_lint_never_replaces_a_json_file_of_the_folder_it_scans(name: str, tmp_path: Path) -> None:
    _folder(tmp_path)
    target = tmp_path / name
    target.parent.mkdir(exist_ok=True)
    before = '{"nodes": [' if name == "broken.json" else '{"name": "pkg"}'
    target.write_text(before)
    assert main(["lint", str(tmp_path), "-o", str(target), "--no-config", "-f", "json", "--force"]) == 2
    assert target.read_text() == before


def test_lint_never_replaces_its_config_file(tmp_path: Path) -> None:
    _folder(tmp_path)
    config = tmp_path / "n8n-doctor.toml"
    config.write_text("")
    assert main(["lint", str(tmp_path / "ok.json"), "--config", str(config), "-o", str(config), "--force"]) == 2
    assert config.read_text() == ""
    found = tmp_path / ".n8n-doctor.toml"
    found.write_text("")
    assert main(["lint", str(tmp_path / "ok.json"), "-o", str(found), "--force"]) == 2
    assert found.read_text() == ""


def test_lint_never_replaces_the_file_stdin_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "s.json"
    source.write_text(WORKFLOW_TEXT)
    with source.open() as stdin:
        monkeypatch.setattr(sys, "stdin", stdin)
        assert main(["lint", "-", "-o", str(source), "--no-config", "-f", "json", "--force"]) == 2
    assert source.read_text() == WORKFLOW_TEXT


def test_lint_replaces_only_its_own_report_without_force(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = _folder(tmp_path) / "ok.json"
    report = tmp_path / "out"
    report.mkdir()
    for fmt in ("json", "sarif"):
        target = report / f"r.{fmt}"
        assert main(["lint", str(source), "-o", str(target), "--no-config", "-f", fmt]) == 0
        assert main(["lint", str(source), "-o", str(target), "--no-config", "-f", fmt]) == 0  # again: its own report
    other = report / "notes.json"
    other.write_text('{"keep": true}')
    assert main(["lint", str(source), "-o", str(other), "--no-config", "-f", "json"]) == 2
    assert other.read_text() == '{"keep": true}' and "--force" in capsys.readouterr().err
    text = report / "r.txt"
    text.write_text("my notes")
    assert main(["lint", str(source), "-o", str(text), "--no-config"]) == 2
    assert text.read_text() == "my notes"
    assert main(["lint", str(source), "-o", str(text), "--no-config", "--force"]) == 0
    assert text.read_text() != "my notes"


def test_lint_refuses_a_workflow_piped_in_from_its_own_output_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    source = tmp_path / "s.json"
    source.write_text(WORKFLOW_TEXT)
    monkeypatch.setattr(sys, "stdin", io.StringIO(WORKFLOW_TEXT))  # a pipe: not the same file, but no report either
    assert main(["lint", "-", "-o", str(source), "--no-config", "-f", "json"]) == 2
    assert source.read_text() == WORKFLOW_TEXT


def test_a_closed_stdout_is_a_clean_error(tmp_path: Path) -> None:
    import subprocess

    source = tmp_path / "s.json"
    source.write_text(WORKFLOW_TEXT)
    for args in (["lint", str(source), "--no-config"], ["explain", str(source), "--no-config"], ["rules"]):
        done = subprocess.run(
            [sys.executable, "-m", "n8n_doctor", *args], capture_output=False, stderr=subprocess.PIPE, text=True, preexec_fn=lambda: os.close(1), check=False
        )
        assert done.returncode == 2, (args, done.stderr)
        assert "stdout" in done.stderr and "Traceback" not in done.stderr and "internal error" not in done.stderr
