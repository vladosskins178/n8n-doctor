"""Writing output files without following symlinks or modifying linked files."""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any, TextIO


def write_text(path: Path, text: str, mode: int | None = None) -> None:
    """Write ``text`` to ``path`` through a temporary file and an atomic rename (see :func:`open_atomic`)."""
    with open_atomic(path, mode) as handle:
        handle.write(text)


_STREAM_FOLDERS = ("/proc/", "/dev/")
_DEVICE_FOLDER = Path("/dev")


def _check_target(path: Path) -> None:
    """Raise :class:`OSError` when a rename over ``path`` would destroy something other than a regular file: a device,
    fifo, socket or folder, a symlink resolving to one, or a symlink into /proc or /dev (``/dev/stdout`` resolves to a
    regular file when stdout is redirected to one, and the rename would replace the link itself). Nothing is written
    directly in /dev either: a typo such as ``/dev/nul`` would leave a regular file among the devices."""
    if path.absolute().parent.resolve() == _DEVICE_FOLDER.resolve():
        raise OSError(errno.EINVAL, "directly in the device folder, which holds devices, not files", str(path))
    not_regular = OSError(errno.EINVAL, "not a regular file", str(path))
    try:
        mode = path.stat().st_mode
    except (FileNotFoundError, NotADirectoryError):
        mode = None  # nothing there, or a dangling symlink, which the rename replaces
    if mode is not None and not stat.S_ISREG(mode):
        raise not_regular
    current = path.absolute()
    while current.is_symlink():  # it ends: the stat above raises on a symlink loop
        current = current.parent.resolve() / current.name
        target = current.parent / current.readlink()
        target = target.parent.resolve() / target.name  # also when dangling: /proc/self/fd/1 with stdout closed
        if str(current).startswith(_STREAM_FOLDERS) or str(target).startswith(_STREAM_FOLDERS):
            raise not_regular
        current = target


def check_writable(path: Path) -> None:
    """Raise :class:`OSError` unless a file can be written at ``path``: its folder must exist (it is never created),
    and what is at ``path`` must be a regular file, a symlink to one, or nothing (see :func:`_check_target`)."""
    parent = path.parent
    if not parent.is_dir():
        raise FileNotFoundError(errno.ENOENT, f"the folder {parent} does not exist", str(path))
    _check_target(path)
    if not os.access(parent, os.W_OK | os.X_OK):
        raise PermissionError(errno.EACCES, f"the folder {parent} is not writable", str(path))


@contextlib.contextmanager
def open_atomic(path: Path, mode: int | None = None) -> Iterator[TextIO]:
    """A text file to write ``path`` with, through a temporary file renamed over ``path`` when the block ends.

    The folder of ``path`` must exist and ``path`` must not be a device, fifo, socket or folder, or a symlink to one
    (see :func:`check_writable`). The rename replaces a regular file at ``path`` (a symlink or a hard link to another
    file is replaced, never written through), and readers never see a half-written file; when the block raises,
    ``path`` is left as it was. The file keeps the permissions of what it replaces; a new file gets ``mode``, or the
    usual ones (0666 less the umask). A copy of a private file must not come out readable by others.
    """
    check_writable(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        # errors="replace": a lone surrogate (a file name that is not UTF-8) cannot be written as UTF-8
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace", newline="\n") as handle:
            yield handle
        Path(tmp).chmod(_new_mode(path, mode))  # mkstemp creates 0600
        _check_target(path)  # again: writing a long report takes time
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def _new_mode(path: Path, mode: int | None) -> int:
    """The permissions of a file that replaces ``path`` (see :func:`open_atomic`)."""
    with contextlib.suppress(OSError):
        return stat.S_IMODE(path.stat().st_mode)
    if mode is not None:
        return mode
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


REPORT_MAX_BYTES = 256 * 1024 * 1024  # a longer file is not read to see whether it is a report
# The first line of a text or GitHub report written to a file: those formats have nothing else to tell them by, and a
# line without :: is ordinary log text to GitHub Actions.
REPORT_HEADER = "n8n-doctor report (a later lint -o may replace this file)\n"


def is_report(path: Path) -> bool:
    """Whether ``path`` holds a report of ``lint -o`` (JSON, SARIF, or text and GitHub by their first line), which a new report may replace."""
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > REPORT_MAX_BYTES:
            return False
        with path.open("rb") as raw:
            if raw.read(len(REPORT_HEADER)) == REPORT_HEADER.encode():
                return True
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError, RecursionError):
        return False
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("summary"), dict) and isinstance(data.get("findings"), list) and isinstance(data.get("workflows"), list) and "nodes" not in data:
        return True
    runs = data.get("runs")
    run = runs[0] if isinstance(runs, list) and runs else None
    tool = run.get("tool") if isinstance(run, dict) else None
    driver = tool.get("driver") if isinstance(tool, dict) else None
    return isinstance(driver, dict) and driver.get("name") == "n8n-doctor"


_C1 = re.compile("[\u0080-\u009f\u2028\u2029\ud800-\udfff]")


# lone surrogates (from \ud800 escapes in the input, or undecodable file names) are escaped too, so the text
# is valid UTF-8 wherever it is written
_C1_ESCAPES = {c: f"\\u{c:04x}" for c in [*range(0x80, 0xA0), 0x2028, 0x2029, *range(0xD800, 0xE000)]}


def json_copy(value: Any) -> Any:
    """A deep copy of JSON data (dicts, lists and scalars). Iterative, so a value nested deeper than the
    recursion limit (allowed with --max-depth up to 512) is copied too, unlike :func:`copy.deepcopy`."""
    root: list[Any] = [value]
    stack: list[tuple[Any, Any]] = [(root, 0)]
    while stack:
        container, key = stack.pop()
        current = container[key]
        if isinstance(current, dict):
            current = container[key] = dict(current)
            stack.extend((current, k) for k in current)
        elif isinstance(current, list):
            current = container[key] = list(current)
            stack.extend((current, i) for i in range(len(current)))
    return root[0]


def json_dumps(data: Any, indent: int | None = 2) -> str:
    """JSON with readable Unicode, but C1 control characters, line separators and lone surrogates escaped.

    ``ensure_ascii=False`` would leave characters such as U+009B (a terminal escape
    introducer on some terminals) raw in the output.
    """
    separators = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(data, indent=indent, ensure_ascii=False, separators=separators)
    return text.translate(_C1_ESCAPES) if _C1.search(text) else text


# A placeholder for a list that write_json_stream writes item by item (JSON-escaped, it cannot occur in other output).
STREAM_MARK = "\x00n8n-doctor-stream:"


def write_json_stream(write: Callable[[str], object], document: Any, streams: dict[str, Iterable[Any]]) -> None:
    """Write ``document`` as :func:`json_dumps` would, with each string ``STREAM_MARK + key`` in it replaced by a
    list of the items of ``streams[key]``, each dumped and written on its own. The text is the same as dumping
    the document with the lists in place, but no more than one item is in memory at a time. The placeholders
    must appear in the document in the order of ``streams``."""
    text = json_dumps(document)
    pos = 0
    for key, items in streams.items():
        mark = json_dumps(STREAM_MARK + key)
        at = text.index(mark, pos)
        write(text[pos:at])
        line = text[text.rfind("\n", 0, at) + 1 : at]
        base = len(line) - len(line.lstrip(" "))  # indentation of the line holding the list
        pad = "\n" + " " * (base + 2)
        first = True
        for item in items:
            write(("[" if first else ",") + pad + json_dumps(item).replace("\n", pad))  # JSON strings hold no raw newline
            first = False
        write("[]" if first else "\n" + " " * base + "]")
        pos = at + len(mark)
    write(text[pos:])
