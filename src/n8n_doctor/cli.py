"""Command line interface: ``n8n-doctor lint | explain | fix | executions | rules | mcp | skill``.

Exit codes: 0 ok, 1 findings at or above ``--fail-on`` (or failed executions found with
``executions --fail-on-errors``), 2 usage, input or API error, 3 ``executions`` results cut short (``--timeout``, a repeated pagination cursor).
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import stat
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .api import RUN_TIMEOUT, ApiError, Client
from .config import FAIL_ON, Config, ConfigError, find_config
from .config import load as load_config
from .files import REPORT_HEADER, check_writable, is_report, json_dumps, open_atomic, write_text
from .limits import DEFAULT, EXECUTIONS_ONLY, EXPLAIN_ONLY, LINT_ONLY, MAX_TIMEOUT_MS, MB, SETTINGS, Limits, with_settings
from .model import Finding, Severity, plural
from .report import ClosedStdout, Style, guard_commands, safe_text, use_color, write_stdout
from .workflow import Workflow, WorkflowError, from_data, parse_export

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
EXIT_INCOMPLETE = 3  # executions: --timeout ran out or pagination stalled; the results read until then are printed
API_MAX_WORKFLOWS = 1000  # workflows `lint --api` reads by default (--max-workflows)

_D = DEFAULT
# --help text of each resource limit flag, in the order --help lists them (defaults from limits.DEFAULT)
LIMIT_HELP = {
    "max-file-mb": f"largest input file in MB (default: {_D.max_file_bytes // MB}, at most 64)",
    "max-workflows-per-file": f"most workflows in one file (default: {_D.max_workflows:,})",
    "max-depth": f"deepest nesting of JSON arrays and objects (default: {_D.max_depth})",
    "max-nodes": f"most nodes per workflow (default: {_D.max_nodes:,})",
    "max-file-nodes": f"most nodes plus workflows in one file, embedded ones included (default: {_D.max_file_nodes:,})",
    "max-connections": f"most connections, and connection output lists, per workflow (default: {_D.max_connections:,})",
    "max-outputs": f"most outputs of one node, Switch rules included (default: {_D.max_outputs:,})",
    "max-targets-per-output": f"most connections from one output (default: {_D.max_targets:,})",
    "max-name-length": f"longest node or workflow name, node type or workflow id (default: {_D.max_name_chars:,})",
    "max-path-length": f"longest path of a value in node parameters (default: {_D.max_path_chars:,})",
    "max-parameter-values": f"most values in all node parameters of a workflow (default: {_D.max_parameter_values:,})",
    "max-list-length": f"longest array in node parameters (default: {_D.max_list_length:,})",
    "max-value-kb": f"longest value fully checked for secrets in KB (default: {_D.max_value_chars // 1024}); longer ones are checked at both ends",
    "max-secrets": f"most distinct secrets in a workflow's parameters (default: {_D.max_secrets:,})",
    "max-secret-kb": f"their largest total length in KB (default: {_D.max_secret_chars // 1024:,})",
    "max-raw-scan-mb": f"embedded text that does not parse read per file in MB (default: {_D.max_raw_scan_bytes // MB}); the rest is reported as not checked",
    "max-code-kb": f"Code node source analysed in KB (default: {_D.max_code_chars // 1024:,}); the rest is reported as not checked",
    "max-findings-per-rule": f"findings listed per rule and workflow (default: {_D.max_findings_per_rule}); the rest are counted",
    "max-findings": f"findings listed per workflow (default: {_D.max_findings:,}); the rest are counted",
    "max-findings-total": f"findings listed in the whole run (default: {_D.max_findings_total:,}); the rest are counted",
    "max-explain-depth": f"tree levels before branches stop indenting (default: {_D.max_explain_depth})",
    "max-output-kb": f"explain output size in KB per run (all workflows together) before it is truncated (default: {_D.max_output_bytes // 1024:,})",
    "max-masker-mb": f"workflow JSON read per run to mask workflow secrets in messages, in MB (default: {_D.max_masker_chars // MB}); "
    "past it, messages are hidden",
}


class UsageError(Exception):
    pass


def _cannot_write(path: Path | str, exc: OSError, stdout_hint: bool = False) -> UsageError:
    hint = " (for standard output use -o -)" if stdout_hint and exc.errno == errno.EINVAL else ""
    return UsageError(f"cannot write {safe_text(str(path))}: {exc.strerror or exc}{hint}")


def _same_file(path: Path, other: Path) -> bool:
    try:
        return path.samefile(other)
    except OSError:
        return False


def _stdin_is(path: Path) -> bool:
    """Whether stdin reads the file at ``path``: ``lint - -o s.json < s.json``."""
    try:
        here, there = os.fstat(sys.stdin.fileno()), path.stat()
    except (OSError, ValueError, AttributeError):  # closed, or not a real file (a pipe has no path to compare)
        return False
    return (here.st_dev, here.st_ino) == (there.st_dev, there.st_ino)


def _check_report_target(path: Path, args: argparse.Namespace, cfg_path: Path | None) -> None:
    """What ``lint -o`` may replace. Never what this run reads or could have read: a file it was given, stdin's file or
    the config file; in a folder, a JSON file unless it is an earlier report. Any other existing file only if it is
    an earlier report (JSON, SARIF, or text and GitHub by their first line), or with ``--force``. A symlink to another file counts as
    nothing there: the rename replaces the link and leaves that file as it is."""
    if not path.exists():
        return
    paths = [] if getattr(args, "api", False) else args.paths or ["."]
    if (
        any(p != "-" and Path(p).is_file() and _same_file(path, Path(p)) for p in paths)
        or _stdin_is(path)
        or (cfg_path is not None and _same_file(path, cfg_path))
    ):
        raise UsageError("refusing to write the report over an input file; choose another --output")
    own = is_report(path)
    if not own and any(Path(p).is_dir() and any(_same_file(path, q) for q in _json_files(Path(p), path)) for p in paths if p != "-"):
        raise UsageError("refusing to write the report over an input file; choose another --output")
    if not own and not args.force and not path.is_symlink():
        raise UsageError(f"{safe_text(str(path))} already exists and is not an n8n-doctor report; use --force to replace it")


def _json_files(folder: Path, target: Path) -> Iterator[Path]:
    """The JSON files of ``folder`` a scan looks at, when ``target`` can be one of them."""
    from .workflow import iter_json_files

    return iter_json_files(folder) if target.name.lower().endswith(".json") else iter(())


def _writable(path: Path, stdout_hint: bool = False) -> None:
    """Fail before any work is shown when ``path`` cannot be written (missing folder, a folder, no permission)."""
    try:
        check_writable(path)
    except OSError as exc:
        raise _cannot_write(path, exc, stdout_hint) from None


def _err(message: str) -> None:
    """Every error goes out through here: masked (names and paths can hold secrets) and without control characters."""
    from .rules import redact

    if sys.stderr is not None:  # closed with 2>&-
        sys.stderr.write(f"n8n-doctor: {safe_text(redact(message))}\n")


def _shorten(text: str, limit: int = 80) -> str:
    from .rules import shorten

    return shorten(text, limit)


def _resolve_id(ref: str) -> str:
    from .rules import resolve

    return resolve(ref).id


def _config(args: argparse.Namespace, anchor: Path) -> Config:
    """The config file's settings, with resource limits given on the command line applied over them."""
    if getattr(args, "no_config", False):
        cfg = Config()
    else:
        path = Path(args.config) if getattr(args, "config", None) else find_config(anchor)
        if getattr(args, "config", None) and not Path(args.config).is_file():
            raise UsageError(f"{args.config}: config file not found")
        cfg = load_config(path, _resolve_id)
    given = {key: getattr(args, key.replace("-", "_")) for key in SETTINGS if getattr(args, key.replace("-", "_"), None) is not None}
    if given:
        try:
            cfg.limits = with_settings(cfg.limits, given, "command line")
        except ValueError as exc:
            raise UsageError(str(exc).replace("command line: ", "--")) from None
    return cfg


def _anchor(path: str | None) -> Path:
    """Where to look for a config file: the first input, if it exists, else the working directory."""
    anchor = Path(path) if path and path != "-" else Path.cwd()
    return anchor if anchor.exists() else Path.cwd()


def _repo_root(start: Path) -> Path:
    """The repository root above ``start`` (SARIF paths must be relative to it), else ``start``."""
    for folder in (start, *start.parents):
        if (folder / ".git").exists():
            return folder
    return start


def _rule_set(refs: Sequence[str] | None) -> set[str]:
    out: set[str] = set()
    for chunk in refs or ():
        for ref in chunk.split(","):
            if ref.strip():
                try:
                    out.add(_resolve_id(ref.strip()))
                except KeyError:
                    raise UsageError(f"unknown rule {_shorten(ref.strip(), 40)!r} (see `n8n-doctor rules`)") from None
    return out


# a line that starts a JSON array of objects or a JSON object with a key ("[", "[{", "{", '{"name"'), not "[WARN] ..."
def _read_stdin(limits: Limits) -> list[Workflow]:
    text = sys.stdin.read(limits.max_file_bytes + 1)  # a longer input is refused by parse_export without reading all of it
    return parse_export(text, "<stdin>", limits)


def _api_workflows(args: argparse.Namespace, limits: Limits) -> tuple[list[Workflow], bool]:
    """The workflows to check, and whether the instance has more than --max-workflows of them (the rest are not read)."""
    client = Client.from_env(args.api_url, getattr(args, "timeout", RUN_TIMEOUT))
    flows: list[Workflow] = []
    if args.workflow_id:
        for wid in args.workflow_id:
            flows.extend(from_data(client.workflow(wid), f"<api>/workflows/{wid}", limits=limits))
        return flows, False
    most = args.max_workflows or API_MAX_WORKFLOWS
    for i, data in enumerate(client.workflows(active_only=args.active_only, max_items=most + 1)):  # one more: are there more?
        if i == most:
            return flows, True
        wid = data.get("id", i)
        flows.extend(from_data(data, f"<api>/workflows/{wid}", limits=limits))
    return flows, False


def _load_targets(args: argparse.Namespace, cfg: Config) -> tuple[list[Workflow], list[str], list[str], bool]:
    """(workflows, skipped files, files that could not be checked, whether --api stopped at --max-workflows).
    A file that cannot be checked does not stop the others; with no workflow left to check it is an error of the run."""
    from .lint import collect

    if getattr(args, "api", False):
        if args.paths:
            raise UsageError("--api reads workflows from the n8n instance; do not pass paths too")
        got, more = _api_workflows(args, cfg.limits)
        return got, [], [], more
    paths = args.paths or ["."]
    flows: list[Workflow] = []
    skipped: list[str] = []
    errors: list[str] = []
    files = [p for p in paths if p != "-"]
    if "-" in paths:
        flows.extend(_read_stdin(cfg.limits))
    if files:
        got, skipped, errors = collect([Path(p) for p in files], cfg)
        if errors and not got and not flows:
            raise UsageError("; ".join(errors))
        flows.extend(got)
    return flows, skipped, errors, False


def cmd_lint(args: argparse.Namespace) -> int:
    from . import lint, report
    from .rules import RULES

    cfg = _config(args, _anchor(args.paths[0] if args.paths else None))
    if args.select:
        cfg.enabled_only = _rule_set(args.select)
    cfg.disabled |= _rule_set(args.ignore)
    fail_on = args.fail_on or cfg.fail_on
    # "-" is stdout, the way paths read "-" as stdin (./- names a file called -)
    out_path = Path(args.output) if args.output and args.output != "-" else None
    if out_path is not None:
        anchor = _anchor(args.paths[0] if args.paths else None)
        config_file = None if args.no_config else Path(args.config) if args.config else find_config(anchor)
        _writable(out_path, stdout_hint=True)  # first: what follows reads the file, and a fifo would block
        _check_report_target(out_path, args, config_file)
    flows, skipped, errors, more = _load_targets(args, cfg)
    if not flows and getattr(args, "api", False):
        write_stdout("No workflows on the instance match (nothing to check).\n")
        return EXIT_OK
    excluded = [s for s in skipped if s.endswith(lint.EXCLUDED)]
    if not flows and excluded:
        raise UsageError("; ".join(excluded))
    not_flows = [s for s in skipped if not s.endswith(lint.EXCLUDED)]
    if not flows:
        raise UsageError("no n8n workflows found" + (f" ({plural(len(not_flows), 'JSON file')} skipped; use --verbose to list them)" if not_flows else ""))
    for note in excluded:
        sys.stderr.write(f"n8n-doctor: {safe_text(note)}\n")
    suppressed: list[Finding] = []
    minimum = Severity.parse(args.min_severity) if args.min_severity else None
    # the filter applies before the per-rule and per-workflow limits, so the counts of omitted findings match it
    findings = lint.run(flows, cfg, suppressed, inline_suppressions=not args.no_inline_suppress, min_severity=minimum)
    labels = lint.labels(flows)
    inputs = {*(p for p in args.paths if p != "-"), *(wf.source for wf in flows)}  # the files of a folder too
    if out_path is not None and out_path.exists() and any(Path(p).is_file() and out_path.samefile(p) for p in inputs):
        raise UsageError("refusing to write the report over an input file; choose another --output")
    if args.format in ("json", "sarif"):
        # written as a stream, one finding at a time: the report is never held in memory as a whole
        def write_report(write: report.Write) -> None:
            if args.format == "json":
                report.write_json(write, findings, labels, skipped, suppressed, errors)
            else:
                report.write_sarif(write, findings, [r.meta for r in RULES], _repo_root(Path.cwd()), suppressed, errors)

        if out_path is None:
            write_report(write_stdout)
        else:
            try:
                with open_atomic(out_path) as handle:
                    write_report(handle.write)
            except BrokenPipeError:
                raise
            except OSError as exc:
                raise _cannot_write(out_path, exc) from None
    else:
        if args.format == "github":
            out = report.render_github(findings, errors)
        else:
            style = Style(use_color(sys.stdout, args.color) and out_path is None)
            out = report.render_text(findings, labels, style, args.verbose, suppressed, errors)
            if args.verbose and not_flows:
                out += "\nSkipped (not workflows):\n" + "".join(f"  {safe_text(s)}\n" for s in not_flows)
            elif not_flows:
                what = "that is not an n8n workflow" if len(not_flows) == 1 else "that are not n8n workflows"
                sys.stderr.write(f"n8n-doctor: skipped {plural(len(not_flows), 'JSON file')} {what} (--verbose lists them)\n")
            out = guard_commands(out)
        if out_path is not None:
            try:
                write_text(out_path, REPORT_HEADER + out)  # the header lets a later run replace this file
            except OSError as exc:
                raise _cannot_write(out_path, exc) from None
        else:
            write_stdout(out)
    if out_path is not None and args.format != "text":
        sys.stderr.write(f"n8n-doctor: wrote {out_path} ({plural(report.total(findings), 'finding')})\n")
    if errors:  # after the report: the other files were checked, but the run is not clean
        _err(f"{plural(len(errors), 'file')} could not be checked (listed in the report)")
        return EXIT_USAGE
    if more:
        most = args.max_workflows or API_MAX_WORKFLOWS
        _err(f"warning: the instance has more than {plural(most, 'workflow')}; only the first {most:,} were checked (raise --max-workflows)")
        if not args.max_workflows:  # the default cap: the run did not check everything it was asked to
            return EXIT_USAGE
    if fail_on == "never":
        return EXIT_OK
    threshold = Severity.parse(fail_on)
    return EXIT_FINDINGS if any(f.severity >= threshold for f in findings) else EXIT_OK


def _single_workflow(args: argparse.Namespace, limits: Limits) -> list[Workflow]:
    if getattr(args, "api", False):
        if not args.workflow_id:
            raise UsageError("--api needs --workflow-id")
        return _api_workflows(args, limits)[0]
    if not args.file:
        raise UsageError("pass a workflow file (or - for stdin)")
    if args.file == "-":
        return _read_stdin(limits)
    path = Path(args.file)
    if path.is_dir():
        raise UsageError(f"{path}: expected a workflow file, got a folder")
    from .workflow import load_file

    return load_file(path, limits, recover=True)


def cmd_explain(args: argparse.Namespace) -> int:
    from . import explain

    flows = _single_workflow(args, _config(args, _anchor(args.file)).limits)
    if args.format == "mermaid":
        write_stdout(explain.mermaids(flows))
    elif args.format == "json":
        write_stdout(json_dumps([explain.as_dict(w) for w in flows]) + "\n")
    else:
        enc = (getattr(sys.stdout, "encoding", None) or "").lower()
        unicode = not args.ascii and "utf" in enc
        write_stdout(guard_commands(explain.outlines(flows, unicode)))
    return EXIT_OK


def cmd_fix(args: argparse.Namespace) -> int:
    from .fix import fix_workflow

    if args.file == "-" and args.write:
        raise UsageError("--write needs a file, not stdin")
    dest: Path | None = None
    if args.write:
        src = Path(args.file)
        if args.output == "-":
            raise UsageError("--write -o - is not supported: stdout carries the diff; name a file (./- for a file called -)")
        dest = Path(args.output) if args.output else src.with_name(src.stem + ".fixed" + (src.suffix or ".json"))
        _writable(dest)
        if dest.resolve() == src.resolve():
            raise UsageError("refusing to overwrite the input file; choose another --output")
        if (dest.exists() or dest.is_symlink()) and not args.force:
            raise UsageError(f"{dest} already exists (use --force to replace it)")
    elif args.output or args.force:
        raise UsageError("--output and --force only apply with --write")
    if args.include_patch and args.format != "json":
        raise UsageError("--include-patch only applies with --format json")
    if args.set_timeout is not None and not 0 < args.set_timeout <= MAX_TIMEOUT_MS:
        raise UsageError(f"--set-timeout takes a number of milliseconds from 1 to {MAX_TIMEOUT_MS}")
    cfg = _config(args, _anchor(args.file))
    flows = _single_workflow(args, cfg.limits)
    selected = _rule_set(args.rule) or None
    if len(flows) != 1:
        raise UsageError(f"{args.file}: holds {len(flows)} workflows; fix works on one workflow per file (split it, or use n8n export:workflow --backup)")
    result = fix_workflow(flows[0], selected, cfg, args.set_timeout)
    if result.unwritable and (args.write or args.include_patch):
        raise UsageError(result.unwritable)
    if result.unwritable and result.changes:
        sys.stderr.write(f"n8n-doctor: the fixes below cannot be saved: {result.unwritable}\n")
    style = Style(use_color(sys.stdout, args.color))
    skipped = [style.dim(f"  - {note}") for note in result.skipped]
    if args.format == "json":
        # changes, edits and diff are for reading (masked, no whole values); patch, the raw RFC 6902 JSON Patch with
        # the file's secrets, only on request
        payload: dict[str, Any] = {"changes": result.changes, "skipped": result.skipped, "edits": [e.as_dict() for e in result.edits], "diff": result.diff}
        if args.include_patch:
            payload["patch"] = result.patch
        write_stdout(json_dumps(payload) + "\n")
    elif not result.changes:
        write_stdout(guard_commands("\n".join(["Nothing to fix automatically.", *(["Skipped:", *skipped] if skipped else [])]) + "\n"))
    else:
        lines = [style.bold(f"{plural(len(result.changes), 'change')}:")] + [f"  - {safe_text(c)}" for c in result.changes]
        lines += (["Skipped:", *skipped] if skipped else []) + [""]
        lines += [style.bold(line) if not line.startswith(" ") else line for line in result.diff.splitlines()]
        write_stdout(guard_commands("\n".join(lines) + "\n"))
    if not args.write or not result.changes:
        if result.changes and args.format != "json":
            sys.stderr.write("n8n-doctor: dry run, nothing written (add --write to save a fixed copy)\n")
        return EXIT_OK
    assert dest is not None
    try:
        write_text(dest, result.fixed_text, stat.S_IMODE(Path(args.file).stat().st_mode))  # no wider than the file it comes from
    except OSError as exc:
        raise _cannot_write(dest, exc) from None
    sys.stderr.write(f"n8n-doctor: wrote {dest}; import it into n8n or replace the original after review\n")
    return EXIT_OK


def cmd_executions(args: argparse.Namespace) -> int:
    from .executions import render_text, summarize

    cfg = _config(args, Path.cwd())
    client = Client.from_env(args.api_url, getattr(args, "timeout", RUN_TIMEOUT))
    result = summarize(
        client, args.workflow_id, args.limit, status=args.status, masker_budget=cfg.limits.max_masker_chars, pattern_only=args.pattern_masking_only
    )
    if args.format == "json":
        write_stdout(json_dumps(result) + "\n")
    else:
        write_stdout(guard_commands(render_text(result, Style(use_color(sys.stdout, args.color)))))
    if result.get("incomplete"):
        sys.stderr.write(f"n8n-doctor: warning: results are incomplete, {result['incomplete']}\n")
        return EXIT_INCOMPLETE
    return EXIT_FINDINGS if args.fail_on_errors and result["groups"] else EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules import RULES

    if args.format == "json":
        payload = [
            {
                "id": r.meta.id,
                "name": r.meta.name,
                "severity": r.meta.severity.label,
                "summary": r.meta.summary,
                "fix": r.meta.fix,
                "fixable": r.meta.fixable,
                "docs": r.meta.doc_url,
            }
            for r in RULES
        ]
        write_stdout(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK
    style = Style(use_color(sys.stdout, args.color))
    for r in RULES:
        mark = " (fixable)" if r.meta.fixable else ""
        write_stdout(f"{style.bold(r.meta.id)}  {style.severity(r.meta.severity)} {r.meta.name}{mark}\n         {r.meta.summary}\n")
    return EXIT_OK


def _skill_text(frontmatter: bool) -> str:
    from importlib import resources

    candidates = [Path(__file__).resolve().parents[2] / "skills" / "n8n-doctor" / "SKILL.md"]
    text = None
    for c in candidates:
        if c.is_file():
            text = c.read_text(encoding="utf-8")
            break
    if text is None:
        text = resources.files("n8n_doctor").joinpath("skill/SKILL.md").read_text(encoding="utf-8")
    if not frontmatter and text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            text = text[end + 4 :].lstrip("\n")
    return text


def cmd_skill(args: argparse.Namespace) -> int:
    if args.action == "print":
        write_stdout(_skill_text(args.frontmatter))
        return EXIT_OK
    dest_dir = Path(args.dest).expanduser() if args.dest else Path.home() / ".claude" / "skills" / "n8n-doctor"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "SKILL.md"
    try:
        write_text(dest, _skill_text(True))
    except OSError as exc:
        raise _cannot_write(dest, exc) from None
    sys.stderr.write(f"n8n-doctor: installed the skill at {dest}\n")
    return EXIT_OK


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp import serve

    return serve()


def _add_api_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--api-url", help="n8n base URL (default: $N8N_API_URL); the key is always read from $N8N_API_KEY")
    p.add_argument(
        "--timeout",
        type=_seconds,
        default=RUN_TIMEOUT,
        metavar="SECONDS",
        help=f"stop when the n8n API calls take longer than this in all (default: {RUN_TIMEOUT:.0f})",
    )


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text!r}") from None
    if not 0 < value <= 86_400:
        raise argparse.ArgumentTypeError("must be more than 0 and at most 86400 seconds")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="n8n-doctor",
        description="Find problems in n8n workflows before they fail in production. Works on exported workflow JSON; "
        "optional read-only access to an n8n instance via N8N_API_URL and N8N_API_KEY.",
    )
    parser.add_argument("--version", action="version", version=f"n8n-doctor {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")
    color = argparse.ArgumentParser(add_help=False)
    color.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour output (default: auto; NO_COLOR is honoured)")

    def limit_flags(command: str) -> argparse.ArgumentParser:
        """The resource limit flags ``command`` uses (see limits.SETTINGS; the config file accepts them all)."""
        parent = argparse.ArgumentParser(add_help=False)
        group = parent.add_argument_group("resource limits", "override the defaults and the config file's [limits]; see the README")
        for key, help_text in LIMIT_HELP.items():
            only = (LINT_ONLY, "lint"), (EXPLAIN_ONLY, "explain"), (EXECUTIONS_ONLY, "executions")
            if any(key in keys and command != owner for keys, owner in only) or (command == "executions" and key not in EXECUTIONS_ONLY):
                continue
            group.add_argument(f"--{key}", type=int, metavar="N", help=help_text)
        return parent

    p = sub.add_parser("lint", parents=[color, limit_flags("lint")], help="check workflows and report problems", description="Check workflow files or folders.")
    p.add_argument("paths", nargs="*", help="workflow .json files or folders (default: .); - reads stdin")
    p.add_argument("--format", "-f", choices=["text", "json", "sarif", "github"], default="text", help="github: workflow-command annotations")
    p.add_argument("--output", "-o", help="write the report to this regular file (- is stdout); an existing file only if it is an earlier report of n8n-doctor")
    p.add_argument("--force", action="store_true", help="with --output: replace an existing file that is no report (never one this run reads)")
    p.add_argument("--fail-on", choices=FAIL_ON, help="lowest severity that makes the exit code 1 (default: error, or the config file)")
    p.add_argument("--min-severity", choices=["error", "warning", "info"], help="only report findings at or above this severity")
    p.add_argument("--select", action="append", metavar="RULES", help="only run these rules (ids or names, comma separated)")
    p.add_argument("--ignore", action="append", metavar="RULES", help="skip these rules (ids or names, comma separated)")
    p.add_argument("--config", help="config file (default: nearest .n8n-doctor.toml)")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    p.add_argument("--verbose", "-v", action="store_true", help="also list clean workflows, skipped files and suppressed findings")
    p.add_argument(
        "--no-inline-suppress",
        action="store_true",
        help="ignore n8n-doctor-disable in node notes and sticky notes (use when checking workflows from others)",
    )
    p.add_argument("--api", action="store_true", help="lint workflows from the n8n instance (read-only)")
    p.add_argument("--workflow-id", action="append", help="with --api: only this workflow (repeatable)")
    p.add_argument("--active-only", action="store_true", help="with --api: only active workflows")
    p.add_argument(
        "--max-workflows",
        type=int,
        metavar="N",
        help=f"with --api: read at most N workflows (default: {API_MAX_WORKFLOWS:,}; with more on the instance the run fails unless N is given)",
    )
    _add_api_options(p)
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser(
        "explain",
        parents=[color, limit_flags("explain")],
        help="outline what a workflow does",
        description="Outline a workflow: triggers, branches, loops, ends.",
    )
    p.add_argument("file", nargs="?", help="workflow .json file (- for stdin)")
    p.add_argument("--config", help="config file (default: nearest .n8n-doctor.toml); only its [limits] apply")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    p.add_argument("--format", "-f", choices=["text", "mermaid", "json"], default="text")
    p.add_argument("--ascii", action="store_true", help="draw the tree with ASCII characters")
    p.add_argument("--api", action="store_true", help="read the workflow from the n8n instance (needs --workflow-id)")
    p.add_argument("--workflow-id", action="append", help="with --api: the workflow to explain")
    p.add_argument("--active-only", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--max-workflows", type=int, help=argparse.SUPPRESS)
    _add_api_options(p)
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser(
        "fix",
        parents=[color, limit_flags("fix")],
        help="show the changes for auto-fixable findings (dry run)",
        description="Show the changes for the auto-fixable findings. Nothing is written unless --write is given, "
        "and then only to a new file (default: <name>.fixed.json); the input is never modified.",
    )
    p.add_argument("file", help="workflow .json file (- for stdin)")
    p.add_argument("--dry-run", action="store_true", help="the default; accepted for explicitness")
    p.add_argument("--write", action="store_true", help="save the fixed workflow to a new file")
    p.add_argument("--output", "-o", help="with --write: where to save (default: <name>.fixed.json next to the input)")
    p.add_argument("--force", action="store_true", help="with --write: replace an existing output file")
    p.add_argument(
        "--set-timeout",
        type=int,
        metavar="MS",
        help="also set this timeout on HTTP Request nodes without one (N8D302); never by default, as long requests can need n8n's 5 minutes",
    )
    p.add_argument("--rule", "--select", dest="rule", action="append", metavar="RULES", help="only apply fixes for these rules (ids or names, comma separated)")
    p.add_argument(
        "--format",
        "-f",
        choices=["text", "diff", "json"],
        default="text",
        help="text (default; diff is the same): the changes, then each changed value with only the changed token. "
        "json: the same as changes/edits/diff (log-safe)",
    )
    p.add_argument(
        "--include-patch",
        action="store_true",
        help="with --format json: add patch, the raw RFC 6902 JSON Patch; it copies values from the file, secrets included, so it is not log-safe",
    )
    p.add_argument("--config", help="config file (default: nearest .n8n-doctor.toml); disabled rules are not fixed")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    p.set_defaults(func=cmd_fix, api=False)

    p = sub.add_parser(
        "executions",
        parents=[color, limit_flags("executions")],
        help="group recent failed executions on an n8n instance (read-only)",
        description="Summarize recent failed executions from the n8n public API, grouped by workflow, node and error. "
        "Reads N8N_API_URL and N8N_API_KEY; only GET requests are made.",
    )
    p.add_argument("--workflow-id", help="only this workflow")
    p.add_argument("--limit", type=int, default=100, help="how many recent executions to read (default: 100, max 1000)")
    p.add_argument("--status", choices=["error", "crashed", "canceled"], default="error", help=argparse.SUPPRESS)
    p.add_argument("--format", "-f", choices=["text", "json"], default="text")
    p.add_argument("--fail-on-errors", action="store_true", help="exit 1 if any failed execution was found")
    p.add_argument(
        "--pattern-masking-only",
        action="store_true",
        help="less safe: when a workflow's secrets cannot be checked (see --max-masker-mb), show its messages masked by the "
        "secret patterns only instead of hiding them; secrets that exist only in the workflow can then show",
    )
    p.add_argument("--config", help="config file (default: nearest .n8n-doctor.toml); only its [limits] apply")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    _add_api_options(p)
    p.set_defaults(func=cmd_executions)

    p = sub.add_parser("rules", parents=[color], help="list the rules", description="List every rule with its id, default severity and summary.")
    p.add_argument("--format", "-f", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser(
        "mcp",
        help="run the MCP server on stdio",
        description="Serve n8n_lint, n8n_explain, n8n_fix and n8n_executions as Model Context Protocol tools over stdio.",
    )
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser(
        "skill",
        help="print or install the agent skill (SKILL.md)",
        description="print: write the skill to stdout (for AGENTS.md and other rule files); install: copy it to ~/.claude/skills.",
    )
    p.add_argument("action", choices=["print", "install"])
    p.add_argument("--dest", help="install folder (default: ~/.claude/skills/n8n-doctor)")
    p.add_argument("--frontmatter", action="store_true", help="with print: keep the YAML front matter")
    p.set_defaults(func=cmd_skill)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    if getattr(args, "max_workflows", None) is not None and args.max_workflows < 1:
        _err("--max-workflows must be at least 1")
        return EXIT_USAGE
    if getattr(args, "limit", None) is not None and not 1 <= args.limit <= 1000:
        _err("--limit must be from 1 to 1000")
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except (UsageError, WorkflowError, ConfigError, ApiError, ValueError) as exc:
        _err(str(exc))
        return EXIT_USAGE
    except BrokenPipeError:
        return EXIT_OK
    except ClosedStdout:
        _err("cannot write to stdout: it is closed")
        return EXIT_USAGE
    except OSError as exc:  # a file that could not be read or written (written files are named by _cannot_write)
        where = f" {safe_text(str(exc.filename))}" if exc.filename else ""
        _err(f"cannot access{where}: {exc.strerror or exc}")
        return EXIT_USAGE
    except RecursionError:
        _err("input nested too deeply")
        return EXIT_USAGE
    except Exception as exc:  # never let a crash look like "findings" (exit 1) to CI
        _err(f"internal error: {type(exc).__name__}: {exc} (please report this with the workflow that caused it)")
        return EXIT_USAGE
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
