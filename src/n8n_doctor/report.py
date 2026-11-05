"""Rendering lint results as text, JSON or SARIF 2.1.0."""

from __future__ import annotations

import functools
import os
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .files import STREAM_MARK, write_json_stream
from .model import Finding, Rule, Severity, plural

INFO_URI = "https://github.com/vladosskins178/n8n-doctor"


def use_color(stream: TextIO, mode: str = "auto") -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty() and os.environ.get("TERM") != "dumb"


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31;1", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33;1", text)

    def blue(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32;1", text)

    def severity(self, sev: Severity) -> str:
        label = f"{sev.label:<7}"
        return {Severity.ERROR: self.red, Severity.WARNING: self.yellow, Severity.INFO: self.blue}[sev](label)


def counts(findings: Sequence[Finding]) -> dict[str, int]:
    """Findings by severity; a summary of findings past the per-rule limit counts as the findings it stands for."""
    out = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        omitted = f.extra.get("omitted")
        if omitted:
            for label, n in omitted.items():
                out[label] += n
        else:
            out[f.severity.label] += 1
    return out


def fixable(findings: Sequence[Finding]) -> int:
    """How many of the findings ``fix`` can fix (those past the per-rule limit included)."""
    return sum(f.extra["omitted_fixable"] if f.extra.get("omitted") else int(f.fixable) for f in findings)


def total(findings: Sequence[Finding]) -> int:
    """How many findings ``findings`` stands for (see :func:`counts`)."""
    return sum(counts(findings).values())


def run_summaries(findings: Sequence[Finding]) -> list[Finding]:
    """The summaries of findings past the per-run limit (:func:`lint.run` lists them last; they belong to no workflow)."""
    return [f for f in findings[-1:] if f.extra.get("run_summary")]


def not_listed(findings: Sequence[Finding]) -> int:
    """How many findings the per-run limit left out of ``findings``."""
    return sum(sum(f.extra["omitted"].values()) for f in run_summaries(findings))


def safe_text(value: str) -> str:
    """Drop control characters (terminal escape sequences) from workflow-supplied text."""
    return "".join(ch if ch.isprintable() or ch == " " else "?" for ch in value)


def render_text(
    findings: Sequence[Finding],
    workflows: Sequence[tuple[str, str, int]],
    style: Style,
    verbose: bool = False,
    suppressed: Sequence[Finding] = (),
    errors: Sequence[str] = (),
) -> str:
    """``workflows`` lists (source label, workflow name, node count) for every workflow checked; ``errors``
    the files that could not be checked (malformed, or over a limit)."""
    lines: list[str] = []
    explained: set[str] = set()
    by_label: dict[str, list[Finding]] = {}
    for f in findings:
        label = f.source + (f"[{f.position}]" if f.position else "")
        by_label.setdefault(label, []).append(f)
    for label, name, n_nodes in workflows:
        group = by_label.get(label, [])
        if not group and not verbose:
            continue
        lines.append(f"{style.bold(safe_text(label))}  {style.dim(safe_text(name) + ', ' + plural(n_nodes, 'node'))}")
        if not group:
            lines.append(f"  {style.green('ok')}")
        for f in sorted(group, key=lambda x: (bool(x.extra.get("summary")), x.line, -x.severity, x.rule.id)):  # summaries last
            where = f":{f.line}" if f.line > 1 else ""
            node = f'"{safe_text(f.node)}" ' if f.node else ""
            lines.append(f"  {style.severity(f.severity)} {style.bold(f.rule.id)} {style.dim(f.rule.name + where)}  {node}{safe_text(f.message)}")
            if f.fix_hint or f.rule.id not in explained:  # the generic fix is shown once per rule
                lines.append(f"  {'':7} {style.dim('fix: ' + safe_text(f.fix_hint or f.rule.fix))}")
                explained.add(f.rule.id)
            else:
                lines.append(f"  {'':7} {style.dim('fix: as above')}")
        lines.append("")
    for f in run_summaries(findings):
        lines.append(f"{style.severity(f.severity)} {style.bold(f.rule.id)} {style.dim(f.rule.name)}  {safe_text(f.message)}")
        lines.append(f"{'':7} {style.dim('fix: raise --max-findings-total (max-findings-total in [limits]), or fix or filter the findings listed first')}")
        lines.append("")
    c = counts(findings)
    n_total = sum(c.values())
    n_fixable = fixable(findings)
    n_wf = len(workflows)
    if n_total == 0:
        lines.append(style.green(f"No problems found in {plural(n_wf, 'workflow')}."))
    else:
        parts = [
            f"{c['error']:,} error{'s' if c['error'] != 1 else ''}",
            f"{c['warning']:,} warning{'s' if c['warning'] != 1 else ''}",
            f"{c['info']:,} info",
        ]
        summary = f"{plural(n_total, 'problem')} ({', '.join(parts)}) in {plural(n_wf, 'workflow')}."
        lines.append(style.bold(summary))
        if n_fixable:
            lines.append(style.dim(f"{n_fixable:,} can be fixed automatically: n8n-doctor fix <file> shows the changes (one workflow per file)."))
    if suppressed:
        lines.append(
            style.yellow(f"{plural(total(suppressed), 'finding')} suppressed by n8n-doctor-disable notes in the workflow")
            + style.dim(" (--no-inline-suppress reports them)")
        )
        if verbose:
            for f in suppressed:
                lines.append(f'  {safe_text(f.source)}: {f.rule.id} {f.rule.name} "{safe_text(f.node or "")}" ({f.suppressed})')
    if errors:
        lines.append(style.red(style.bold(f"{plural(len(errors), 'file')} could not be checked:")))
        lines.extend(f"  {style.severity(Severity.ERROR)} {safe_text(e)}" for e in errors)
    return "\n".join(lines) + "\n"


Write = Callable[[str], object]


def write_json(
    write: Write,
    findings: Sequence[Finding],
    workflows: Sequence[tuple[str, str, int]],
    skipped: Sequence[str] = (),
    suppressed: Sequence[Finding] = (),
    errors: Sequence[str] = (),
) -> None:
    """The JSON report, written piece by piece: one finding at a time, never the whole document in memory."""
    payload: dict[str, Any] = {
        "version": __version__,
        "summary": {
            **counts(findings),
            "workflows": len(workflows),
            "fixable": fixable(findings),
            "suppressed": total(suppressed),
            "file_errors": len(errors),
            "not_listed": not_listed(findings),
        },
        "findings": STREAM_MARK + "findings",
        "workflows": STREAM_MARK + "workflows",
    }
    streams: dict[str, Iterable[Any]] = {
        "findings": (f.to_dict() for f in findings),
        "workflows": ({"file": label, "name": name, "nodes": n} for label, name, n in workflows),
    }
    if suppressed:
        payload["suppressed"] = STREAM_MARK + "suppressed"
        streams["suppressed"] = (f.to_dict() for f in suppressed)
    if skipped:
        payload["skipped"] = list(skipped)
    if errors:
        payload["errors"] = list(errors)
    write_json_stream(write, payload, streams)
    write("\n")


def render_json(
    findings: Sequence[Finding],
    workflows: Sequence[tuple[str, str, int]],
    skipped: Sequence[str] = (),
    suppressed: Sequence[Finding] = (),
    errors: Sequence[str] = (),
) -> str:
    parts: list[str] = []
    write_json(parts.append, findings, workflows, skipped, suppressed, errors)
    return "".join(parts)


def _gh_escape(value: str, prop: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if prop else value


_GH_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "notice"}


def render_github(findings: Sequence[Finding], errors: Sequence[str] = ()) -> str:
    """GitHub Actions workflow commands: one annotation per finding, shown on the PR diff."""
    lines = []
    for f in findings:
        if f.extra.get("run_summary"):
            lines.append(f"::warning title={_gh_escape('n8n-doctor (findings not listed)', True)}::{_gh_escape(safe_text(f.message))}")
            continue
        props = [f"title={_gh_escape(f'{f.rule.id} {f.rule.name}', True)}"]
        if not f.source.startswith("<"):
            props = [f"file={_gh_escape(Path(f.source).as_posix(), True)}", f"line={max(1, f.line)}", *props]
        node = f'"{f.node}": ' if f.node else ""
        message = safe_text(f"{node}{f.message}") + "\nFix: " + safe_text(f.fix_hint or f.rule.fix)
        lines.append(f"::{_GH_LEVEL[f.severity]} {','.join(props)}::{_gh_escape(message)}")
    for e in errors:
        lines.append(f"::error title=n8n-doctor (file not checked)::{_gh_escape(safe_text(e))}")
    return "\n".join(lines) + ("\n" if lines else "")


_SARIF_LEVEL = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "note"}


@functools.lru_cache(maxsize=256)
def _sarif_uri(source: str, root: Path) -> str:  # cached: every finding of a file asks for the same path
    path = Path(source)
    if source.startswith("<"):
        return source.replace("<", "").replace(">", "")  # "<api>/workflows/7" -> "api/workflows/7"
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_uri()


def _fingerprint(f: Finding) -> str:
    """Stable across runs and line moves; the message is included so findings without a node stay distinct."""
    import hashlib

    key = f"{f.rule.id}|{f.workflow_id or f.workflow}|{f.node or ''}|{f.parameter or ''}|{f.message}"
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]  # names can hold lone surrogates


def _sarif_result(f: Finding, base: Path, rule_index: dict[str, int]) -> dict[str, Any]:
    message = f.message + (f' (node "{f.node}")' if f.node else "") + f"\nFix: {f.fix_hint or f.rule.fix}"
    return {
        "ruleId": f.rule.id,
        "ruleIndex": rule_index.get(f.rule.id, 0),
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(f.source, base)},
                    "region": {"startLine": max(1, f.line)},
                },
                **({"logicalLocations": [{"name": f.node, "kind": "object"}]} if f.node else {}),
            }
        ],
        **({"suppressions": [{"kind": "inSource", "justification": f"n8n-doctor-disable in {f.suppressed}"}]} if f.suppressed else {}),
        "partialFingerprints": {"n8nDoctor/v1": _fingerprint(f)},
    }


def write_sarif(
    write: Write,
    findings: Sequence[Finding],
    rules: Sequence[Rule],
    root: Path | None = None,
    suppressed: Sequence[Finding] = (),
    errors: Sequence[str] = (),
) -> None:
    """SARIF 2.1.0 for GitHub code scanning, written one result at a time. File paths are relative to ``root``
    (default: cwd). Files that could not be checked (``errors``) are tool execution notifications, and the run is
    not successful. Findings past the per-run limit are a warning notification and counted in the run's properties."""
    base = root or Path.cwd()
    rule_index = {r.id: i for i, r in enumerate(rules)}
    left_out = [*run_summaries(findings), *run_summaries(suppressed)]
    notifications = [{"level": "error", "message": {"text": e}} for e in errors]
    notifications += [{"level": "warning", "message": {"text": f.message}} for f in left_out]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "n8n-doctor",
                "version": __version__,
                "informationUri": INFO_URI,
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "shortDescription": {"text": r.summary},
                        "fullDescription": {"text": f"{r.summary} {r.fix}"},
                        "help": {"text": r.fix, "markdown": f"{r.fix}\n\n[Rule documentation]({r.doc_url})"},
                        "helpUri": r.doc_url,
                        "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                        "properties": {"tags": ["n8n"]},
                    }
                    for r in rules
                ],
            }
        },
        "results": STREAM_MARK + "results",
        "invocations": [{"executionSuccessful": not errors, "toolExecutionNotifications": notifications}],
    }
    if left_out:
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in left_out:
            for key, n in f.extra["omitted"].items():
                by_severity[key] = by_severity.get(key, 0) + n
            for key, n in f.extra["omitted_by_rule"].items():
                by_rule[key] = by_rule.get(key, 0) + n
        run["properties"] = {"omittedFindings": {"count": sum(by_severity.values()), "bySeverity": by_severity, "byRule": dict(sorted(by_rule.items()))}}
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}
    listed = (f for f in (*findings, *suppressed) if not f.extra.get("run_summary"))
    write_json_stream(write, sarif, {"results": (_sarif_result(f, base, rule_index) for f in listed)})
    write("\n")


def render_sarif(
    findings: Sequence[Finding],
    rules: Sequence[Rule],
    root: Path | None = None,
    suppressed: Sequence[Finding] = (),
    errors: Sequence[str] = (),
) -> str:
    parts: list[str] = []
    write_sarif(parts.append, findings, rules, root, suppressed, errors)
    return "".join(parts)


def guard_commands(text: str) -> str:
    """Stop workflow-supplied text from starting a GitHub Actions workflow command (``::error ...``).

    The runner reads any output line whose trimmed start is ``::``. In human-readable
    output such lines get a leading ``>`` so they are shown, not executed.
    """
    return "\n".join(f"> {line}" if line.lstrip().startswith("::") or "\x1b[0m::" in line[:40] else line for line in text.split("\n"))


class ClosedStdout(Exception):
    """Standard output is closed (``>&-``): Python leaves ``sys.stdout`` None."""


def write_stdout(text: str) -> None:
    if sys.stdout is None:
        raise ClosedStdout
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "ascii"
        sys.stdout.write(text.encode(enc, "replace").decode(enc))
