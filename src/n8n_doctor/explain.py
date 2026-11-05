"""``n8n-doctor explain``: a readable outline of a workflow, from triggers to the last nodes."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from . import nodes as nk
from .files import json_copy, json_dumps
from .limits import MB
from .model import plural
from .report import safe_text
from .rules import _map_strings, shown_value
from .workflow import Edge, Workflow

_UNI = {"tee": "├─ ", "end": "└─ ", "bar": "│  ", "gap": "   ", "down": "↓  ", "arrow": "→", "loop": "↻", "deep": "↳ "}
_ASCII = {"tee": "|- ", "end": "`- ", "bar": "|  ", "gap": "   ", "down": "v  ", "arrow": "->", "loop": "(loop)", "deep": "-> "}


Show = Callable[[str], str]


class _Lines(list[str]):
    """Output lines that stop growing past ``budget`` bytes of UTF-8 (``full`` is then set)."""

    def __init__(self, budget: int) -> None:
        super().__init__()
        self.budget = budget
        self.full = False

    def add(self, line: str) -> bool:
        """Append ``line`` if it fits; False once the output is full."""
        if self.full:
            return False
        self.budget -= len(line.encode("utf-8", "surrogatepass")) + 1
        if self.budget < 0:
            self.full = True
            return False
        self.append(line)
        return True


def _truncated(limit: int) -> str:
    return f"... truncated: the output is longer than {limit // 1024:,} KB (--max-output-kb, max-output-kb in [limits]; one limit per run)"


def _setting(value: Any, mask: Show) -> Any:
    """A workflow setting for output: strings in it masked, whatever its JSON type."""
    if isinstance(value, str):
        return mask(value)
    if isinstance(value, (dict, list)):
        return _map_strings(json_copy(value), mask)
    return value


def _setting_text(value: Any, _n: Show) -> str:
    return _n(value) if isinstance(value, str) else _n(json_dumps(value, None))


def _viewer(wf: Workflow) -> tuple[Workflow, Show, Show]:
    """The workflow and how to show its text: every secret of the workflow masked, also where a name repeats
    one, and a value too long to check for secrets in full replaced as a whole (``mask``, for JSON); control
    characters removed as well (``show``, for the outline and Mermaid). Node summaries, sticky notes and output
    labels pass the parameter values they quote through ``mask`` before they shorten them."""
    mask = shown_value(wf)
    return wf, mask, lambda value: safe_text(mask(value))


def _label(wf: Workflow, name: str, _n: Show) -> str:
    node = wf.by_name.get(name)
    if node is None:
        return f"{_n(name)} [missing node]"
    detail = nk.describe(node, _n)
    flags = " [disabled]" if node.disabled else ""
    return f"{_n(node.name)} ({_n(node.short_type)}){flags}" + (f": {_n(detail)}" if detail else "")


_NOTES_MASKED = 4 * MB  # sticky-note text masked for the outline, of which it shows the start of each note


def outline(wf: Workflow, unicode: bool = True, budget: int | None = None) -> str:
    """The workflow as text. Branches deeper than ``max_explain_depth`` continue without more indentation,
    and the text stops at ``budget`` bytes (default ``max_output_bytes``, see :mod:`limits`)."""
    wf, mask, _n = _viewer(wf)
    g = _UNI if unicode else _ASCII
    limit = wf.limits.max_output_bytes
    lines = _Lines(limit if budget is None else budget)
    state = "active" if wf.active else "inactive"
    real = wf.real_nodes
    head = f'Workflow "{_n(wf.name)}" ({state}, {len(real)} node{"s" if len(real) != 1 else ""}'
    lines.add(head + (f", id {_n(wf.id)})" if wf.id else ")"))
    settings = wf.settings
    error_wf = settings.get("errorWorkflow")
    facts = [f"error workflow: {_setting_text(error_wf, _n) if error_wf else 'none'}"]
    if settings.get("timezone"):
        facts.append(f"timezone: {_setting_text(settings['timezone'], _n)}")
    if settings.get("executionTimeout") not in (None, -1):
        facts.append(f"timeout: {_setting_text(settings['executionTimeout'], _n)}s")
    if wf.pin_data:
        facts.append(f"pinned data on {plural(len(wf.pin_data), 'node')}")
    lines.add("Settings: " + "; ".join(facts))
    lines.add("")

    triggers = wf.triggers
    if not triggers:
        lines.add("No trigger node: this workflow cannot start on its own.")
    else:
        lines.add("Triggers")
        for i, t in enumerate(triggers, 1):
            if not lines.add(f"  {i}. {_label(wf, t.name, _n)}"):
                break
    printed: set[str] = set()
    for t in triggers:
        if lines.full:
            break
        lines.add("")
        lines.add(f'Flow from "{_n(t.name)}"')
        lines.add(f"  {_label(wf, t.name, _n)}")
        printed.add(t.name)
        _walk(wf, t.name, "  ", printed, g, lines, _n)
    if lines.full:
        return "\n".join(lines).rstrip() + "\n" + _truncated(limit) + "\n"

    ends = sorted(n.name for n in real if n.name in printed and not wf.connected_outputs(n.name) and not n.is_trigger)
    reachable = wf.reachable_from_triggers()
    unreachable = [n.name for n in real if n.name not in reachable]
    lines.add("")
    if ends:
        lines.add("Ends at: " + _joined((_n(e) for e in ends), lines.budget))
    subs = [n for n in real if n.name in reachable and n.name not in printed and not n.is_trigger]
    if subs:
        parents: dict[str, str] = {}  # by name: nodes that share a name share its connections
        for n in subs:
            if n.name not in parents:
                parents[n.name] = _ai_parent(wf, n.name, _n)
        lines.add("Sub-nodes (AI models, tools, memory): " + _joined((f"{_n(n.name)} {g['arrow']} {parents[n.name]}" for n in subs), lines.budget))
    if unreachable:
        lines.add("Never runs (not reachable from a trigger): " + _joined((_n(u) for u in unreachable), lines.budget))
    notes = [n for n in wf.nodes if n.is_sticky and isinstance(n.parameters.get("content"), str)]
    if notes:
        lines.add("Sticky notes:")
        left = _NOTES_MASKED
        for n in notes:
            content = n.parameters["content"]
            left -= len(content)
            text = (
                re.sub(r"\s+", " ", mask(content)[:1000].replace("#", "")).strip()
                if left >= 0
                else f"<{len(content):,} characters, past {_NOTES_MASKED // MB} MB of sticky notes: not shown>"
            )
            if not lines.add(f"  - {_n(text[:120])}{'...' if len(text) > 120 else ''}"):
                break
    return "\n".join(lines).rstrip() + "\n" + (_truncated(limit) + "\n" if lines.full else "")


def _joined(items: Iterable[str], budget: int) -> str:
    """``", ".join(items)``, stopping with ``...`` once it is longer than ``budget`` characters."""
    out: list[str] = []
    size = 0
    for item in items:
        if size > budget:
            out.append("...")
            break
        out.append(item)
        size += len(item) + 2
    return ", ".join(out)


def _ai_parent(wf: Workflow, name: str, _n: Show) -> str:
    parents = sorted({e.target for e in wf.outgoing(name, None) if e.kind != "main"})
    return ", ".join(_n(p) for p in parents[:20]) + (f" and {len(parents) - 20:,} more" if len(parents) > 20 else "") or "?"


def _rows(wf: Workflow, name: str) -> list[tuple[str, Edge | None]]:
    """(branch label, edge or None for an unconnected labelled output) in output order."""
    node = wf.by_name.get(name)
    labels = nk.output_labels(node) if node else []
    edges = wf.outgoing(name)
    rows: list[tuple[int, Edge | None]] = [(e.output, e) for e in edges]
    if len(labels) > 1:  # show branches that lead nowhere, they are part of the logic
        connected = {e.output for e in edges}
        rows += [(i, None) for i in range(len(labels)) if i not in connected and not (node and node.type == nk.FILTER and labels[i] == "discarded")]
    rows.sort(key=lambda r: r[0])
    out: list[tuple[str, Edge | None]] = []
    for output, edge in rows:
        branch = labels[output] if output < len(labels) and labels[output] else (f"output {output}" if output else "")
        out.append((branch if (branch and len(labels) > 1) or output else "", edge))
    return out


def _walk(wf: Workflow, start: str, indent: str, printed: set[str], g: dict[str, str], lines: _Lines, _n: Show) -> None:
    """Print everything after ``start``. Iterative, so very long chains cannot exhaust the stack.

    A node with a single plain output continues on the same indent (``↓``); branches
    open a tree level. ``on_path`` holds the nodes on the way here, to mark loops; an
    ``exit`` task takes a node off it once everything after it is printed. Past
    ``max_explain_depth`` levels, branches continue at that indentation after a ``↳ (depth
    limit)`` line, so each line is at most that wide plus its text, and the walk stops when
    the output is full: the work is linear in the lines printed.
    """
    Task = tuple[str, str, str, Edge | None, bool, int]
    max_depth = wf.limits.max_explain_depth
    stack: list[Task] = [("node", indent, start, None, False, 0)]
    on_path: set[str] = set()
    while stack and not lines.full:
        kind, ind, name, edge, last, depth = stack.pop()
        if kind == "exit":
            on_path.discard(name)
            continue
        if kind == "node":
            on_path.add(name)
            stack.append(("exit", ind, name, None, False, depth))
            rows = _rows(wf, name)
            if len(rows) == 1 and not rows[0][0] and rows[0][1] is not None:
                stack.append(("row", ind, "", rows[0][1], True, depth))
                continue
            if rows and depth == max_depth:  # deeper branches are not indented further
                lines.add(f"{ind}{g['deep']}(depth limit: the branches below continue at this indentation)")
            for i in range(len(rows) - 1, -1, -1):
                stack.append(("branch", ind, rows[i][0], rows[i][1], i == len(rows) - 1, depth))
            continue
        straight = kind == "row"
        connector = g["down"] if straight else g["end"] if last else g["tee"]
        prefix = f"[{_n(name)}] " if name else ""  # a branch label: a Switch output key, a fallback name
        if edge is None:
            lines.add(f"{ind}{connector}{prefix}(nothing connected)")
            continue
        target = edge.target
        if target in on_path:
            lines.add(f"{ind}{connector}{prefix}{g['loop']} back to {_n(target)}")
        elif target in printed:
            lines.add(f"{ind}{connector}{prefix}{g['arrow']} {_n(target)} (continues above)")
        else:
            lines.add(f"{ind}{connector}{prefix}{_label(wf, target, _n)}")
            printed.add(target)
            if straight:
                stack.append(("node", ind, target, None, False, depth))
            elif depth >= max_depth:
                stack.append(("node", ind, target, None, False, max_depth + 1))
            else:
                stack.append(("node", ind + (g["gap"] if last else g["bar"]), target, None, False, depth + 1))


def _mermaid_id(i: int) -> str:
    return f"n{i}"


def _mermaid_text(value: str, _n: Show) -> str:
    return _n(value).replace("#", "#35;").replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;").replace("|", "#124;")


def mermaid(wf: Workflow, budget: int | None = None) -> str:
    """A Mermaid flowchart (renders in GitHub Markdown); it stops at ``budget`` bytes (default ``max_output_bytes``)
    with a comment."""
    wf, _, _n = _viewer(wf)
    ids: dict[str, str] = {}
    for i, n in enumerate(wf.real_nodes):
        ids.setdefault(n.name, _mermaid_id(i))  # connections name the first node of a duplicated name
    limit = wf.limits.max_output_bytes
    out = _Lines(limit if budget is None else budget)
    out.add("flowchart LR")
    for i, n in enumerate(wf.real_nodes):
        if out.full:
            break
        text = f"{_mermaid_text(n.name, _n)}<br/>{_mermaid_text(n.short_type, _n)}"
        shape = (
            f'(["{text}"])'
            if n.is_trigger
            else f'{{"{text}"}}'
            if sum(1 for lab in nk.output_labels(n) if lab not in ("success", "error")) > 1
            else f'["{text}"]'
        )
        own = _mermaid_id(i)
        out.add(f"  {own}{shape}")
        if n.disabled:
            out.add(f"  style {own} stroke-dasharray: 5 5")
    labels_of: dict[str, list[str]] = {}
    for e in wf.edges:
        if out.full:
            break
        if e.source not in ids or e.target not in ids:
            continue
        if e.source not in labels_of:
            labels_of[e.source] = nk.output_labels(wf.by_name[e.source])
        labels = labels_of[e.source]
        label = labels[e.output] if e.output < len(labels) and labels[e.output] else ""
        arrow = "-.->" if e.kind != "main" else "-->"
        out.add(f"  {ids[e.source]} {arrow}" + (f"|{_mermaid_text(label, _n)}|" if label and e.kind == "main" else "") + f" {ids[e.target]}")
    if out.full:
        out.append("%% " + _truncated(limit))
    return "\n".join(out) + "\n"


def _each_within(flows: Sequence[Workflow], render: Callable[[Workflow, int], str], comment: str) -> str:
    """``render`` of each workflow, joined by blank lines, within one ``max_output_bytes`` for the whole run: each
    workflow gets what the ones before it left, and once one is cut the rest are counted, not shown."""
    if not flows:
        return ""
    limit = flows[0].limits.max_output_bytes
    left = limit
    parts: list[str] = []
    for i, wf in enumerate(flows):
        text = render(wf, left)
        parts.append(text)
        left -= len(text.encode("utf-8", "surrogatepass")) + 1
        if text.rstrip("\n").endswith(_truncated(limit)) or left <= 0:
            if not text.rstrip("\n").endswith(_truncated(limit)):
                parts.append(comment + _truncated(limit) + "\n")
            if i + 1 < len(flows):
                parts.append(f"{comment}... {plural(len(flows) - i - 1, 'more workflow')} not shown\n")
            break
    return "\n".join(parts)


def outlines(flows: Sequence[Workflow], unicode: bool = True) -> str:
    """:func:`outline` of each workflow of a run, within one output limit for them all."""
    return _each_within(flows, lambda wf, left: outline(wf, unicode, left), "")


def mermaids(flows: Sequence[Workflow]) -> str:
    """:func:`mermaid` of each workflow of a run, within one output limit for them all."""
    return _each_within(flows, mermaid, "%% ")


def _outputs(wf: Workflow, name: str | None, labels: list[str], mask: Show, is_filter: bool = False) -> list[dict[str, Any]]:
    """Each output of a node with its label and the (sorted, masked) names ``name``'s connections lead to
    (None: a node that shares its name with an earlier one, whose connections are shown there)."""
    targets: dict[int, set[str]] = {}
    for e in wf.outgoing(name) if name is not None else ():
        targets.setdefault(e.output, set()).add(e.target)
    size = max(len(labels), max(targets, default=-1) + 1)
    if is_filter and labels[-1] == "discarded" and size == len(labels) and size - 1 not in targets:
        size -= 1  # every Filter has this output: nothing goes there unless a node is connected
    shown = [mask(label) for label in labels]
    return [{"label": shown[i] if i < len(shown) else None, "to": sorted(mask(t) for t in targets.get(i, ()))} for i in range(size)]


def as_dict(wf: Workflow) -> dict[str, Any]:
    wf, mask, _ = _viewer(wf)
    reachable = wf.reachable_from_triggers()
    error_wf = wf.settings.get("errorWorkflow")
    return {
        "name": mask(wf.name),
        "id": mask(wf.id) if wf.id else wf.id,
        "active": wf.active,
        "error_workflow": _setting(error_wf, mask),
        "triggers": [{"name": mask(t.name), "type": mask(t.type), "summary": mask(nk.describe(t, mask))} for t in wf.triggers],
        "nodes": [
            {
                "name": mask(n.name),
                "type": mask(n.type),
                "summary": mask(nk.describe(n, mask)),
                "disabled": n.disabled,
                "reachable": n.name in reachable,
                # connections name their source: where nodes share a name, they are listed on the first one
                "outputs": _outputs(wf, n.name if wf.by_name.get(n.name) is n else None, nk.output_labels(n), mask, n.type == nk.FILTER),
            }
            for n in wf.real_nodes
        ],
    }
