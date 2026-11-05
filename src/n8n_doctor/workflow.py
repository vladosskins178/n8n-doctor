"""Loading exported n8n workflows and walking their graph.

An n8n workflow export is a JSON object with ``nodes`` and ``connections``. The
``n8n export:workflow --all`` command writes an array of them, and the public REST API
wraps lists in ``{"data": [...]}``; n8n.io templates wrap one in ``{"id": ..., "workflow": {...}}``. All are accepted.

Connections are keyed by the *source node name*::

    {"IF": {"main": [[{"node": "A", "type": "main", "index": 0}], [{"node": "B", ...}]]}}

The outer list is indexed by output (for an IF node: 0 = true, 1 = false), the inner
list holds every node fed by that output. AI sub-nodes (models, tools, memory) use
connection types such as ``ai_languageModel`` and point *from* the sub-node *to* the
agent that uses them.
"""

from __future__ import annotations

import fnmatch
import functools
import glob
import json
import math
import os
import re
import sys
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .expressions import code_values
from .limits import DEFAULT, Limits
from .model import plural

STICKY = "n8n-nodes-base.stickyNote"

# Node types that start an execution but do not end in "Trigger".
_EXTRA_TRIGGERS = {
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.cron",
    "n8n-nodes-base.interval",
    "n8n-nodes-base.start",
    "n8n-nodes-base.n8nTrigger",
    "n8n-nodes-base.emailReadImap",
    "@n8n/n8n-nodes-langchain.mcpTrigger",
}


class WorkflowError(Exception):
    """A file that cannot be read as an n8n workflow."""

    def __init__(self, message: str, broken_workflow: bool = False) -> None:
        super().__init__(message)
        self.broken_workflow = broken_workflow  # looks like a workflow but cannot be parsed


class LimitError(WorkflowError):
    """An input over one of the resource limits (see :mod:`limits`): always an error, never a skipped file."""

    def __init__(self, message: str) -> None:
        super().__init__(message, broken_workflow=True)


@dataclass
class FileBudget:
    """How many more nodes plus workflows one file may hold (``max-file-nodes``), its embedded workflows included.

    Per-workflow limits do not bound a file of many workflows, nor text in a node that holds many more. The file's own
    workflows are charged when it is loaded (past the budget it is refused); embedded ones when they are read, all at
    once and in document order, so that every command reads the same ones (see ``rules._embedded``).
    """

    left: int
    flows: list[Workflow] = field(default_factory=list, repr=False)  # the file's own workflows
    expanded: bool = False  # its embedded workflows have been read
    spent: bool = False  # something did not fit: no more embedded workflows are read
    raw_scanned: dict[bool, int] = field(default_factory=lambda: {False: 0, True: 0})  # characters read as raw text, by whether for masking
    raw_cut: bool = False  # the masker did not read all raw text: output must not show those values
    raw_limit: int = DEFAULT.max_raw_scan_bytes

    def charge(self, flows: list[dict[str, Any]], where: str, limits: Limits) -> None:
        count = len(flows) + sum(len(flow["nodes"]) for flow in flows)
        if count > self.left and all(len(flow["nodes"]) <= limits.max_nodes for flow in flows):  # else build names that limit
            self.spent = True
            raise _over(where, f"{count:,} nodes and workflows, more than the limit of {limits.max_file_nodes:,} per file", "max-file-nodes")
        self.left -= count

    def raw_charge(self, size: int, mask: bool) -> bool:
        """Whether ``size`` more characters of embedded text that does not parse may be read (``max-raw-scan-mb``,
        once for reporting and once for masking)."""
        if self.raw_scanned[mask] + size > self.raw_limit:
            return False
        self.raw_scanned[mask] += size
        return True


@dataclass
class Node:
    name: str
    type: str
    type_version: float
    parameters: dict[str, Any]
    raw: dict[str, Any]
    index: int
    line: int = 1
    cache: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)  # derived facts (nodes.output_labels)

    @property
    def disabled(self) -> bool:
        return bool(self.raw.get("disabled"))

    @property
    def short_type(self) -> str:
        """``n8n-nodes-base.httpRequest`` -> ``httpRequest``."""
        return self.type.rsplit(".", 1)[-1]

    @property
    def is_sticky(self) -> bool:
        return self.type == STICKY

    @property
    def is_trigger(self) -> bool:
        return self.type in _EXTRA_TRIGGERS or self.short_type.lower().endswith("trigger")

    @property
    def credentials(self) -> dict[str, Any]:
        creds = self.raw.get("credentials")
        return creds if isinstance(creds, dict) else {}

    @property
    def notes(self) -> str:
        notes = self.raw.get("notes")
        return notes if isinstance(notes, str) else ""


@dataclass(frozen=True)
class Edge:
    source: str
    output: int
    target: str
    input: int
    kind: str  # "main", "ai_tool", ...


@dataclass
class Workflow:
    data: dict[str, Any]
    source: str  # file path, "<api>/<id>" or "<stdin>"
    nodes: list[Node]
    edges: list[Edge]
    position: int = 0  # index inside a multi-workflow file
    text: str | None = None  # the original file text, when it came from one
    by_name: dict[str, Node] = field(default_factory=dict)
    name_index: Any = field(default=None, repr=False)  # cache for rules.suggest_name
    fuzzy_budget: Any = field(default=None, repr=False)  # rules.FuzzyBudget shared by the workflows of one run
    masker: Any = field(default=None, repr=False)  # cache for rules.secret_masker (only that of the last few workflows is kept)
    secrets: set[str] | None = field(default=None, repr=False)  # cache for rules._known_secrets
    budget: Any = field(default=None, repr=False, compare=False)  # the FileBudget shared by the workflows of its file
    limits: Limits = DEFAULT
    # entries of the raw "nodes" array that are not objects: (position in the array, JSON type, line)
    invalid_entries: list[tuple[int, str, int]] = field(default_factory=list)
    # nodes whose typeVersion is a number no version can be (400 digits, NaN): (index, what), read as version 1
    bad_versions: list[tuple[int, str]] = field(default_factory=list)
    # parts of the workflow checked only in part because of a soft limit: (node index or None, what), see N8D001
    partial: list[tuple[int | None, str]] = field(default_factory=list)
    node_at: dict[int, Node] = field(default_factory=dict)  # position in the raw "nodes" array -> node
    _out: dict[str, list[Edge]] = field(default_factory=dict, repr=False)
    _in: dict[str, list[Edge]] = field(default_factory=dict, repr=False)
    _views: dict[tuple[str, str, str | None], list[Edge]] = field(default_factory=dict, repr=False)
    _connected: dict[str, set[int]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.budget is None:  # a workflow on its own: a file of one
            self.budget = FileBudget(self.limits.max_file_nodes - len(self.nodes) - 1, [self], raw_limit=self.limits.max_raw_scan_bytes)
        for node in self.nodes:
            self.by_name.setdefault(node.name, node)
            self.node_at[node.index] = node
        for edge in self.edges:
            self._out.setdefault(edge.source, []).append(edge)
            self._in.setdefault(edge.target, []).append(edge)

    @property
    def name(self) -> str:
        name = self.data.get("name")
        return name if isinstance(name, str) and name else "(unnamed workflow)"

    @property
    def id(self) -> str | None:
        wid = self.data.get("id")
        return str(wid) if wid not in (None, "") else None

    @property
    def active(self) -> bool:
        return bool(self.data.get("active"))

    @property
    def settings(self) -> dict[str, Any]:
        settings = self.data.get("settings")
        return settings if isinstance(settings, dict) else {}

    @property
    def pin_data(self) -> dict[str, Any]:
        pin = self.data.get("pinData")
        return pin if isinstance(pin, dict) else {}

    @functools.cached_property
    def real_nodes(self) -> list[Node]:
        """Every node except sticky notes (computed once: nodes do not change after loading)."""
        return [n for n in self.nodes if not n.is_sticky]

    @functools.cached_property
    def triggers(self) -> list[Node]:
        return [n for n in self.real_nodes if n.is_trigger]

    def _view(self, direction: str, name: str, kind: str | None) -> list[Edge]:
        """The edges of ``name`` in one direction, of one kind; filtered once per name and kind, since several
        nodes can share a name (and so its edges) and rules ask once per node. Callers must not change the list."""
        key = (direction, name, kind)
        view = self._views.get(key)
        if view is None:
            edges = (self._out if direction == "out" else self._in).get(name, [])
            view = self._views[key] = edges if kind is None else [e for e in edges if e.kind == kind]
        return view

    def outgoing(self, name: str, kind: str | None = "main") -> list[Edge]:
        return self._view("out", name, kind)

    def incoming(self, name: str, kind: str | None = "main") -> list[Edge]:
        return self._view("in", name, kind)

    def connected_outputs(self, name: str) -> set[int]:
        """Main outputs of ``name`` connected to an existing node (computed once per name; do not change the set)."""
        found = self._connected.get(name)
        if found is None:
            found = self._connected[name] = {e.output for e in self.outgoing(name) if e.target in self.by_name}
        return found

    def downstream(self, start: Iterable[str], kind: str | None = "main") -> set[str]:
        """Names reachable from ``start`` (exclusive unless reachable again) along edges of ``kind``."""
        seen: set[str] = set()
        queue = deque(start)
        while queue:
            current = queue.popleft()
            for edge in self.outgoing(current, kind):
                if edge.target not in seen:
                    seen.add(edge.target)
                    queue.append(edge.target)
        return seen

    def reachable_from_triggers(self) -> set[str]:
        """Nodes that can run: triggers, everything downstream of them, and the AI sub-nodes they use."""
        reached = {t.name for t in self.triggers}
        # Under the legacy execution order (v0, also when the setting is missing) a node with several inputs that
        # lacks data on one runs that input's branch first: every node upstream of it runs too
        legacy = self.settings.get("executionOrder") != "v1"
        upstream: set[str] = set()  # nodes already walked backwards from (legacy order only)
        # along main edges, through nodes that exist only: a connection to a missing node leads nowhere
        queue = deque(reached)
        while queue:
            current = queue.popleft()
            for edge in self.outgoing(current):
                if edge.target not in reached and edge.target in self.by_name:
                    reached.add(edge.target)
                    queue.append(edge.target)
            if legacy and current not in upstream and len({e.input for e in self.incoming(current) if e.source in self.by_name}) > 1:
                back = deque([current])
                upstream.add(current)
                while back:
                    for edge in self.incoming(back.popleft()):
                        if edge.source in self.by_name and edge.source not in upstream:
                            upstream.add(edge.source)
                            back.append(edge.source)
                            if edge.source not in reached:
                                reached.add(edge.source)
                                queue.append(edge.source)
        # sub-nodes feed their parent through ai_* edges, and can have sub-nodes of their own:
        # walk those edges backwards from everything reached (linear in nodes + edges)
        queue = deque(reached)
        while queue:
            current = queue.popleft()
            for edge in self._in.get(current, ()):
                if edge.kind != "main" and edge.source not in reached and edge.source in self.by_name:
                    reached.add(edge.source)
                    queue.append(edge.source)
        return reached


NUMBER_MAX = 1e12  # a number further from zero is no version, count or duration n8n can use


def bounded_number(value: Any) -> float | None:
    """``value`` as a float when it is a JSON number within ``NUMBER_MAX`` of zero; None for anything else (a
    400-digit integer, 1e308, NaN, Infinity, a bool or a string). Never raises."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, int):
        return float(value) if -NUMBER_MAX <= value <= NUMBER_MAX else None
    return value if math.isfinite(value) and abs(value) <= NUMBER_MAX else None


def number_problem(value: Any) -> str | None:
    """What is wrong with a JSON number that :func:`bounded_number` refuses, for messages (None when fine or not a number)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or bounded_number(value) is not None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return "NaN"
    if isinstance(value, float) and math.isinf(value):
        return "infinite"
    return f"{'over' if value > 0 else 'under'} {'' if value > 0 else '-'}{NUMBER_MAX:,.0f}"


def _num(value: Any, default: float = 1) -> float:
    n = bounded_number(value)
    return default if n is None else n


def _shown(text: str, limit: int = 80) -> str:
    """A name or key as an error message shows it: masked, then shortened (see :func:`rules.shorten`)."""
    from .rules import shorten  # rules imports this module

    return shorten(text, limit)


def _node_ref(index: int | None, name: str) -> str:
    """A node as a limit error names it: by position and name length. The workflow is refused before its secrets
    are known, so a name that repeats one of them (a header value) could not be masked."""
    where = f"node #{index}" if index is not None else "a node not in the nodes list"
    return f"{where} ({len(name):,} chars)"


def _connection_kind(kind: str) -> str:
    """A connection type as a limit error shows it: n8n's own types only (any other key could hold anything)."""
    return kind if kind == "main" or (len(kind) <= 40 and re.fullmatch(r"ai_[a-zA-Z]+", kind)) else "connection-type"


def _over(where: str, what: str, flag: str) -> LimitError:
    return LimitError(f"{_shown(where, 1024)}: {what} (raise the limit with --{flag} or {flag} in [limits])")


def _edges(connections: Any, limits: Limits, where: str, raw_nodes: list[Any] | None = None) -> list[Edge]:
    """Every connection, checking the connection limits as they are read (over one: :class:`LimitError`).

    Limited: connections and output lists per workflow, output lists per node and connection type,
    connections per output, and the length of the node names they use.
    """
    edges: list[Edge] = []
    if not isinstance(connections, dict):
        return edges
    positions: dict[str, int] | None = None

    def ref(name: str) -> str:  # built on the first error only
        nonlocal positions
        if positions is None:
            positions = {}
            for i, raw in enumerate(raw_nodes or ()):
                if isinstance(raw, dict) and isinstance(raw.get("name"), str):
                    positions.setdefault(raw["name"], i)
        return _node_ref(positions.get(name), name)

    slots = 0
    names = limits.max_name_chars
    for source, kinds in connections.items():
        if not isinstance(kinds, dict):
            continue
        if len(source) > names:
            raise _over(where, f"a connection from a node name {len(source):,} characters long, more than {names:,}", "max-name-length")
        for kind, outputs in kinds.items():
            if not isinstance(outputs, list):
                continue
            if len(outputs) > limits.max_outputs:
                raise _over(where, f"{ref(source)} has {len(outputs):,} {_connection_kind(str(kind))} outputs, more than {limits.max_outputs:,}", "max-outputs")
            for out_index, targets in enumerate(outputs):
                if not isinstance(targets, list) or not targets:
                    continue
                if len(targets) > limits.max_targets:
                    what = f"output {out_index} of {ref(source)} has {len(targets):,} connections, more than {limits.max_targets:,}"
                    raise _over(where, what, "max-targets-per-output")
                for target in targets:
                    if not isinstance(target, dict):
                        continue
                    name = target.get("node")
                    if not isinstance(name, str):
                        continue
                    if len(name) > names:
                        raise _over(where, f"a connection to a node name {len(name):,} characters long, more than {names:,}", "max-name-length")
                    idx = target.get("index", 0)
                    idx = idx if isinstance(idx, int) and not isinstance(idx, bool) else 0
                    kind_of = target.get("type", kind)
                    edges.append(Edge(source, out_index, name, idx, kind_of if isinstance(kind_of, str) else kind))
                    if len(edges) > limits.max_connections:
                        raise _over(where, f"more than {plural(limits.max_connections, 'connection')}", "max-connections")
            slots += len(outputs)  # output lists count too: empty ones cost work in reports
            if slots > limits.max_connections:
                raise _over(where, f"more than {plural(limits.max_connections, 'connection output')}", "max-connections")
    return edges


_JSON_TYPES = {type(None): "null", bool: "a boolean", int: "a number", float: "a number", str: "a string", list: "an array"}
_CONTAINERS = (dict, list)


def check_depth(data: Any, source: str, limits: Limits) -> None:
    """Refuse a document nested deeper than ``max_depth`` arrays and objects. One pass, level by level."""
    level = [data] if isinstance(data, _CONTAINERS) else []
    depth = 0
    while level:
        depth += 1
        if depth > limits.max_depth:
            raise _over(source, f"JSON nested more than {limits.max_depth} levels deep", "max-depth")
        below: list[Any] = []
        for value in level:
            below.extend([v for v in (value.values() if isinstance(value, dict) else value) if isinstance(v, _CONTAINERS)])
        level = below


def _check_parameters(nodes: list[Any], where: str, limits: Limits) -> None:
    """Refuse a workflow whose node parameters hold more than ``max_parameter_values`` values, an array longer
    than ``max_list_length``, or a value whose path (``options.headers[0].value``, as findings show it) is longer
    than ``max_path_chars``. Rules walk parameters several times and quote paths: this bounds every walk."""
    budget = limits.max_parameter_values
    longest = limits.max_list_length
    widest = limits.max_path_chars
    count = 0
    for index, raw in enumerate(nodes):
        params = raw.get("parameters") if isinstance(raw, dict) else None
        if not isinstance(params, dict):
            continue
        name = raw.get("name") if isinstance(raw.get("name"), str) else ""
        too_long = functools.partial(_path_too_long, where, _node_ref(index, name), widest)
        stack: list[tuple[Any, int]] = [(params, 0)]  # a container, and the length of its path
        while stack:
            current, size = stack.pop()
            count += len(current)
            if count > budget:
                raise _over(where, f"more than {budget:,} values in node parameters", "max-parameter-values")
            if isinstance(current, dict):
                for key, value in current.items():
                    inner = size + len(key) + (1 if size else 0)  # "key" or ".key"
                    if inner > widest:
                        raise too_long(inner)
                    if isinstance(value, _CONTAINERS):
                        stack.append((value, inner))
                continue
            if len(current) > longest:
                what = f"{_node_ref(index, name)} has an array of {len(current):,} entries in its parameters, more than {longest:,}"
                raise _over(where, what, "max-list-length")
            if current and size + len(str(len(current) - 1)) + 2 > widest:  # "[index]"
                raise too_long(size + len(str(len(current) - 1)) + 2)
            stack.extend((v, size + len(str(i)) + 2) for i, v in enumerate(current) if isinstance(v, _CONTAINERS))


def _path_too_long(where: str, node: str, widest: int, size: int) -> LimitError:
    return _over(where, f"{node} has a parameter path {size:,} characters long, more than {widest:,}", "max-path-length")


# Switch nodes: the parameter list with one output per entry, by type version (see nodes.output_labels)
_SWITCH = "n8n-nodes-base.switch"
_SWITCH_RULES = (("rules", "values"), ("rules", "rules"))


def _check_node(raw: dict[str, Any], i: int, where: str, limits: Limits, partial: list[tuple[int | None, str]]) -> str:
    """The node's name, after checking its length, its outputs (Switch rules) and its code length."""
    name = raw.get("name", f"(node {i})")
    name = name if isinstance(name, str) else str(name)
    if len(name) > limits.max_name_chars:
        raise _over(where, f"nodes[{i}] has a name {len(name):,} characters long, more than {limits.max_name_chars:,}", "max-name-length")
    kind = raw.get("type", "")
    if len(kind if isinstance(kind, str) else str(kind)) > limits.max_name_chars:  # types are shown with names
        raise _over(where, f"nodes[{i}] has a type more than {limits.max_name_chars:,} characters long", "max-name-length")
    params = raw.get("parameters")
    if not isinstance(params, dict):
        return name
    if raw.get("type") == _SWITCH:
        for first, second in _SWITCH_RULES:
            group = params.get(first)
            rules = group.get(second) if isinstance(group, dict) else None
            if isinstance(rules, list) and len(rules) > limits.max_outputs:
                raise _over(where, f"Switch {_node_ref(i, name)} has {len(rules):,} rules (one output each), more than {limits.max_outputs:,}", "max-outputs")
    for keys, code in code_values(kind if isinstance(kind, str) else "", params):  # the source the rules analyse
        if len(code) > limits.max_code_chars:
            size = limits.max_code_chars // 1024
            key = ".".join(keys)
            partial.append((i, f"{key} is {len(code):,} characters long: only its first {size:,} KB were checked for node references and legacy syntax"))
    return name


def _workflow_members(text: str, i: int) -> tuple[list[int] | None, int]:
    """For the JSON object at ``text[i]``: the element offsets of its ``"nodes"`` array (None without one), and the
    offset after the object. The parser skips every other value at C speed: Python only steps over keys and nodes."""
    found: list[int] | None = None
    i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]  # matches the empty string
    if text.startswith("}", i):
        return found, i + 1
    while True:
        key, i = _DECODER.raw_decode(text, i)
        i = _WS.match(text, _WS.match(text, i).end() + 1).end()  # type: ignore[union-attr]  # past the colon
        if key == "nodes" and text.startswith("[", i):
            found, i = _elements(text, i)
        else:
            i = _DECODER.raw_decode(text, i)[1]
        i = _WS.match(text, i).end()  # type: ignore[union-attr]
        if not text.startswith(",", i):
            return found, i + 1
        i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]


def _elements(text: str, i: int, inner: Any = None) -> tuple[list[int], int]:
    """Offsets of the elements of the array at ``text[i]``, and the offset after it. ``inner(text, offset)``, if
    given, reads each element that is an object (returning the offset after it); others are skipped."""
    offsets: list[int] = []
    i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]
    if text.startswith("]", i):
        return offsets, i + 1
    while True:
        offsets.append(i)
        i = inner(text, i) if inner is not None and text.startswith("{", i) else _DECODER.raw_decode(text, i)[1]
        i = _WS.match(text, i).end()  # type: ignore[union-attr]
        if not text.startswith(",", i):
            return offsets, i + 1
        i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]


_TEMPLATE_WRAPPERS = 4  # "workflow" members followed from the top of a document
_WS = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder()


def nodes_arrays(text: str) -> list[list[int]]:
    """Element offsets of each workflow's ``"nodes"`` array in a JSON text, in document order.

    The standard library parser does not report positions, so the workflow objects are walked
    again with :meth:`json.JSONDecoder.raw_decode`, which reads every value other than the keys
    of a workflow and its nodes at C speed. Only the ``"nodes"`` arrays of workflow objects (a
    single export, an array of exports, or the API's ``{"data": [...]}``) are counted, not, say,
    one inside ``staticData``. Used for line numbers in reports only; text that is not valid
    JSON gives what was found before the error.
    """
    found: list[list[int]] = []
    member = _collector(found)
    try:
        i = _WS.match(text).end()  # type: ignore[union-attr]
        if text.startswith("[", i):
            _elements(text, i, member)
        elif text.startswith("{", i):
            nodes, _ = _workflow_members(text, i)
            if nodes is not None:
                found.append(nodes)
            elif '"data"' in text or '"workflow"' in text:  # {"data": [...]}, {"data": {...}} or {"workflow": {...}}
                found.extend(_data_arrays(text, i)[0])
    except (ValueError, IndexError):
        pass
    return found


def _collector(found: list[list[int]]) -> Any:
    """An ``inner`` reader for :func:`_elements`: reads a workflow object and adds its ``"nodes"`` offsets to ``found``."""

    def member(text: str, i: int) -> int:
        nodes, end = _workflow_members(text, i)
        if nodes is not None:
            found.append(nodes)
        return end

    return member


def _data_arrays(text: str, i: int, depth: int = _TEMPLATE_WRAPPERS) -> tuple[list[list[int]], int]:
    """The ``"nodes"`` arrays of the workflows in the ``"data"`` member of the object at ``text[i]``, or in its
    ``"workflow"`` member (an n8n.io template, also wrapped several times: see :func:`_unwrap_template`), and where
    the object ends."""
    last: list[list[int]] = []
    i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]
    while not text.startswith("}", i):
        key, i = _DECODER.raw_decode(text, i)
        i = _WS.match(text, _WS.match(text, i).end() + 1).end()  # type: ignore[union-attr]
        if key == "data" and text.startswith("[", i):
            found: list[list[int]] = []
            i = _elements(text, i, _collector(found))[1]
            last = found
        elif key in ("data", "workflow") and text.startswith("{", i):
            nodes, end = _workflow_members(text, i)
            inner = _data_arrays(text, i, depth - 1)[0] if key == "workflow" and depth and text.find('"workflow"', i, end) >= 0 else []
            last, i = inner or ([nodes] if nodes is not None else []), end
        else:
            i = _DECODER.raw_decode(text, i)[1]
        i = _WS.match(text, i).end()  # type: ignore[union-attr]
        if text.startswith(",", i):
            i = _WS.match(text, i + 1).end()  # type: ignore[union-attr]
    return last, i + 1


def node_offsets(text: str) -> list[int]:
    """Element offsets of the first ``"nodes"`` array (kept for callers that handle one workflow)."""
    arrays = nodes_arrays(text)
    return arrays[0] if arrays else []


def is_workflow(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("nodes"), list) and isinstance(data.get("connections", {}), dict)


def _unwrap_template(data: Any) -> Any:
    """The workflow in an n8n.io template: ``{"id": 1, "workflow": {...}}``, or what its API returns,
    ``{"workflow": {"id": 1, "nodes": [summary], "workflow": {...}}}``, whose ``nodes`` only list the node types. The
    innermost object that is a workflow counts; one with its own ``connections`` is real whatever else it holds."""
    found = data
    current = data
    for _ in range(_TEMPLATE_WRAPPERS):
        if not isinstance(current, dict) or not isinstance(current.get("workflow"), dict) or (is_workflow(current) and "connections" in current):
            break
        current = current["workflow"]
        if is_workflow(current) or not is_workflow(found):
            found = current
    return found


class _LineCounter:
    """1-based line numbers of offsets in one text, counting each newline once over all calls (offsets in
    later calls must not come before those of earlier ones, as with workflows in document order)."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.line = 1

    def lines(self, offsets: list[int]) -> list[int]:
        out = [1] * len(offsets)
        for i in sorted(range(len(offsets)), key=offsets.__getitem__):
            if offsets[i] > self.pos:
                self.line += self.text.count("\n", self.pos, offsets[i])
                self.pos = offsets[i]
            out[i] = self.line
        return out


def _line_numbers(text: str, offsets: list[int]) -> list[int]:
    """1-based line of each offset, counting newlines once over the text (offsets in any order)."""
    return _LineCounter(text).lines(offsets)


def build(
    data: dict[str, Any],
    source: str,
    position: int = 0,
    text: str | None = None,
    offsets: list[int] | None = None,
    limits: Limits = DEFAULT,
    lines: list[int] | None = None,
    budget: FileBudget | None = None,
) -> Workflow:
    """A :class:`Workflow` from one parsed export, after checking it against ``limits`` (:class:`LimitError`).

    ``lines`` (or ``text`` and the ``offsets`` of the nodes in it) give the nodes' line numbers.
    """
    if not is_workflow(data):
        raise WorkflowError(f"{source}: not an n8n workflow (needs a 'nodes' list and a 'connections' object)")
    where = source + (f"[{position}]" if position else "")
    raw_nodes = data["nodes"]
    if len(raw_nodes) > limits.max_nodes:
        raise _over(where, f"{len(raw_nodes):,} nodes, more than the limit of {limits.max_nodes:,}", "max-nodes")
    for key in ("name", "id"):
        value = data.get(key)
        if value is not None and len(value if isinstance(value, str) else str(value)) > limits.max_name_chars:
            raise _over(where, f"the workflow {key} is more than {limits.max_name_chars:,} characters long", "max-name-length")
    pin = data.get("pinData")
    if isinstance(pin, dict) and (longest := max(map(len, pin), default=0)) > limits.max_name_chars:
        raise _over(where, f"pinned data for a node name {longest:,} characters long, more than {limits.max_name_chars:,}", "max-name-length")
    _check_parameters(raw_nodes, where, limits)
    edges = _edges(data.get("connections"), limits, where, raw_nodes)
    if lines is None or len(lines) != len(raw_nodes):
        if offsets is None:
            offsets = node_offsets(text) if text is not None and position == 0 else []
        lines = _line_numbers(text, offsets) if text is not None and len(offsets) == len(raw_nodes) else []
    nodes: list[Node] = []
    invalid: list[tuple[int, str, int]] = []
    bad_versions: list[tuple[int, str]] = []
    partial: list[tuple[int | None, str]] = []
    for i, raw in enumerate(raw_nodes):
        line = lines[i] if lines else 1
        if not isinstance(raw, dict) or not raw:
            invalid.append((i, _JSON_TYPES.get(type(raw), "an empty object" if raw == {} else "not an object"), line))
            continue
        params = raw.get("parameters")
        if why := number_problem(raw.get("typeVersion")):
            bad_versions.append((i, why))
        nodes.append(
            Node(
                name=_check_node(raw, i, where, limits, partial),
                type=str(raw.get("type", "")),
                type_version=_num(raw.get("typeVersion")),
                parameters=params if isinstance(params, dict) else {},
                raw=raw,
                index=i,
                line=line,
            )
        )
    return Workflow(
        data=data,
        source=source,
        nodes=nodes,
        edges=edges,
        position=position,
        text=text,
        limits=limits,
        budget=budget,
        invalid_entries=invalid,
        partial=partial,
        bad_versions=bad_versions,
    )


def from_data(data: Any, source: str, text: str | None = None, limits: Limits = DEFAULT, budget: FileBudget | None = None) -> list[Workflow]:
    """Every workflow in a parsed JSON document (single object, array, API ``{"data": [...]}``, or an n8n.io
    template ``{"id": ..., "workflow": {...}}``).

    This is where input is checked against ``limits``, once, before any rule or output sees it:
    a document or workflow over a hard limit raises :class:`LimitError` (see :mod:`limits`). ``budget`` is that of
    the file an embedded workflow is in; without it the document is a file of its own.
    """
    own = budget is None
    shared = FileBudget(limits.max_file_nodes, raw_limit=limits.max_raw_scan_bytes) if budget is None else budget
    check_depth(data, source, limits)
    if isinstance(data, dict) and not is_workflow(data) and isinstance(data.get("data"), (list, dict)):
        data = data["data"]
    data = _unwrap_template(data)
    counter = _LineCounter(text) if text is not None else None
    if isinstance(data, list):
        flows = [d for d in data if is_workflow(d)]
        if not flows:
            raise WorkflowError(f"{source}: no n8n workflows in this JSON array")
        if len(flows) > limits.max_workflows:
            raise _over(source, f"{len(flows):,} workflows, more than the limit of {limits.max_workflows:,}", "max-workflows-per-file")
        shared.charge(flows, source, limits)
        arrays = deque(nodes_arrays(text) if text is not None else [])
        located: list[list[int] | None] = []
        for flow in flows:  # pair each workflow with the next "nodes" array of the same length
            while arrays and len(arrays[0]) != len(flow["nodes"]):
                arrays.popleft()
            located.append(arrays.popleft() if arrays else None)
        lines = [counter.lines(offs) if counter is not None and offs else None for offs in located]
        if len(flows) == 1 and len(data) == 1:
            built = [build(flows[0], source, 0, limits=limits, text=text, lines=lines[0] or [], budget=shared)]
        else:
            built = [build(d, source, i + 1, text, limits=limits, lines=lines[i] or [], budget=shared) for i, d in enumerate(flows)]
    elif not is_workflow(data):
        built = [build(data, source, 0, text, limits=limits, lines=[], budget=shared)]
    else:
        shared.charge([data], source, limits)
        found = nodes_arrays(text) if text is not None else []
        offsets = found[0] if found and len(found[0]) == len(data["nodes"]) else []
        built = [build(data, source, 0, text, limits=limits, lines=counter.lines(offsets) if counter is not None and offsets else [], budget=shared)]
    if own:
        shared.flows.extend(built)
    return built


def _too_large(source: object, size: int, limits: Limits) -> LimitError:
    return LimitError(
        f"{source}: {size / (1024 * 1024):.1f} MB, larger than the limit of {limits.max_file_bytes // (1024 * 1024)} MB "
        "(raise it with --max-file-mb or max-file-mb in [limits], up to 64)"
    )


def read_text(path: Path, limits: Limits = DEFAULT) -> str:
    try:
        if not path.is_file():
            raise WorkflowError(f"{path}: not a regular file")
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise _too_large(path, size, limits)
        raw = path.read_bytes()
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):  # PowerShell `>` writes UTF-16
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise WorkflowError(f"{path}: not UTF-8 text ({exc.reason})") from exc
    except OSError as exc:
        raise WorkflowError(f"{path}: {exc.strerror or exc}") from exc


_DIGITS = re.compile(r"\d+")


def number_error(exc: ValueError, text: str) -> str | None:
    """For json.loads failing on an integer too long to convert: "a number with 5,000 digits on line 3 is too
    large" instead of Python's message (which names a Python setting); None for any other error."""
    if "integer string conversion" not in str(exc):
        return None
    limit = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else 4300
    m = next((d for d in _DIGITS.finditer(text) if d.end() - d.start() > limit), None)  # runs of digits: linear
    if m is None:
        return "a number is too large"
    return f"a number with {m.end() - m.start():,} digits on line {text.count(chr(10), 0, m.start()) + 1:,} is too large"


class _InvalidJson(WorkflowError):
    """The text is no JSON at all, unlike JSON that holds no workflow."""


def parse_text(text: str, source: str, limits: Limits = DEFAULT) -> list[Workflow]:
    if len(text) > limits.max_file_bytes // 4 and (size := len(text.encode("utf-8", "surrogatepass"))) > limits.max_file_bytes:
        raise _too_large(source, size, limits)
    text = text.lstrip("﻿")
    try:
        data = json.loads(text)
    except ValueError as exc:
        # a workflow export cut short (a failed download, a bad merge) must not pass as "not a workflow"
        looks_like_workflow = '"nodes"' in text or '"connections"' in text or re.match(r'\s*(?:\[\s*)?\{\s*"name"', text) is not None
        raise _InvalidJson(f"{source}: invalid JSON ({number_error(exc, text) or exc})", looks_like_workflow) from exc
    except RecursionError:
        raise _over(source, "JSON nested too deeply to read", "max-depth") from None
    return from_data(data, source, text, limits)


_JSON_START = re.compile(r"""[ \t]*(?:\[\s*(?:\{|\]|$)|\{\s*(?:"|\}|$))""")


def parse_export(text: str, source: str, limits: Limits = DEFAULT) -> list[Workflow]:
    """:func:`parse_text`, and for text that is no JSON a second try after any log lines at its start.

    ``n8n export:workflow --all`` can print warnings before the JSON: one more try, from the first line (of the first
    50) that starts like a JSON export; one try, so any input costs two parses at most. If that fails too, the text
    is what the first parse said it is."""
    try:
        return parse_text(text, source, limits)
    except _InvalidJson as first:
        start = 0
        for _ in range(50):
            end = text.find("\n", start)
            if end < 0:
                break
            start = end + 1
            if _JSON_START.match(text, start, start + 256):
                try:
                    return parse_text(text[start:], source, limits)
                except LimitError:
                    raise
                except WorkflowError:
                    break
        raise first from None


def load_file(path: Path, limits: Limits = DEFAULT, recover: bool = False) -> list[Workflow]:
    """The workflows of a file; with ``recover``, past log lines at its start (see :func:`parse_export`)."""
    return (parse_export if recover else parse_text)(read_text(path, limits), str(path), limits)


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".n8n-doctor"}


def iter_json_files(root: Path) -> Iterator[Path]:
    """``*.json`` files under ``root`` in a stable order.

    Skips VCS and dependency folders, never follows symlinks, and ignores folders it
    cannot read. Iterative, so deep trees cannot exhaust the stack.
    """
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=lambda _err: None):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(folder) / d).is_symlink())
        for name in sorted(files):
            path = Path(folder) / name
            if name.lower().endswith(".json") and not path.is_symlink() and path.is_file():
                yield path


GLOB_MAX = 10_000  # paths one expansion of glob patterns may give (see expand_paths)


class GlobError(ValueError):
    """A glob pattern matched more paths than :data:`GLOB_MAX`."""


def _glob_match(parts: list[str], names: list[str]) -> bool:
    """Whether the path components ``names`` match the pattern components ``parts``: ``**`` is any number of
    folders (none included), every other component is matched with :func:`fnmatch.fnmatch` (``*`` stays inside
    one name and matches names starting with a dot too)."""

    def close(states: set[int]) -> set[int]:
        todo = list(states)
        while todo:
            i = todo.pop()
            if i < len(parts) and parts[i] == "**" and i + 1 not in states:
                states.add(i + 1)
                todo.append(i + 1)
        return states

    states = close({0})
    for name in names:
        step = {i for i in states if i < len(parts) and parts[i] == "**"}
        step |= {i + 1 for i in states if i < len(parts) and parts[i] != "**" and fnmatch.fnmatch(name, parts[i])}
        states = close(step)
        if not states:
            return False
    return len(parts) in states


def _tidy(path: str) -> str:
    """``path`` without ``.`` parts and doubled separators (``./wf//a.json`` is ``wf/a.json``); a path with ``..``
    is kept as written (a symlinked folder before it would make the shorter path another file)."""
    if not path or ".." in re.split(r"[/\\]", path):
        return path
    return os.path.normpath(path)


def expand_glob(pattern: str, limit: int = GLOB_MAX) -> list[str]:
    """The paths ``pattern`` matches, sorted, like :func:`glob.glob` with ``recursive=True`` and hidden files.

    The folders are walked with :func:`os.walk` without following symlinks, and symlinks (to files or folders)
    are never matched, as in a folder scan; the folders a folder scan skips (``SKIP_DIRS``) are not entered, and
    more than ``limit`` matches raise :class:`GlobError`. A pattern ending in ``/`` matches folders only. Without
    ``**`` the walk stops at the pattern's depth. Paths are normalised (``./wf//a.json`` is ``wf/a.json``).
    """
    seps = "/\\" if os.sep == "\\" else "/"
    folders_only = pattern.endswith(tuple(seps))
    parts = re.split(r"[/\\]" if os.sep == "\\" else "/", pattern)
    absolute = parts[0] == "" and len(parts) > 1
    parts = [p for p in parts if p and p != "."]
    fixed = 0
    while fixed < len(parts) and not glob.has_magic(parts[fixed]):
        fixed += 1
    head, rest = parts[:fixed], parts[fixed:]
    if not rest:
        return [_tidy(pattern)] if os.path.lexists(pattern) else []
    base = Path(os.sep if absolute else "", *head)
    if not base.is_dir():
        return []
    depth = None if "**" in rest else len(rest)
    found: list[str] = []
    for folder, dirs, files in os.walk(base, followlinks=False, onerror=lambda _err: None):
        names = list(Path(folder).relative_to(base).parts)
        here = Path(folder)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (here / d).is_symlink())
        candidates = dirs if folders_only else [*dirs, *(f for f in files if not (here / f).is_symlink())]
        for name in candidates:
            if _glob_match(rest, [*names, name]):
                found.append(str(base.joinpath(*names, name)))
                if len(found) > limit:
                    raise GlobError(f"{pattern} matches more than {limit:,} paths; use a narrower pattern")
        if depth is not None and len(names) + 1 >= depth:
            dirs[:] = []  # deeper paths cannot match
    return sorted(found)


def expand_paths(patterns: Iterable[str], limit: int = GLOB_MAX) -> list[str]:
    """The paths to check for the Action's ``path`` input: a path that exists as written (or has no glob
    characters) is kept (normalised: ``./wf/a.json`` is ``wf/a.json``), a pattern is expanded (:func:`expand_glob`; kept as written when it matches
    nothing, so the error names it), and a path given or matched twice is listed once. More than ``limit``
    paths in all raise :class:`GlobError`."""
    paths: dict[str, None] = {}
    for pattern in patterns:
        matches = [pattern] if os.path.lexists(pattern) or not glob.has_magic(pattern) else expand_glob(pattern, limit) or [pattern]
        paths.update(dict.fromkeys(map(_tidy, matches)))
        if len(paths) > limit:
            raise GlobError(f"the path input matches more than {limit:,} paths; use narrower patterns")
    return list(paths)


def describe(workflow: Workflow) -> str:
    """``file.json`` or ``file.json[3]`` for multi-workflow files, plus the workflow name."""
    where = workflow.source + (f"[{workflow.position}]" if workflow.position else "")
    return f"{where} ({workflow.name})"
