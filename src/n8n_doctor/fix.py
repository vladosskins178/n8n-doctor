"""``n8n-doctor fix``: patches for the auto-fixable rules.

Fixes are computed on a copy of the workflow. The result carries a list of plain-language
changes, a review of what changed (one :class:`Edit` per changed value: node, path and only
the changed token, masked; never a whole parameter value), an RFC 6902 JSON Patch and the
fixed workflow text. The patch and the fixed text are raw copies of the file's content.
Nothing here writes files; the CLI writes a new file only with ``--write``.
"""

from __future__ import annotations

import functools
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from . import nodes as nk
from .config import Config
from .expressions import Key, NodeRef, find_refs, format_path, iter_leaves, node_refs_with_keys, replace_refs
from .files import json_copy, json_dumps
from .lint import run
from .report import safe_text
from .rules import (
    _CUSTOM_SECRET_NAME,
    NODE_FIXES,
    RULES,
    SENSITIVE_NAME,
    _css_selector,
    _self_resolved,
    active_parameters,
    node_id_owners,
    path_of,
    secret_masker,
    suggest_name,
)
from .workflow import Workflow, build

TIMEOUT_RULE = "N8D302"  # only fixed when asked: n8n's 5 minutes can be what a long request needs (see fix_workflow)
RETRY = {"retryOnFail": True, "maxTries": 3, "waitBetweenTries": 1000}


@dataclass
class Edit:
    """One changed value, as the review shows it: masked, and only the changed token of a parameter value."""

    node: str | None  # the node's name (masked), None for the workflow itself
    path: str  # parameters.x is shown as x; node settings (retryOnFail) and workflow keys (pinData) as they are
    before: str | None  # the changed token before and after ("" for nothing); None where not shown
    after: str | None
    note: str  # the whole line: what changed, the changed token only

    @property
    def text(self) -> str:
        where = " ".join(([f'"{self.node}"'] if self.node is not None else []) + ([self.path] if self.path else []))
        return f"{where}: {self.note}"

    def as_dict(self) -> dict[str, Any]:
        return {"node": self.node, "path": self.path, "before": self.before, "after": self.after, "note": self.note}


@dataclass
class FixResult:
    changes: list[str] = field(default_factory=list)
    patch: list[dict[str, Any]] = field(default_factory=list)
    edits: list[Edit] = field(default_factory=list)
    diff: str = ""  # the review: the edits as text (no longer a unified diff; the name is kept for callers)
    fixed: dict[str, Any] = field(default_factory=dict)
    fixed_text: str = ""
    skipped: list[str] = field(default_factory=list)  # findings left alone, and why (shown masked)
    unwritable: str | None = None  # why the fixed text and the patch cannot be used (then fixed_text is empty)


def _ptr(*parts: str | int) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def _dump(data: Any) -> str:
    return json_dumps(data) + "\n"


def _get_original(obj: Any, keys: tuple[str | int, ...]) -> Any:
    for k in keys:
        try:
            obj = obj[k]
        except (KeyError, IndexError, TypeError):
            return None
    return obj


def _set_keys(obj: Any, keys: tuple[str | int, ...], value: str) -> None:
    target = obj
    for k in keys[:-1]:
        target = target[k]
    target[keys[-1]] = value


def _fix_pass(wf: Workflow, selected: set[str] | None, cfg: Config | None, set_timeout: int | None = None) -> tuple[FixResult, dict[str, Any]]:
    """One round of fixes on ``wf``; returns the changes and patch, and the fixed data."""
    result = FixResult()
    data = json_copy(wf.data)
    whole: set[int] = set()  # nodes whose parameters the patch replaces as a whole (see _compact)
    timeouts = set_timeout is not None and (selected is None or TIMEOUT_RULE in selected)
    fixable = {r.id for r in RULES if r.meta.fixable and (selected is None or r.id in selected)} | ({TIMEOUT_RULE} if timeouts else set())
    # every finding of the rules it can fix, not only those a report lists; none of them is shown, so none is masked
    findings = run([wf], cfg or Config(), capped=False, shown=False, only=fixable)
    wanted = {f.rule.id for f in findings if f.rule.id in fixable}
    counts: dict[str, int] = {}
    for n in wf.nodes:
        counts[n.name] = counts.get(n.name, 0) + 1
    # Node fixes are addressed by index; a name shared by two nodes is ambiguous, so those nodes are left alone.
    by_name = {n.name: n for n in wf.nodes if counts[n.name] == 1}
    unique = {n.index for n in by_name.values()}
    for f in findings:
        if f.rule.id in wanted and f.rule.id in NODE_FIXES and f.node_index is not None and f.node_index not in unique:
            name = wf.node_at[f.node_index].name
            result.skipped.append(f'{f.rule.id} "{name}": not fixed, {counts[name]} nodes are named "{name}" (rename them first, see N8D206)')

    if "N8D211" in wanted and data.get("pinData"):
        names = ", ".join(sorted(str(k) for k in data["pinData"]))
        data["pinData"] = {}
        result.patch.append({"op": "replace", "path": "/pinData", "value": {}})
        result.changes.append(f"N8D211 removed pinned data ({names})")

    if "N8D310" in wanted and isinstance(data.get("settings"), dict) and data["settings"].get("saveDataErrorExecution") == "none":
        del data["settings"]["saveDataErrorExecution"]
        result.patch.append({"op": "remove", "path": "/settings/saveDataErrorExecution"})
        result.changes.append("N8D310 failed executions are saved again (removed saveDataErrorExecution: none)")

    for f in findings:
        if f.rule.id not in wanted or f.node_index not in unique:
            continue
        node = wf.node_at[f.node_index]
        idx = node.index
        raw = data["nodes"][idx]
        params = raw.get("parameters")
        if f.rule.id == "N8D302" and isinstance(params, dict) and isinstance(params.get("options", {}), dict):
            if "options" not in params:
                params["options"] = {}
                result.patch.append({"op": "add", "path": _ptr("nodes", idx, "parameters", "options"), "value": {}})
            params["options"]["timeout"] = set_timeout
            result.patch.append({"op": "add", "path": _ptr("nodes", idx, "parameters", "options", "timeout"), "value": set_timeout})
            result.changes.append(f'N8D302 "{node.name}": timeout {set_timeout} ms')
        elif f.rule.id == "N8D303" and f.fixable:
            missing = [key for key in RETRY if raw.get(key) is None]  # maxTries: 5 stays
            for key in missing:
                raw[key] = RETRY[key]
                result.patch.append({"op": "add", "path": _ptr("nodes", idx, key), "value": RETRY[key]})
            tries = [f"{RETRY[key]} {unit}" for key, unit in (("maxTries", "tries"), ("waitBetweenTries", "ms apart")) if key in missing]
            result.changes.append(f'N8D303 "{node.name}": {", ".join(["retry on fail", *tries])} ({nk.http_method(node)})')

    if "N8D207" in wanted:
        flagged = {f.node_index for f in findings if f.rule.id == "N8D207"}  # suppressed nodes are not in findings
        for node in wf.nodes:
            params = data["nodes"][node.index].get("parameters")
            if not isinstance(params, dict) or node.disabled or node.index not in flagged or node.index not in unique:
                continue
            strings = {path.keys(): text for path, text in iter_leaves(params)}
            changed: list[str] = []
            by_keys: dict[tuple[str | int, ...], list[Any]] = {}
            for keys, ref in node_refs_with_keys(active_parameters(node), wf.limits.max_code_chars, functools.partial(_self_resolved, node), node.type):
                if ref.name not in wf.by_name and not (ref.in_literal and _css_selector(ref.name)):  # as N8D207 reports them
                    by_keys.setdefault(keys, []).append(ref)
            for keys, refs in by_keys.items():
                current = strings.get(keys)
                if current is None or current != _get_original(node.parameters, keys):  # changed by an earlier fix
                    continue
                renames: list[tuple[NodeRef, str]] = []
                counted: Counter[tuple[str, str]] = Counter()  # the same rename many times in one value is said once
                targets: dict[str, str | None] = {}
                for ref in refs:
                    if ref.name not in targets:
                        targets[ref.name] = suggest_name(wf, ref.name)
                    target = targets[ref.name]
                    if target is not None:
                        renames.append((ref, target))
                        counted[ref.name, target] += 1
                if renames:
                    text = replace_refs(current, renames)
                    _set_keys(params, keys, text)
                    result.patch.append({"op": "replace", "path": _ptr("nodes", node.index, "parameters", *keys), "value": text})
                    listed = [f'"{name}" -> "{target}"' + (f" ({n:,} times)" if n > 1 else "") for (name, target), n in counted.items()]
                    changed.append(f'N8D207 "{node.name}" {path_of(keys)}: ' + ", ".join(listed))
            if len(changed) <= _LISTED:
                result.changes += changed
            else:
                result.changes.append(f'N8D207 "{node.name}": rewrote node references in {len(changed):,} values ({_first(changed)})')

    if "N8D212" in wanted:
        added: dict[int, list[tuple[str | int, ...]]] = {}  # node -> keys of the values that got the =
        for f in findings:
            if f.rule.id != "N8D212" or f.node_index not in unique or "keys" not in f.extra:
                continue
            params = data["nodes"][f.node_index].get("parameters")
            keys = f.extra["keys"].keys()
            text = _get_original(params, keys)
            if isinstance(text, str) and not text.startswith("="):
                # " ={{ $json.a }}" is an expression but for the space before its =
                _set_keys(params, keys, text.lstrip() if text.lstrip().startswith("=") else "=" + text)
                added.setdefault(f.node_index, []).append(keys)
        for idx, changed_keys in added.items():
            if len(changed_keys) > _COMPACT:  # one operation replaces the node's parameters (see _compact)
                whole.add(idx)
            else:
                params = data["nodes"][idx]["parameters"]
                result.patch += [{"op": "replace", "path": _ptr("nodes", idx, "parameters", *k), "value": _get_original(params, k)} for k in changed_keys]
            name = wf.node_at[idx].name
            paths = [path_of(k) for k in changed_keys[: _LISTED + 1]]  # only the ones listed are formatted
            if len(changed_keys) <= _LISTED:
                result.changes += [f'N8D212 "{name}" {path}: added the leading = so the expression is evaluated' for path in paths]
            else:
                what = f"added the leading = to {len(changed_keys):,} values so their expressions are evaluated"
                result.changes.append(f'N8D212 "{name}": {what} ({_first(paths)})')

    if "N8D205" in wanted and isinstance(data.get("connections"), dict):
        existing = {n.name for n in wf.nodes}
        conns: dict[str, Any] = data["connections"]
        owners = node_id_owners(wf)
        for source in list(conns):
            if source not in existing:
                id_names = owners.get(source)
                if id_names and (len(id_names) > 1 or id_names[0] in conns):
                    why = f"{len(id_names)} nodes have this id" if len(id_names) > 1 else f'"{id_names[0]}" also has connections under its name'
                    result.skipped.append(f'N8D205 "{source}": not fixed, {why}; n8n connects nodes by name')
                    continue
                if id_names:
                    conns[id_names[0]] = conns.pop(source)
                    result.patch += [
                        {"op": "remove", "path": _ptr("connections", source)},
                        {"op": "add", "path": _ptr("connections", id_names[0]), "value": conns[id_names[0]]},
                    ]
                    result.changes.append(f'N8D205 "{id_names[0]}": its connections were listed under node id "{source}", now under its name')
                    source = id_names[0]
            if source not in existing:
                del conns[source]
                result.patch.append({"op": "remove", "path": _ptr("connections", source)})
                result.changes.append(f'N8D205 removed connections from missing node "{source}"')
                continue
            kinds = conns[source]
            if not isinstance(kinds, dict):
                continue
            for kind, outputs in kinds.items():
                if not isinstance(outputs, list):
                    continue
                for out_i, targets in enumerate(outputs):
                    if not isinstance(targets, list):
                        continue
                    kept: list[Any] = []
                    gone: set[str] = set()
                    renamed: dict[str, str] = {}
                    for t in targets:
                        target = t.get("node") if isinstance(t, dict) else None
                        if not isinstance(target, str) or target in existing:
                            kept.append(t)
                        elif target not in owners:
                            gone.add(target)
                        elif len(owners[target]) > 1:
                            kept.append(t)
                            result.skipped.append(f'N8D205 "{target}": not fixed, {len(owners[target])} nodes have this id; n8n connects nodes by name')
                        else:
                            renamed[target] = owners[target][0]
                            kept.append({**t, "node": owners[target][0]})
                    if gone or renamed:
                        outputs[out_i] = kept
                        result.patch.append({"op": "replace", "path": _ptr("connections", source, kind, out_i), "value": kept})
                    if renamed:
                        said = ", ".join(f'"{i}" -> "{n}"' for i, n in renamed.items())
                        result.changes.append(f'N8D205 "{source}": connection by node id now by name: {said}')
                    if gone:
                        what = "connections to missing nodes" if len(gone) > 1 else "a connection to missing node"
                        result.changes.append(f'N8D205 "{source}": removed {what} ' + ", ".join(f'"{g}"' for g in sorted(gone)))

    result.patch = _compact(result.patch, data, whole)
    return result, data


_LISTED = 5  # changes of one rule on one node listed one by one; more are summed up in one line
_COMPACT = 50  # more patch operations than this inside one node's parameters become one replace of them


def _first(items: list[str]) -> str:
    """The first few of ``items``, for a summary line."""
    return "; ".join(items[:3]) + ("; ..." if len(items) > 3 else "")


def _compact(patch: list[dict[str, Any]], data: dict[str, Any], whole: set[int]) -> list[dict[str, Any]]:
    """``patch``, with the operations inside the parameters of a node that has many (or is in ``whole``) replaced by
    one operation that replaces those parameters: the same result, and the patch stays about as large as the workflow."""
    inside: Counter[str] = Counter()
    for op in patch:
        parts = op["path"].split("/")
        if len(parts) > 4 and parts[1] == "nodes" and parts[3] == "parameters":
            inside[parts[2]] += 1
    many = {index for index, n in inside.items() if n > _COMPACT} | {str(i) for i in whole}
    if not many:
        return patch
    out: list[dict[str, Any]] = []
    replaced: set[str] = set()
    for op in patch:
        parts = op["path"].split("/")
        if len(parts) > 4 and parts[1] == "nodes" and parts[3] == "parameters" and parts[2] in many:
            if parts[2] not in replaced:  # where its first operation was
                replaced.add(parts[2])
                out.append({"op": "replace", "path": f"/nodes/{parts[2]}/parameters", "value": data["nodes"][int(parts[2])]["parameters"]})
            continue
        out.append(op)
    for index in sorted(many - replaced, key=int):  # nodes with no operation of their own in the patch
        out.append({"op": "replace", "path": f"/nodes/{index}/parameters", "value": data["nodes"][int(index)]["parameters"]})
    return out


# ---------------------------------------------------------------------------------------------
# The review: what each fix changed, without the values around it
# ---------------------------------------------------------------------------------------------

_EDITS_PER_NODE = 50  # changed values listed per node; more are counted
_TOKEN_MAX = 80  # a longer changed token is shown by its length only
_WHOLE = 40  # a plain-field value replaced as a whole is shown (masked) only up to this long
_SPANS_MAX = 8  # more separate changes in one value are shown by its length
_SPLIT_MAX = 128  # a longer changed region is split by node references (see _ref_spans), not by difflib
_OPCODES_MAX = 64  # difflib finding more separate pieces than this in a region: it is one span
_GAP = 6  # equal characters that separate two changes
_SCALAR = 8  # an added or removed string at least this long is shown by its length
_REF_WINDOW = 512  # how far around a change node references are looked for
# fields whose text is code, a request or a template: a change there shows the changed token only
_SENSITIVE_FIELD = re.compile(r"(?i)^(?:jscode|pythoncode|code|functioncode|functionitemcode|body|query|sqlquery|html|url|headers|json\w*|\w*json)$")
_SECRET_WORD = re.compile(r"(?i)pass|pwd|secret|token|api[-_]?key|apikey|auth|credential|private|signature|cookie|session")


def _word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _common_prefix(a: str, b: str) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i : i + 4096] == b[i : i + 4096]:  # compared in C, a block at a time
        i += 4096
    i = min(i, n)
    while i < n and a[i] == b[i]:
        i += 1
    return i


def _common_suffix(a: str, b: str, most: int) -> int:
    i = 0
    la, lb = len(a), len(b)
    while i + 4096 <= most and a[la - i - 4096 : la - i] == b[lb - i - 4096 : lb - i]:
        i += 4096
    while i < most and a[la - i - 1] == b[lb - i - 1]:
        i += 1
    return i


def _quote(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def describe_change(old: str, new: str, sensitive: bool, mask: Callable[[str], str] | None = None, limit: int | None = None) -> str:
    """What changed from ``old`` to ``new``, never the whole value: the changed token (widened to the whole word,
    or the whole node reference ``$('Name')`` it is in), never the text around it. A value replaced as a whole
    shows its length, unless it is at most 40 characters, outside ``sensitive`` fields and holds no secret: then
    old -> new. ``mask`` masks secrets; a value over ``limit`` characters (too long to check for secrets) is
    treated as sensitive."""
    return _describe(old, new, sensitive, mask, limit)[2]


def _describe(old: str, new: str, sensitive: bool, mask: Callable[[str], str] | None, limit: int | None) -> tuple[str | None, str | None, str]:
    """(changed token before, after, the description) for :func:`describe_change`."""
    big = limit is not None and max(len(old), len(new)) > limit
    if big or mask is None:
        a, b = old, new
        sensitive = sensitive or big
    else:
        a, b = mask(old), mask(new)
        sensitive = sensitive or a != old or b != new  # a secret in the value: never shown whole
    changed = f"<value changed, {len(new):,} chars>"
    if a == b:
        return None, None, changed
    spans = _spans(a, b)
    cores: list[str] = []
    distinct: set[str] = set()
    for a0, a1, b0, b1 in spans:
        before, after = a[a0:a1], b[b0:b1]
        if mask is not None and big:
            before, after = mask(before), mask(after)
        if a0 == 0 and a1 == len(a) and b1 == len(b) and (sensitive or max(len(a), len(b)) > _WHOLE):
            return None, None, changed  # replaced as a whole: shown only when short and in a plain field
        if max(len(before), len(after)) > _TOKEN_MAX:
            return None, None, changed
        if not before or not after:
            where = "at the start" if a0 == 0 else "at the end" if a1 == len(a) else f"at character {a0 + 1:,}"
            cores.append(f"inserted {_quote(after)} {where}" if not before else f"removed {_quote(before)} {where}")
        else:
            cores.append(f"{_quote(before)} -> {_quote(after)}")
        distinct.add(cores[-1])
        if len(distinct) > _SPANS_MAX:
            return None, None, changed
    if len(spans) > 1:  # separate changes: each token alone, never the text between them; repeats counted
        counted = Counter(cores)
        if len(counted) > _SPANS_MAX:
            return None, None, changed
        return None, None, "; ".join(core + (f" ({n:,} times)" if n > 1 else "") for core, n in counted.items())
    a0, a1, b0, b1 = spans[0]
    before, after = a[a0:a1], b[b0:b1]
    if mask is not None and big:
        before, after = mask(before), mask(after)
    return before, after, cores[0]


def _widen(a: str, b: str, a0: int, a1: int, b0: int, b1: int) -> tuple[int, int]:
    """The span ``a[a0:a1]`` widened to the whole word, or the whole node reference ``$('Name')``, it is in."""
    if any(map(_word, a[a0:a1] + b[b0:b1])):  # a word changed: show all of it, not "ia" -> "ai"
        while a0 > 0 and _word(a[a0 - 1]):
            a0 -= 1
        while a1 < len(a) and _word(a[a1]):
            a1 += 1
    if "$" in a:
        lo = max(0, a0 - _REF_WINDOW)
        for ref in find_refs(a[lo : a1 + _REF_WINDOW]):
            if lo + ref.start <= a0 and a1 <= lo + ref.end:
                return lo + ref.start, lo + ref.end
    return a0, a1


def _ref_spans(a: str, b: str) -> list[tuple[int, int, int, int]] | None:
    """The changed spans from ``a`` to ``b`` when they differ only in node references (and a leading ``=``), which
    is what the fixes change: one span per changed reference. None for any other change. Linear time."""
    refs_a, refs_b = find_refs(a), find_refs(b)
    if len(refs_a) != len(refs_b) or not refs_a:
        return None
    spans: list[tuple[int, int, int, int]] = []
    if a[: refs_a[0].start] != b[: refs_b[0].start]:
        if "=" + a[: refs_a[0].start] != b[: refs_b[0].start]:
            return None
        spans.append((0, 0, 0, 1))  # the = that makes it an expression
    for k, (x, y) in enumerate(zip(refs_a, refs_b, strict=True)):
        next_a = refs_a[k + 1].start if k + 1 < len(refs_a) else len(a)
        next_b = refs_b[k + 1].start if k + 1 < len(refs_b) else len(b)
        if next_a < x.end or next_b < y.end or a[x.end : next_a] != b[y.end : next_b]:  # overlapping, or text changed
            return None
        if a[x.start : x.end] != b[y.start : y.end]:
            spans.append((x.start, x.end, y.start, y.end))
    return spans or None


def _spans(a: str, b: str) -> list[tuple[int, int, int, int]]:
    """The changed spans (a0, a1, b0, b1) from ``a`` to ``b``, each widened by :func:`_widen`. Changes apart by
    at least ``_GAP`` equal characters are separate spans, so the text between them is never shown. A changed
    region longer than ``_SPLIT_MAX`` is split only by node references (:func:`_ref_spans`), or is one span:
    difflib's work grows faster than the square of the length."""
    p = _common_prefix(a, b)
    s = _common_suffix(a, b, min(len(a), len(b)) - p)
    a0, a1, b0, b1 = p, len(a) - s, p, len(b) - s
    raw: list[list[int]] = [[a0, a1, b0, b1]]
    if max(a1 - a0, b1 - b0) > _SPLIT_MAX:
        by_ref = _ref_spans(a, b)
        if by_ref is not None:
            return by_ref  # whole references already: nothing to widen
    else:
        opcodes = SequenceMatcher(None, a[a0:a1], b[b0:b1], autojunk=False).get_opcodes()
        if len(opcodes) <= _OPCODES_MAX:
            raw = []
            for tag, i0, i1, j0, j1 in opcodes:
                if tag == "equal" and i1 - i0 >= _GAP:
                    continue
                if raw and raw[-1][1] == a0 + i0:  # a short equal run joins its neighbours
                    raw[-1][1], raw[-1][3] = a0 + i1, b0 + j1
                else:
                    raw.append([a0 + i0, a0 + i1, b0 + j0, b0 + j1])
    k = 0
    while k < len(raw):
        i0, i1, j0, j1 = raw[k]
        x0, x1 = _widen(a, b, i0, i1, j0, j1)
        if k > 0 and x0 <= raw[k - 1][1]:  # widened into the previous span: one span
            prev = raw.pop(k - 1)
            k -= 1
            raw[k] = [prev[0], i1, prev[2], j1]
            continue
        if k + 1 < len(raw) and x1 >= raw[k + 1][0]:
            nxt = raw.pop(k + 1)
            raw[k] = [i0, nxt[1], j0, nxt[3]]
            continue
        raw[k] = [x0, x1, j0 - (i0 - x0), j1 + (x1 - i1)]
        k += 1
    return [(x[0], x[1], x[2], x[3]) for x in raw]


def _sensitive(keys: Key, params: Any) -> bool:
    """A parameter whose value is code, a request body, query, URL, header or template, or that is named for a
    secret (``password``, or the ``value`` of an entry whose ``name`` is ``Authorization``)."""
    for k in keys:
        if isinstance(k, str) and (_SENSITIVE_FIELD.match(k) or _SECRET_WORD.search(k)):
            return True
    obj = params
    for k in keys[:-1]:
        try:
            obj = obj[k]
        except (KeyError, IndexError, TypeError):
            return True
    name = obj.get("name") if isinstance(obj, dict) else None
    return isinstance(name, str) and bool(SENSITIVE_NAME.match(name.strip()) or _CUSTOM_SECRET_NAME.search(name) or _SECRET_WORD.search(name))


def _scalar(value: Any, mask: Callable[[str], str]) -> str:
    """A value a fix adds or removes: numbers, booleans and short strings (masked) as they are, the rest by size."""
    if isinstance(value, str):
        return _quote(mask(value)) if len(value) < _SCALAR else f"<{len(value):,} chars>"
    if isinstance(value, dict):
        return "{}" if not value else f"<{len(value):,} entries>"
    if isinstance(value, list):
        return "[]" if not value else f"<{len(value):,} items>"
    return json.dumps(value)


def _added_removed(kind: str, old: Any, new: Any, mask: Callable[[str], str]) -> str:
    if kind == "added":
        return f"added {_scalar(new, mask)}"
    if kind == "removed":
        return f"removed {_scalar(old, mask)}"
    return f"{_scalar(old, mask)} -> {_scalar(new, mask)}"


def _leaf_changes(a: Any, b: Any) -> Iterator[tuple[Key, Any, Any, str]]:
    """(keys, old, new, kind) for every leaf where ``a`` and ``b`` differ; kind is changed, added or removed.
    A container added as a whole is listed by its leaves. Iterative."""
    missing = object()
    stack: list[tuple[Key, Any, Any]] = [((), a, b)]
    while stack:
        keys, x, y = stack.pop()
        if isinstance(x, dict) and isinstance(y, dict):
            for k in reversed(list(dict.fromkeys([*x, *y]))):
                stack.append(((*keys, k), x.get(k, missing), y.get(k, missing)))
        elif isinstance(x, list) and isinstance(y, list):
            for i in range(max(len(x), len(y)) - 1, -1, -1):
                stack.append(((*keys, i), x[i] if i < len(x) else missing, y[i] if i < len(y) else missing))
        elif x is missing and isinstance(y, dict) and y:
            stack.extend(((*keys, k), missing, v) for k, v in reversed(list(y.items())))
        elif x is missing:
            yield keys, None, y, "added"
        elif y is missing:
            yield keys, x, None, "removed"
        elif x != y or type(x) is not type(y):
            yield keys, x, y, "changed"


def _review(wf: Workflow, data: dict[str, Any], mask: Callable[[str], str]) -> list[Edit]:
    """The edits from ``wf.data`` to ``data``."""
    edits: list[Edit] = []
    limit = wf.limits.max_value_chars
    old = wf.data

    def shown_path(keys: Key) -> str:
        return safe_text(mask(path_of(keys)))

    pinned = old.get("pinData")
    if isinstance(pinned, dict) and pinned and data.get("pinData") == {}:
        # pinned data is captured output (emails, tokens): how much went, not what it was
        records = sum(len(v) if isinstance(v, list) else 1 for v in pinned.values())
        note = f"removed {records:,} pinned record{'s' if records != 1 else ''} of {len(pinned):,} node{'s' if len(pinned) != 1 else ''}"
        edits.append(Edit(None, "pinData", None, None, note))
    settings_old, settings_new = old.get("settings"), data.get("settings")
    if isinstance(settings_old, dict) and isinstance(settings_new, dict) and settings_old != settings_new:
        for keys, x, y, kind in _leaf_changes(settings_old, settings_new):
            edits.append(Edit(None, "settings." + shown_path(keys), None, None, safe_text(_added_removed(kind, x, y, mask))))
    nodes_old, nodes_new = old.get("nodes"), data.get("nodes")
    if isinstance(nodes_old, list) and isinstance(nodes_new, list):
        for raw_old, raw_new in zip(nodes_old, nodes_new, strict=False):
            if raw_old == raw_new or not isinstance(raw_old, dict) or not isinstance(raw_new, dict):
                continue
            name = raw_old.get("name")
            shown_name = safe_text(mask(name)) if isinstance(name, str) else None
            params = raw_old.get("parameters")
            listed = more = 0
            for keys, x, y, kind in _leaf_changes(raw_old, raw_new):
                if listed == _EDITS_PER_NODE:  # one fix can touch thousands of values: they are counted
                    more += 1
                    continue
                listed += 1
                inside = len(keys) > 1 and keys[0] == "parameters"
                path = shown_path(keys[1:] if inside else keys)
                if kind == "changed" and isinstance(x, str) and isinstance(y, str):
                    sensitive = not inside or _sensitive(keys[1:], params)
                    before, after, note = _describe(x, y, sensitive, mask, limit)
                    token_before = None if before is None else safe_text(before)
                    edits.append(Edit(shown_name, path, token_before, None if after is None else safe_text(after), safe_text(note)))
                    continue
                edits.append(Edit(shown_name, path, None, None, safe_text(_added_removed(kind, x, y, mask))))
            if more:
                edits.append(Edit(shown_name, "", None, None, f"and {more:,} more changed value{'s' if more != 1 else ''}"))
    conns_old, conns_new = old.get("connections"), data.get("connections")
    if isinstance(conns_old, dict) and isinstance(conns_new, dict) and conns_old != conns_new:
        for source, kinds in conns_old.items():
            shown_source = safe_text(mask(str(source)))
            if source not in conns_new:
                edits.append(Edit(shown_source, "connections", None, None, "removed (the node does not exist)"))
                continue
            if not isinstance(kinds, dict) or kinds == conns_new[source]:
                continue
            for kind, outputs in kinds.items():
                after_outputs = conns_new[source].get(kind) if isinstance(conns_new[source], dict) else None
                if not isinstance(outputs, list) or not isinstance(after_outputs, list):
                    continue
                for i, targets in enumerate(outputs):
                    kept = after_outputs[i] if i < len(after_outputs) else []
                    if targets == kept or not isinstance(targets, list) or not isinstance(kept, list):
                        continue
                    gone = sorted({str(t.get("node")) for t in targets if isinstance(t, dict)} - {str(t.get("node")) for t in kept if isinstance(t, dict)})
                    names = ", ".join(_quote(g) for g in gone)
                    what = "the connections to" if len(gone) > 1 else "the connection to"
                    edits.append(Edit(shown_source, f"connections.{format_path((kind, i))}", None, None, safe_text(mask(f"removed {what} {names}"))))
    return edits


def _diff_label(source: str) -> str:
    """The file name the review starts with: ``./x.json`` -> ``x.json``, ``/abs/x.json`` as it is."""
    label = source
    while label.startswith("./"):
        label = label[2:].lstrip("/")
    return label or source


def _not_finite(data: Any) -> str | None:
    """Where ``data`` holds a number JSON cannot write (NaN, Infinity, 1e999 as read), or None. Iterative, linear."""
    stack: list[tuple[Any, tuple[str | int, ...]]] = [(data, ())]
    while stack:
        current, keys = stack.pop()
        if isinstance(current, float) and not math.isfinite(current):
            return path_of(keys)
        if isinstance(current, dict):
            stack.extend((v, (*keys, k)) for k, v in current.items() if isinstance(v, (dict, list, float)))
        elif isinstance(current, list):
            stack.extend((v, (*keys, i)) for i, v in enumerate(current) if isinstance(v, (dict, list, float)))
    return None


def fix_workflow(wf: Workflow, selected: set[str] | None = None, cfg: Config | None = None, set_timeout: int | None = None) -> FixResult:
    """Patches for the fixable findings that ``cfg`` leaves enabled (``selected``: only these rule ids).

    Runs a few rounds, because one fix can reveal another (adding the = to an expression
    makes its node reference visible to N8D207). ``set_timeout``: also set this timeout on HTTP Requests without
    one (N8D302), which no default does: lowering n8n's 5 minutes can break a long request that works today.
    A file holding NaN, Infinity or a number too large for a float cannot be written as JSON again: then
    ``unwritable`` says so and the fixed text is empty.
    """
    result = FixResult()
    current = wf
    data: dict[str, Any] = wf.data
    for round_ in range(3):
        step, data = _fix_pass(current, selected, cfg, set_timeout)
        if round_ == 0:
            result.skipped = step.skipped
            if set_timeout is None and selected is not None and TIMEOUT_RULE in selected:
                count = sum(f.rule.id == TIMEOUT_RULE for f in run([wf], cfg or Config(), capped=False, shown=False, only={TIMEOUT_RULE}))
                if count:
                    result.skipped.append(f"N8D302: {count:,} HTTP Request node{'s' if count != 1 else ''} not fixed, choose a timeout with --set-timeout MS")
        if not step.changes:
            break
        result.changes += step.changes
        result.patch += step.patch
        names = [n.name for n in current.nodes]
        index, budget = current.name_index, current.fuzzy_budget
        current = build(data, wf.source, limits=wf.limits)
        current.fuzzy_budget = budget
        if [n.name for n in current.nodes] == names:  # fixes never rename nodes: the suggestions found so far still hold
            current.name_index = index
    mask = secret_masker(wf)
    result.skipped = [safe_text(mask(note)) for note in dict.fromkeys(result.skipped)]
    if result.changes:
        # the review and the list of changes are for reading, so secrets in them (node names included) are masked,
        # all of them whatever the config or the inline suppressions say; the patch and fixed text stay exact
        result.edits = _review(wf, data, mask)
        label = safe_text(mask(_diff_label(wf.source) + (f"[{wf.position}]" if wf.position else "")))
        result.diff = "".join(f"{line}\n" for line in [f"{label}:", *(f"  {e.text}" for e in result.edits)])
        result.changes = [safe_text(mask(change)) for change in result.changes]  # names can hold terminal escapes
    result.fixed = data
    where = _not_finite(data)
    if where is not None:
        result.unwritable = (
            f"the file holds NaN, Infinity or a number too large for JSON at {safe_text(mask(where))}, so no fixed copy or patch can be made: correct it first"
        )
        return result
    result.fixed_text = _dump(data)
    return result
