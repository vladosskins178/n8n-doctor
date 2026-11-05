"""Finding node references in n8n expressions and Code node source."""

from __future__ import annotations

import ast
import bisect
import collections
import dataclasses
import re
import warnings
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

# Top-level parameters that hold source code on any node: Code, Function, Function Item, AI Transform and the
# LangChain Code Tool (jsCode / pythonCode).
CODE_PARAMS = frozenset({"jsCode", "functionCode", "pythonCode"})
# Other fields n8n edits as code (codeNodeEditor / jsEditor in the node descriptions), by node type: the
# LangChain Code node's two methods, and the custom sort code of the Sort and Item Lists nodes. n8n runs them as
# JavaScript; it never resolves {{ }} in them.
CODE_FIELDS: dict[str, frozenset[tuple[str, ...]]] = {
    "@n8n/n8n-nodes-langchain.code": frozenset({("code", "execute", "code"), ("code", "supplyData", "code")}),
    "n8n-nodes-base.sort": frozenset({("code",)}),
    "n8n-nodes-base.itemLists": frozenset({("code",)}),
}
_CODE_FIELD_DEPTH = 3


def code_language(node_type: str, path: KeyPath) -> str | None:
    """``"javascript"`` or ``"python"`` when the value at ``path`` of a ``node_type`` node is source code, else None."""
    if path.depth == 1 and path.first in CODE_PARAMS:
        return "python" if path.first == "pythonCode" else "javascript"
    fields = CODE_FIELDS.get(node_type)
    if fields is not None and path.depth <= _CODE_FIELD_DEPTH and path.keys() in fields:
        return "javascript"
    return None


def code_values(node_type: str, parameters: dict[str, Any]) -> Iterator[tuple[tuple[str, ...], str]]:
    """(keys, source) for every code field of a node's parameters (see :func:`code_language`)."""
    for key in sorted(CODE_PARAMS):
        if isinstance(parameters.get(key), str):
            yield (key,), parameters[key]
    for keys in sorted(CODE_FIELDS.get(node_type, ())):
        value: Any = parameters
        for k in keys:
            value = value.get(k) if isinstance(value, dict) else None
        if isinstance(value, str) and keys[0] not in CODE_PARAMS:
            yield keys, value


_STR = r"""(?:"((?:[^"\\\n]|\\[\s\S])*)"|'((?:[^'\\\n]|\\[\s\S])*)'|`((?:[^`\\$]|\\[\s\S])*)`)"""
_REF_PATTERNS = (
    ("$()", re.compile(r"\$\(\s*" + _STR + r"\s*\)")),
    ("$node[]", re.compile(r"\$node\s*\[\s*" + _STR + r"\s*\]")),
    ("$items()", re.compile(r"\$items\(\s*" + _STR + r"\s*[,)]")),
    ("$node.", re.compile(r"\$node\.([A-Za-z_$][\w$]*)")),
)
# Python Code: _('Name') (n8n's $('Name'))
_PY_REF = re.compile(r"""(?<![\w.])_\(\s*(?:"((?:[^"\\\n]|\\[\s\S])*)"|'((?:[^'\\\n]|\\[\s\S])*)')\s*\)""")
_NODE_DOT_BUILTINS = {"context", "parameter"}  # `$node.context` is not a node name in old Function nodes

# JavaScript string escapes: \xHH, \uHHHH, \u{H...}, the one-letter ones, a line continuation (gone), any other
# character as itself
_JS_ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|(\r\n|[\s\S]))")
_JS_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "\n": "", "\r": "", "\r\n": "", "\u2028": "", "\u2029": ""}


def _js_escape(m: re.Match[str]) -> str:
    code = m.group(1) or m.group(2) or m.group(3)
    if code is not None:
        value = int(code, 16)
        return chr(value) if value <= 0x10FFFF else m.group(0)
    return _JS_SIMPLE.get(m.group(4), m.group(4))


def _unescape(raw: str) -> str:
    """The text of a JavaScript string literal's body ``raw``."""
    return _JS_ESCAPE.sub(_js_escape, raw) if "\\" in raw else raw


def _unescape_python(raw: str, quote: str) -> str:
    """The text of a Python string literal's body ``raw`` (\\x41, \\u0041, \\101, \\N{...}), as Python reads it."""
    if "\\" not in raw:
        return raw
    try:
        with warnings.catch_warnings():  # "\d" is an invalid escape: a SyntaxWarning, kept off the output
            warnings.simplefilter("ignore")
            value = ast.literal_eval(quote + raw + quote)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return _unescape(raw)
    return value if isinstance(value, str) else raw


@dataclass(slots=True)  # not frozen: building millions of them (refs in huge Code nodes) costs a quarter as much
class NodeRef:
    name: str
    syntax: str  # "$()", "$node[]", "$items()", "$node.", "_()" (Python)
    start: int
    end: int
    in_literal: bool = False  # inside a ${ } of a Code template literal, with a name that may be a CSS selector


_REGEX_AFTER = set("(,=:[!&|?{};~^%*<>")
_REGEX_KEYWORDS = {"return", "typeof", "case", "in", "of", "void", "delete", "throw", "new", "else", "do", "yield", "await", "instanceof"}


def _regex_may_start(code: str, i: int) -> bool:
    """True when a ``/`` at ``i`` starts a regex literal rather than a division (by the previous token)."""
    k = i - 1
    while k >= 0 and code[k] in " \t\r\n":
        k -= 1
    if k < 0 or code[k] in _REGEX_AFTER:
        return True
    end = k + 1
    while k >= 0 and (code[k].isalnum() or code[k] in "_$"):
        k -= 1
    return code[k + 1 : end] in _REGEX_KEYWORDS and (k < 0 or code[k] != ".")


def _regex_end(code: str, i: int) -> int:
    """The index after the closing ``/`` of a regex literal starting at ``i``, or 0 if there is none on the line."""
    j, n, in_class = i + 1, len(code), False
    if j < n and code[j] in "/*":
        return 0
    while j < n:
        c = code[j]
        if c == "\n":
            return 0
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return j + 1
        j += 1
    return 0


_PLAIN = re.compile(r"[^'\"`/]+")  # runs of code with nothing that can start a string, comment or regex literal
_STRING_BODY = {
    q: re.compile(r"(?:[^" + q + r"\\" + ("" if q == "`" else r"\n") + r"]|\\[\s\S]?)*") for q in "'\"`"
}  # up to the closing quote, a line end (except in template literals) or the end; a backslash escapes any character
_NOT_NEWLINE = re.compile(r"[^\n]")


def strip_js_comments(code: str, blank_strings: bool = False) -> str:
    """Blank out ``//`` and ``/* */`` comments, keeping offsets intact.

    String literals are kept, or with ``blank_strings`` their contents (template literals
    included) are replaced by spaces, so words inside strings are not taken for code.
    Regex literals (``/items/g``) are treated like strings.
    Linear time: one pass. The result is cached per source (see :class:`_StripCache`), since
    several rules and the fix and masking passes all strip the same Code node.
    """
    return _STRIPPED.get(_strip_js_comments, code, blank_strings)


class _StripCache:
    """Stripped sources by (function, source, blank_strings), least recently used dropped first, holding at most
    ``budget`` characters: every rule, every fix round and the masking passes strip the same Code values, so
    each is stripped once per run however many Code nodes there are (an lru_cache of a few entries is not
    enough for a workflow with many). The source string is the key: its hash is computed once per string."""

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.size = 0
        self.entries: collections.OrderedDict[tuple[Callable[[str, bool], str], str, bool], str] = collections.OrderedDict()

    def get(self, func: Callable[[str, bool], str], code: str, blank_strings: bool) -> str:
        key = (func, code, blank_strings)
        found = self.entries.get(key)
        if found is not None:
            self.entries.move_to_end(key)
            return found
        result = func(code, blank_strings)
        if 2 * len(code) <= self.budget:  # the key and the result
            self.entries[key] = result
            self.size += 2 * len(code)
            while self.size > self.budget:
                (_, old, _), _ = self.entries.popitem(last=False)
                self.size -= 2 * len(old)
        return result


_STRIPPED = _StripCache(64 * 1024 * 1024)


def _strip_js_comments(code: str, blank_strings: bool) -> str:
    out: list[str] = []
    i, n = 0, len(code)
    no_regex_before = 0  # a regex scan that found no closing / ran to here; later starts on that line are divisions
    while i < n:
        plain = _PLAIN.match(code, i)
        if plain:
            out.append(plain.group(0))
            i = plain.end()
            continue
        ch = code[i]
        if ch in "'\"`":
            j = _STRING_BODY[ch].match(code, i + 1).end()  # type: ignore[union-attr]  # a * pattern always matches
            closed = j < n and code[j] == ch
            literal = code[i : j + 1] if closed else code[i:j]
            if blank_strings and len(literal) > 1:
                inner = literal[1:-1] if closed else literal[1:]
                literal = ch + _NOT_NEWLINE.sub(" ", inner) + (ch if closed else "")
            out.append(literal)
            i = j + 1 if closed else j
        elif code.startswith("//", i):
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif code.startswith("/*", i):
            j = code.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(_NOT_NEWLINE.sub(" ", code[i:j]))
            i = j
        elif i >= no_regex_before and _regex_may_start(code, i) and (j := _regex_end(code, i)) > 0:
            literal = code[i:j]
            out.append("/" + " " * (len(literal) - 2) + "/" if blank_strings else literal)
            i = j
        elif i >= no_regex_before and _regex_may_start(code, i):
            # no regex literal ends on this line: remember that, so a line of "[/[/[/" is scanned once, not once per /
            line_end = code.find("\n", i)
            no_regex_before = n if line_end == -1 else line_end
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def find_refs(text: str) -> list[NodeRef]:
    refs: list[NodeRef] = []
    for syntax, pattern in _REF_PATTERNS:
        for m in pattern.finditer(text):
            if syntax == "$node.":
                name = m.group(1)
                if name in _NODE_DOT_BUILTINS:
                    continue
            else:
                raw = m.group(m.lastindex or 0)  # the one quote style that matched
                name = _unescape(raw)
                if "${" in name:  # $(`${nodeName}`), or '${...}' inside a template literal: the name is computed
                    continue
            refs.append(NodeRef(name, syntax, m.start(), m.end()))
    refs.sort(key=lambda r: r.start)
    return refs


def find_python_refs(text: str) -> list[NodeRef]:
    """References in Python Code source: ``_('Name')``."""
    refs: list[NodeRef] = []
    for m in _PY_REF.finditer(text):
        quote = "'" if m.group(1) is None else '"'
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        refs.append(NodeRef(_unescape_python(raw, quote), "_()", m.start(), m.end()))
    return refs


def strip_python_comments(code: str, blank_strings: bool = False) -> str:
    """:func:`strip_js_comments` for Python: ``#`` comments blanked, strings (triple-quoted ones included) kept or,
    with ``blank_strings``, their contents replaced by spaces. Offsets are kept; linear time; cached."""
    return _STRIPPED.get(_strip_python_comments, code, blank_strings)


_PY_PLAIN = re.compile(r"[^'\"#]+")
_PY_STRING_BODY = {q: re.compile(r"(?:[^" + q + r"\\\n]|\\[\s\S]?)*") for q in "'\""}
_PY_TRIPLE_BODY = {q: re.compile(r"(?:[^" + q + r"\\]|\\[\s\S]?|" + q + r"(?!" + q + q + r"))*") for q in "'\""}


def _strip_python_comments(code: str, blank_strings: bool) -> str:
    out: list[str] = []
    i, n = 0, len(code)
    while i < n:
        plain = _PY_PLAIN.match(code, i)
        if plain:
            out.append(plain.group(0))
            i = plain.end()
            continue
        ch = code[i]
        if ch == "#":
            j = code.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        width = 3 if code.startswith(ch * 3, i) else 1
        body = (_PY_TRIPLE_BODY if width == 3 else _PY_STRING_BODY)[ch].match(code, i + width).end()  # type: ignore[union-attr]  # a * pattern always matches
        closed = code.startswith(ch * width, body)
        j = body + width if closed else body
        literal = code[i:j]
        if blank_strings:
            literal = ch * width + _NOT_NEWLINE.sub(" ", code[i + width : body]) + (ch * width if closed else "")
        out.append(literal)
        i = j
    return "".join(out)


def expression_spans(value: str) -> Iterator[tuple[int, int]]:
    """(start, end) of the text inside each ``{{ ... }}``, found with plain string search (linear time)."""
    pos = 0
    while True:
        start = value.find("{{", pos)
        if start == -1:
            return
        end = value.find("}}", start + 2)
        if end == -1:
            return
        yield start + 2, end
        pos = end + 2


def without_spans(value: str) -> str:
    """``value`` with every ``{{ ... }}`` replaced by ``{{}}``."""
    out: list[str] = []
    pos = 0
    for start, end in expression_spans(value):
        out.append(value[pos:start])
        pos = end
    out.append(value[pos:])
    return "".join(out)


def find_expression_refs(value: str) -> list[NodeRef]:
    """References inside the ``{{ }}`` parts of an expression; the text around them is literal output."""
    refs: list[NodeRef] = []
    for start, end in expression_spans(value):
        code = strip_js_comments(value[start:end])
        found = find_refs(code)
        if found:  # text inside a string or a comment is no reference, as in a Code node
            refs.extend(NodeRef(r.name, r.syntax, r.start + start, r.end + start) for r in _outside_literals(code, found))
    return refs


def is_expression(value: str) -> bool:
    return value.startswith("=")


Key = tuple[str | int, ...]


class KeyPath:
    """Where a value sits inside parameters: a chain of keys that shares its start with its siblings.

    The first and last key and the depth are read in constant time; the full tuple of keys (for
    messages and edits) is built only on request, so walking a parameter tree costs constant
    work per value, however deep it is.
    """

    __slots__ = ("_text", "depth", "first", "last", "parent")

    def __init__(self, parent: KeyPath | None = None, key: str | int = "") -> None:
        self.parent = parent
        self.depth: int = parent.depth + 1 if parent is not None else 0
        self.last: str | int | None = key if parent is not None else None
        self.first: str | int | None = (parent.first if parent.depth else key) if parent is not None else None
        self._text: str | None = None if parent is not None else ""

    def text(self) -> str:
        """:func:`format_path` of the keys: built on the parent's text, which is kept for its other children."""
        if self._text is None:
            pending: list[KeyPath] = []
            node: KeyPath = self
            while node._text is None:
                pending.append(node)
                node = node.parent  # type: ignore[assignment]  # the root's text is set
            text = node._text
            for item in reversed(pending):
                key = item.last
                text = text + (f"[{key}]" if isinstance(key, int) else f".{key}" if text else str(key))
                if item is not self:  # kept for the parents only: a leaf's text is asked for once
                    item._text = text
            return text
        return self._text

    def keys(self) -> Key:
        out: list[str | int] = []
        node: KeyPath | None = self
        while node is not None and node.parent is not None:
            out.append(node.last)  # type: ignore[arg-type]  # set for every node but the root
            node = node.parent
        return tuple(reversed(out))

    def __repr__(self) -> str:
        return f"KeyPath{self.keys()!r}"


ROOT = KeyPath()


def iter_leaves(value: Any) -> Iterator[tuple[KeyPath, str]]:
    """Every string inside ``value`` and where it is, in document order. Iterative (no recursion limit)."""
    stack: list[tuple[KeyPath, Any]] = [(ROOT, value)]
    while stack:
        path, current = stack.pop()
        if isinstance(current, str):
            yield path, current
        elif isinstance(current, dict):
            stack.extend((KeyPath(path, str(k)), v) for k, v in reversed(current.items()) if isinstance(v, (str, dict, list)))
        elif isinstance(current, list):
            stack.extend((KeyPath(path, i), current[i]) for i in range(len(current) - 1, -1, -1) if isinstance(current[i], (str, dict, list)))


def format_path(keys: Key) -> str:
    """``("options", "headers", 0, "value")`` -> ``options.headers[0].value`` (for messages only)."""
    out = ""
    for k in keys:
        out += f"[{k}]" if isinstance(k, int) else (f".{k}" if out else k)
    return out


def iter_strings(value: Any) -> Iterator[tuple[str, str]]:
    """Every string inside ``value`` with a dotted path such as ``options.headers[0].value``."""
    for path, text in iter_leaves(value):
        yield format_path(path.keys()), text


def leaf_key(path: str) -> str:
    """``headerParameters.parameters[0].value`` -> ``value``."""
    return re.split(r"[.\[]", path)[-1].rstrip("]")


def node_refs_with_keys(
    parameters: dict[str, Any], code_limit: int | None = None, resolved: Callable[[KeyPath], bool] | None = None, node_type: str = ""
) -> Iterator[tuple[Key, NodeRef]]:
    """References to other nodes from expressions (``=...``, or any value where ``resolved`` says the node resolves
    its ``{{ }}`` itself: SQL queries, HTML templates) and from source code (its first ``code_limit`` characters,
    see :func:`code_part`; which fields are code depends on ``node_type``, see :func:`code_language`)."""
    for path, value in iter_leaves(parameters):
        language = code_language(node_type, path)
        if language == "python":
            code = strip_python_comments(code_part(value, code_limit))
            refs = find_python_refs(code)
            if refs:
                blanked = strip_python_comments(code, blank_strings=True)
                refs = [r for r in refs if blanked[r.start] == "_"]  # not text inside a string
        elif language is not None:
            code = strip_js_comments(code_part(value, code_limit))
            refs = find_refs(code)
            if refs:
                refs = _outside_literals(code, refs)
            if refs and _declares_dollar(code):
                refs = [r for r in refs if r.syntax != "$()"]
        elif "$" in value and (is_expression(value) or (resolved is not None and "{{" in value and resolved(path))):
            refs = find_expression_refs(value)
        else:
            continue
        if refs:
            keys = path.keys()
            for ref in refs:
                yield keys, ref


# const $ = cheerio.load(html), let $; a, $ = ...; $ => ..., ($, a) => ..., function f(a, $) {, parse($) {
_LOCAL_DOLLAR = re.compile(
    r"(?<![\w$.])(?:(?:const|let|var)\s+\$(?![\w$])|\$\s*=(?!=))"
    r"|\(\s*(?:[\w$]{1,64}\s*,\s*){0,8}\$\s*(?:,\s*[\w$]{1,64}\s*){0,8}\)\s*(?:=>|\{)"
)


def _declares_dollar(code: str) -> bool:
    """The code (comments gone) gives ``$`` a value of its own, as cheerio or jQuery: its ``$()`` calls are not n8n's."""
    return _LOCAL_DOLLAR.search(code) is not None and _LOCAL_DOLLAR.search(strip_js_comments(code, blank_strings=True)) is not None


_BLANK_RUN = re.compile(r"[ \n]+")
_TEMPLATE_LOOKBACK = 4096  # how far back an open ${ is looked for inside a template literal


def _outside_literals(code: str, refs: list[NodeRef]) -> list[NodeRef]:
    """The references that are code, not text inside a string or regex literal: ``"<script>$('#go')</script>"``
    is HTML for a browser. Inside a template literal a reference counts when it is within ``${ }``,
    which n8n evaluates; ``in_literal`` marks one whose name is more than a plain word, as ``#go`` or ``ul li``: that
    can only be jQuery in generated HTML, or a node name with such characters (see rules._css_selector)."""
    blanked = strip_js_comments(code, blank_strings=True)  # literal contents become spaces, offsets kept
    if all(blanked[r.start] == "$" for r in refs):
        return refs
    runs = [(m.start(), m.end()) for m in _BLANK_RUN.finditer(blanked)]
    starts = [start for start, _ in runs]
    kept: list[NodeRef] = []
    for ref in refs:
        if blanked[ref.start] == "$":
            kept.append(ref)
            continue
        opening = runs[bisect.bisect_right(starts, ref.start) - 1][0] - 1  # the quote (or /) the literal starts with
        if opening >= 0 and code[opening] == "`":
            lo = max(opening, ref.start - _TEMPLATE_LOOKBACK)
            if code.rfind("${", lo, ref.start) > code.rfind("}", lo, ref.start):
                kept.append(dataclasses.replace(ref, in_literal=not ref.name.isidentifier()))
    return kept


def node_refs_in_parameters(
    parameters: dict[str, Any], code_limit: int | None = None, resolved: Callable[[KeyPath], bool] | None = None, node_type: str = ""
) -> Iterator[tuple[str, NodeRef]]:
    for keys, ref in node_refs_with_keys(parameters, code_limit, resolved, node_type):
        yield format_path(keys), ref


def code_part(code: str, limit: int | None) -> str:
    """The part of Code node source that is analysed: its first ``limit`` characters (all of it for None).
    Workflow loading notes the cut (``Workflow.partial``), which N8D001 reports."""
    return code if limit is None or len(code) <= limit else code[:limit]


def replace_ref(text: str, ref: NodeRef, new_name: str) -> str:
    """Rewrite one reference to point at ``new_name``, keeping its syntax and its quote style."""
    return replace_refs(text, [(ref, new_name)])


def replace_refs(text: str, renames: Iterable[tuple[NodeRef, str]]) -> str:
    """``text`` with each reference rewritten to its new name, in one pass over the text: the work is linear in
    its length and the number of references, however many there are. Where references overlap the first one wins."""
    parts: list[str] = []
    pos = 0
    for ref, new_name in sorted(renames, key=lambda rename: rename[0].start):
        if ref.start >= pos:
            parts += (text[pos : ref.start], _rewritten(text[ref.start : ref.end], ref, new_name))
            pos = ref.end
    parts.append(text[pos:])
    return "".join(parts)


def _rewritten(original: str, ref: NodeRef, new_name: str) -> str:
    """The text of one reference (``original``) pointing at ``new_name`` instead."""
    quote = next((c for c in original if c in "'\"`"), "'")
    if ref.syntax == "$node.":
        if re.fullmatch(r"[A-Za-z_$][\w$]*", new_name):
            replacement = f"$node.{new_name}"
        else:
            replacement = f"$node[{_js_string(new_name, quote)}]"
    elif ref.syntax == "$()":
        replacement = f"$({_js_string(new_name, quote)})"
    elif ref.syntax == "_()":  # Python: the same escapes for ' and " strings
        replacement = f"_({_js_string(new_name, quote)})"
    elif ref.syntax == "$node[]":
        replacement = f"$node[{_js_string(new_name, quote)}]"
    else:  # $items("X", ...) - keep whatever follows the name
        return f"$items({_js_string(new_name, quote)}" + original[-1]
    return replacement


def _js_string(value: str, quote: str = "'") -> str:
    """``value`` as a JavaScript string literal, in ``quote`` when it holds none (a backtick only without ``${``)."""
    if quote == "`" and "`" not in value and "${" not in value:
        return "`" + value.replace("\\", "\\\\") + "`"
    preferred, other = ('"', "'") if quote == '"' else ("'", '"')
    q = other if preferred in value and other not in value else preferred  # the quote that needs no escaping
    return q + value.replace("\\", "\\\\").replace(q, "\\" + q) + q
