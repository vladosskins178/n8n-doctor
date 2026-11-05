"""What n8n-doctor knows about specific node types: outputs, schedules, short summaries."""

from __future__ import annotations

import itertools
import math
import re
from collections.abc import Callable
from typing import Any

from .workflow import Node, bounded_number

BASE = "n8n-nodes-base."
HTTP = BASE + "httpRequest"
WEBHOOK = BASE + "webhook"
FORM_TRIGGER = BASE + "formTrigger"
RESPOND = BASE + "respondToWebhook"
CODE = BASE + "code"
FUNCTION = BASE + "function"
FUNCTION_ITEM = BASE + "functionItem"
IF = BASE + "if"
SWITCH = BASE + "switch"
FILTER = BASE + "filter"
SPLIT_IN_BATCHES = BASE + "splitInBatches"
WAIT = BASE + "wait"
SCHEDULE = BASE + "scheduleTrigger"
CRON = BASE + "cron"
INTERVAL = BASE + "interval"
ERROR_TRIGGER = BASE + "errorTrigger"
MANUAL_TRIGGER = BASE + "manualTrigger"
EXECUTE_WORKFLOW = BASE + "executeWorkflow"
EXECUTE_WORKFLOW_TRIGGER = BASE + "executeWorkflowTrigger"
MERGE = BASE + "merge"
COMPARE = BASE + "compareDatasets"

LANGCHAIN = "@n8n/n8n-nodes-langchain."
SINGLE_OUTPUT_AI: set[str] = set()
MULTI_OUTPUT_AI = {"textClassifier", "sentimentAnalysis", "guardrails"}

# Nodes whose job is to decide whether items continue; a cycle through one of them can end.
CONDITIONAL = {IF, SWITCH, FILTER, SPLIT_IN_BATCHES, BASE + "removeDuplicates", BASE + "limit"}

_INTERVAL_DEFAULTS = {"seconds": 30, "minutes": 5}
_UNITS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400, "weeks": 604800, "months": 2419200}


def p(node: Node, *keys: str, default: Any = None) -> Any:
    """``p(node, "options", "timeout")`` -> ``node.parameters["options"]["timeout"]`` or ``default``."""
    value: Any = node.parameters
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def on_error_output(node: Node) -> bool:
    return node.raw.get("onError") == "continueErrorOutput"


def _switch_labels(node: Node) -> list[str]:
    v = node.type_version
    if v >= 3 and p(node, "mode") == "expression":
        n = p(node, "numberOutputs", default=4)
        count = n if isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 64 else 4
        return [str(i) for i in range(count)]
    if v >= 3:
        values = p(node, "rules", "values", default=[])
        values = values if isinstance(values, list) else []
        labels = []
        for i, rule in enumerate(values):
            key = rule.get("outputKey") if isinstance(rule, dict) and rule.get("renameOutput") else None
            labels.append(str(key) if key else str(i))
        if p(node, "options", "fallbackOutput") == "extra":
            renamed = p(node, "options", "renameFallbackOutput")
            labels.append(str(renamed) if renamed else "fallback")
        return labels or ["0"]
    if v >= 2:
        if p(node, "mode", default="rules") == "expression":
            n = p(node, "outputsAmount", default=4)
            count = n if isinstance(n, int) and not isinstance(n, bool) and 0 < n <= 64 else 4
            return [str(i) for i in range(count)]
        rules = p(node, "rules", "rules", default=[])
        rules = rules if isinstance(rules, list) else []
        labels = []
        for i, rule in enumerate(rules):
            key = rule.get("outputKey") if isinstance(rule, dict) else None
            labels.append(str(key) if isinstance(key, (str, int)) and str(key) else str(i))
        return labels or ["0"]
    return [str(i) for i in range(4)]  # Switch v1 always has four outputs


def switch_routed_outputs(node: Node) -> set[int] | None:
    """For Switch v1 (always four outputs): the outputs some rule or the fallback sends items to. None for other versions."""
    if node.type != SWITCH or node.type_version >= 2 or p(node, "mode", default="rules") != "rules":
        return None
    used: set[int] = set()
    rules = p(node, "rules", "rules", default=[])
    for rule in rules if isinstance(rules, list) else []:
        out = rule.get("output", 0) if isinstance(rule, dict) else 0
        if isinstance(out, int) and not isinstance(out, bool) and 0 <= out < 4:
            used.add(out)
    fallback = p(node, "fallbackOutput", default=-1)
    if isinstance(fallback, int) and not isinstance(fallback, bool) and 0 <= fallback < 4:
        used.add(fallback)
    return used


def output_labels(node: Node) -> list[str]:
    """One label per main output, in order. ``""`` for a plain single output.

    Computed once per node (rules and outputs ask many times); callers must not change the list.
    """
    labels: list[str] | None = node.cache.get("labels")
    if labels is None:
        labels = node.cache["labels"] = _output_labels(node)
    return labels


def _output_labels(node: Node) -> list[str]:
    t = node.type
    if t == IF:
        labels = ["true", "false"]
    elif t == SWITCH:
        labels = _switch_labels(node)
    elif t == FILTER:
        # Both versions return [kept, discarded] on one declared output. n8n adds its error output after the declared ones,
        # so there the second output is the error output.
        return ["kept", "error"] if on_error_output(node) else ["kept", "discarded"]
    elif t == SPLIT_IN_BATCHES:
        labels = ["done", "loop"] if node.type_version >= 3 else [""]
    elif t == COMPARE:
        labels = ["in A only", "same", "different", "in B only"]
    elif t == BASE + "stopAndError":
        labels = []
    elif t.startswith(LANGCHAIN) and node.short_type in MULTI_OUTPUT_AI:
        labels = [""]  # outputs depend on settings n8n-doctor does not model; is_dynamic_outputs() is True
    else:
        labels = [""]
    if on_error_output(node):
        labels = ["success", "error"] if labels == [""] else [*labels, "error"]
    return labels


def output_count(node: Node) -> int:
    return len(output_labels(node))


def is_dynamic_outputs(node: Node) -> bool:
    """True when the number of outputs cannot be read reliably from the parameters."""
    if node.type == SWITCH:
        key = "numberOutputs" if node.type_version >= 3 else "outputsAmount"
        return p(node, "mode") == "expression" and key in node.parameters and not isinstance(p(node, key), int)
    if node.type.startswith(BASE) or node.type in SINGLE_OUTPUT_AI:
        return False
    return not node.type.startswith(LANGCHAIN) or node.short_type in MULTI_OUTPUT_AI


# --- schedules -------------------------------------------------------------------------------


_WHOLE = re.compile(r"[ \t]*([0-9]{1,9})[ \t]*")  # ASCII digits only ("²" and "٣" are digits to str.isdigit), and short


def _int(value: Any) -> int | None:
    """A whole number written as a JSON number or as plain digits; None for anything else (``True``, ``1.5``,
    ``inf``, ``"²"``, a 5,000-digit string)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer() and abs(value) < 1e15:
        return int(value)
    if isinstance(value, str) and (m := _WHOLE.fullmatch(value)):
        return int(m.group(1))
    return None


# cron fields as n8n-doctor reads them: ASCII digits, at most 9 of them (a longer number is not a valid cron value)
_CRON_STEP = re.compile(r"(?:\*|[0-9]{1,9}(?:-[0-9]{1,9})?)/([0-9]{1,9})")
_CRON_LIST = re.compile(r"[0-9]{1,9}(?:,[0-9]{1,9})+")
_CRON_NUMBER = re.compile(r"[0-9]{1,9}")
_CRON_ANY_STEP = re.compile(r"/([^,\s]*)")


def _cron_min_interval(expr: str) -> int | None:
    """Smallest gap in seconds between runs of a cron expression, for the simple cases.

    Handles 5 fields (minute first) and 6 fields (second first). Returns None when the
    expression is not plain enough to judge, which makes the caller skip it.
    """
    fields = expr.split()
    if len(fields) == 5:
        fields = ["0", *fields]
    if len(fields) != 6:
        return None
    sec, minute = fields[0], fields[1]

    def step(field: str, unit: int, span: int) -> int | None:
        if field == "*":
            return unit
        m = _CRON_STEP.fullmatch(field)
        if m:
            n = int(m.group(1))
            return unit * n if n > 0 else None
        if _CRON_LIST.fullmatch(field):
            values = sorted(int(v) for v in field.split(","))
            gaps = [b - a for a, b in itertools.pairwise(values)] + [span - values[-1] + values[0]]
            return unit * min(gaps)
        return None

    s = step(sec, 1, 60)
    if s is not None:
        return s
    if not _CRON_NUMBER.fullmatch(sec):
        return None
    m = step(minute, 60, 60)
    if m is not None:
        return m
    return None


def schedule_interval(node: Node) -> int | None:
    """Shortest time in seconds between two runs of a Schedule/Cron/Interval trigger, if known."""
    found: list[int] = []
    if node.type == SCHEDULE:
        rules = p(node, "rule", "interval", default=[])
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict):
                continue
            field = rule.get("field", "days")
            if not isinstance(field, str):
                continue
            if field == "cronExpression":
                expr = rule.get("expression")
                if isinstance(expr, str) and not expr.startswith("="):
                    gap = _cron_min_interval(expr.strip())
                    if gap:
                        found.append(gap)
                continue
            if field not in _UNITS:
                continue
            key = f"{field}Interval"
            n = _int(rule.get(key, _INTERVAL_DEFAULTS.get(field, 1)))  # n8n leaves defaults out of exports
            if n is not None and n > 0:
                found.append(n * _UNITS[field])
    elif node.type == CRON:
        items = p(node, "triggerTimes", "item", default=[])
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            mode = item.get("mode")
            if mode == "everyMinute":
                found.append(60)
            elif mode == "everyHour":
                found.append(3600)
            elif mode == "everyX":
                n = _int(item.get("value", 2))
                unit = item.get("unit", "hours")
                if n and isinstance(unit, str) and unit in ("minutes", "hours"):
                    found.append(n * _UNITS[unit])
            elif mode == "custom":
                expr = item.get("cronExpression")
                if isinstance(expr, str):
                    gap = _cron_min_interval(expr.strip())
                    if gap:
                        found.append(gap)
    elif node.type == INTERVAL:
        n = _int(p(node, "interval", default=1))
        unit = p(node, "unit", default="seconds")
        if n and isinstance(unit, str) and unit in _UNITS:
            found.append(n * _UNITS[unit])
    return min(found) if found else None


def wait_seconds(node: Node) -> int | None:
    """Fixed duration of a Wait node in ``timeInterval`` mode, if it is a literal."""
    if node.type != WAIT:
        return None
    resume = p(node, "resume", default="timeInterval")
    if resume != "timeInterval":
        return None
    amount = p(node, "amount", default=1 if node.type_version < 1.1 else 5)
    unit = p(node, "unit", default="hours" if node.type_version < 1.1 else "seconds")
    if bounded_number(amount) is None or not isinstance(unit, str) or unit not in _UNITS:
        return None  # 10**400 weeks, NaN: see invalid_time_values
    seconds = amount * _UNITS[unit]
    if not math.isfinite(seconds) or seconds < 0:  # 1e308 weeks, NaN: see invalid_time_values
        return None
    return int(seconds)


def _whole_problem(value: Any) -> str | None:
    """Why ``value`` is not a positive whole number n8n can use as an interval, or None when it is one (or an expression)."""
    if isinstance(value, str) and value.startswith("="):
        return None
    n = _int(value)
    if n is not None:
        return None if n > 0 else f"is {n}, not a positive number"
    if isinstance(value, float) and not math.isfinite(value):
        return f"is {value}, not a finite number"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "is not a whole number" if math.isfinite(value) and value > 0 else "is not a positive number"
    return f"is {_kind(value)}, not a whole number"


def _kind(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return "text that is not a whole number" if len(value) > 20 else f'"{value}"'
    return "an object" if isinstance(value, dict) else "an array" if isinstance(value, list) else "not a number"


def _cron_problem(expr: Any) -> str | None:
    """Why a cron expression has a step n8n cannot use (``*/0``, ``*/x``, a 5,000-digit step), or None."""
    if not isinstance(expr, str) or expr.startswith("="):
        return None
    for field in expr.split()[:7]:
        for m in _CRON_ANY_STEP.finditer(field):
            step = m.group(1)
            if not _CRON_NUMBER.fullmatch(step):
                from .rules import shorten  # rules imports this module

                return f"has the step /{shorten(step, 20)}, not a whole number"
            if int(step) == 0:
                return "has the step /0"
    return None


def invalid_time_values(node: Node) -> list[tuple[str, str]]:
    """(parameter path, what is wrong) for the time values of a Schedule, Cron, Interval or Wait node that
    n8n cannot use: zero, negative, infinite, not a number, or digits n8n-doctor does not read as a number."""
    out: list[tuple[str, str]] = []
    if node.type == SCHEDULE:
        rules = p(node, "rule", "interval", default=[])
        for i, rule in enumerate(rules if isinstance(rules, list) else []):
            if not isinstance(rule, dict) or not isinstance(rule.get("field", "days"), str):
                continue
            field = rule.get("field", "days")
            if field == "cronExpression" and (why := _cron_problem(rule.get("expression"))):
                out.append((f"rule.interval[{i}].expression", f"the cron expression {why}"))
            key = f"{field}Interval"
            if field in _UNITS and key in rule and (why := _whole_problem(rule[key])):
                out.append((f"rule.interval[{i}].{key}", f"the interval {why}"))
    elif node.type == CRON:
        items = p(node, "triggerTimes", "item", default=[])
        for i, item in enumerate(items if isinstance(items, list) else []):
            if not isinstance(item, dict):
                continue
            if item.get("mode") == "everyX" and "value" in item and (why := _whole_problem(item["value"])):
                out.append((f"triggerTimes.item[{i}].value", f"the interval {why}"))
            if item.get("mode") == "custom" and (why := _cron_problem(item.get("cronExpression"))):
                out.append((f"triggerTimes.item[{i}].cronExpression", f"the cron expression {why}"))
    elif node.type == INTERVAL:
        if "interval" in node.parameters and (why := _whole_problem(node.parameters["interval"])):
            out.append(("interval", f"the interval {why}"))
    elif node.type == WAIT and p(node, "resume", default="timeInterval") == "timeInterval":
        amount = node.parameters.get("amount")
        if isinstance(amount, float) and not math.isfinite(amount):
            out.append(("amount", f"the amount is {amount}, not a finite number"))
        elif isinstance(amount, (int, float)) and not isinstance(amount, bool):
            if amount < 0:
                out.append(("amount", "the amount is negative"))
            elif bounded_number(amount) is None or not math.isfinite(amount * _UNITS.get(str(p(node, "unit", default="seconds")), 1)):
                out.append(("amount", "the amount is too large to be a time"))
    return out


def human_seconds(seconds: int) -> str:
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size and seconds % size == 0:
            n = seconds // size
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


# --- summaries for explain -------------------------------------------------------------------


Show = Callable[[str], str]


def _redact(text: str) -> str:
    from .rules import redact  # rules imports this module

    return redact(text)


def _as_is(text: str) -> str:
    return text


def _short(value: Any, show: Show = _redact, limit: int = 60) -> str:
    """A parameter value for a summary: passed through ``show`` (which masks secrets) before it is shortened,
    so a cut cannot leave part of a secret that masking would no longer recognise."""
    text = show(str(value))
    if text.startswith("="):
        text = text[1:]
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _public_url(url: str) -> str:
    """Drop the user:password part and the query string, which is where URLs usually carry secrets."""
    url = re.sub(r"(://)[^/@\s]{1,256}@", r"\1***@", url)
    return re.sub(r"\?.*", "?...", url, flags=re.DOTALL)


HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"})


def method_name(value: Any) -> str:
    """An HTTP method as reports show it: upper case when it is one, otherwise the text unchanged (a secret
    pasted into the field must keep its case, or masking, which matches exact text, would miss it)."""
    text = str(value)
    return text.upper() if text.upper() in HTTP_METHODS else text


def http_method(node: Node) -> str:
    method = p(node, "method") or p(node, "requestMethod")
    if isinstance(method, str) and method.startswith("="):
        return "(method from an expression)"
    return method_name(method) if isinstance(method, str) and method else "GET"


def webhook_methods(node: Node) -> str:
    methods = p(node, "httpMethod", default="GET")
    return "/".join(method_name(m) for m in methods) if isinstance(methods, list) else method_name(methods)


_LINE_BREAKS = ("\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def _line_count(text: str) -> int:
    """``len(text.splitlines())`` without building the list (a Code node can have millions of lines)."""
    if not text:
        return 0
    breaks = sum(text.count(c) for c in _LINE_BREAKS) + text.count("\r") - text.count("\r\n")
    return breaks + (not text.endswith((*_LINE_BREAKS, "\r")))


def describe(node: Node, show: Show = _redact) -> str:
    """A one-line summary of ``node``. Every parameter value it quotes is passed through ``show`` first
    (explain passes the workflow's secret masker; by default the N8D101 patterns are masked)."""
    t = node.type
    if t == WEBHOOK:
        auth = p(node, "authentication", default="none")
        mode = p(node, "responseMode", default="onReceived")
        reply = {
            "onReceived": "replies immediately",
            "lastNode": "replies with the last node's data",
            "responseNode": "replies from a Respond to Webhook node",
        }
        reply_text = reply.get(mode, mode) if isinstance(mode, str) else mode
        return f"{_short(webhook_methods(node), show)} /{_short(p(node, 'path', default=''), show)}, auth: {_short(auth, show)}, {_short(reply_text, show)}"
    if t in (SCHEDULE, CRON, INTERVAL):
        gap = schedule_interval(node)
        return f"runs every {human_seconds(gap)}" if gap else "scheduled"
    if t == HTTP:
        return f"{_short(http_method(node), show)} {_short(_public_url(show(str(p(node, 'url', default='?')))), _as_is)}"
    if t in (CODE, FUNCTION, FUNCTION_ITEM):
        lang = p(node, "language", default="javaScript")
        lang = {"javaScript": "JavaScript", "python": "Python", "pythonNative": "Python"}.get(lang) if isinstance(lang, str) else None
        lang = lang or _short(p(node, "language"), show)
        src = p(node, "pythonCode" if lang == "Python" else "jsCode") if t == CODE else p(node, "functionCode")
        n_lines = _line_count(src) if isinstance(src, str) else 0
        mode = {"runOnceForEachItem": "once per item", "runOnceForAllItems": "once for all items"}.get(str(p(node, "mode")), "once for all items")
        if t == FUNCTION_ITEM:
            mode = "once per item"
        return f"{lang}, {mode}, {n_lines} line{'s' if n_lines != 1 else ''}"
    if t == IF:
        conds = p(node, "conditions", "conditions")
        if isinstance(conds, list):
            return f"{len(conds)} condition{'s' if len(conds) != 1 else ''}"
        return ""
    if t == SWITCH:
        return f"{output_count(node) - (1 if on_error_output(node) else 0)} outputs"
    if t == SPLIT_IN_BATCHES:
        size = p(node, "batchSize", default=1 if node.type_version >= 3 else 10)
        return f"batches of {_short(size, show)}"
    if t == WAIT:
        resume = p(node, "resume", default="timeInterval")
        secs = wait_seconds(node)
        if secs is not None:
            return f"waits {human_seconds(secs)}"
        known = {"webhook": "waits for a call to its resume URL", "form": "waits for a form submission", "specificTime": "waits until a set time"}
        return known.get(resume, "") if isinstance(resume, str) and resume in known else _short(resume, show)
    if t == EXECUTE_WORKFLOW:
        wid = p(node, "workflowId")
        if isinstance(wid, dict):
            wid = wid.get("cachedResultName") or wid.get("value")
        return f"runs workflow {_short(wid, show)}" if wid else "runs a sub-workflow"
    if t == RESPOND:
        return f"responds with {_short(p(node, 'respondWith', default='firstIncomingItem'), show)}"
    if t == BASE + "set":
        fields = p(node, "assignments", "assignments") or p(node, "fields", "values")
        return f"sets {len(fields)} field{'s' if len(fields) != 1 else ''}" if isinstance(fields, list) else ""
    if node.raw.get("credentials"):
        op = p(node, "operation")
        res = p(node, "resource")
        return " ".join(_short(x, show) for x in (res, op) if isinstance(x, str))
    return ""
