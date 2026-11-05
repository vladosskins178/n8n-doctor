"""Odd values in every field the rules read: no command may raise on any of them."""

from __future__ import annotations

import copy
import itertools
import json
import math
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.cli import main
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import labels, run
from n8n_doctor.report import Style, render_github, render_json, render_sarif, render_text
from n8n_doctor.rules import RULES
from n8n_doctor.workflow import from_data

from .conftest import node, trigger, workflow

ODD: list[Any] = [
    math.inf,
    -math.inf,
    math.nan,
    1e308,
    -1,
    0,
    10**30,
    10**400,  # a 400-digit number: too large for a float
    -(10**400),
    2.5,
    "²",
    "٣",
    "1" * 5000,
    "*/" + "9" * 5000,
    "\ud800 lone",
    "",
    "=",
    "={{ $json.x }}",
    None,
    True,
    False,
    [],
    [[1]],
    {"a": {}},
]

TEMPLATES: list[dict[str, Any]] = [
    node("Hook", "webhook", {"path": "p", "httpMethod": "POST", "authentication": "none", "responseMode": "responseNode", "options": {}}, 2),
    node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", {"public": True, "authentication": "none"}, 1.1),
    node("Mcp", "@n8n/n8n-nodes-langchain.mcpTrigger", {"authentication": "none", "path": "m"}, 1),
    node("Wait", "wait", {"resume": "timeInterval", "amount": 5, "unit": "seconds", "limitWaitTime": False, "options": {"limitWaitTime": True}}, 1.1),
    node("WaitHook", "wait", {"resume": "webhook", "incomingAuthentication": "none"}, 1.1),
    node(
        "Http",
        "httpRequest",
        {
            "url": "https://a.example/x?token=abc",
            "method": "POST",
            "authentication": "genericCredentialType",
            "genericAuthType": "httpHeaderAuth",
            "nodeCredentialType": "x",
            "options": {"timeout": 0, "allowUnauthorizedCerts": True},
            "jsonBody": '{"password": "hunter2hunter2"}',
            "headerParameters": {"parameters": [{"name": "Authorization", "value": "Bearer abcdefghijklmnopqrstuvwxyz"}]},
        },
        4.2,
    ),
    node("If2", "if", {"conditions": {"conditions": [{"leftValue": "a", "rightValue": "b", "operator": {"singleValue": False}}]}}, 2),
    node("If1", "if", {"conditions": {"string": [{"value1": "a", "value2": "b"}], "number": [{"value1": 1}]}}, 1),
    node("Filter", "filter", {"conditions": {"conditions": [{"leftValue": "={{ $json.a }}"}]}}, 2),
    node(
        "Sw3",
        "switch",
        {
            "mode": "rules",
            "numberOutputs": 4,
            "rules": {"values": [{"outputKey": "k", "renameOutput": True, "conditions": {"conditions": [{"leftValue": "a"}]}}]},
            "options": {"fallbackOutput": "extra", "renameFallbackOutput": "fb"},
        },
        3,
    ),
    node("Sw2", "switch", {"mode": "expression", "outputsAmount": 3, "rules": {"rules": [{"output": 1, "outputKey": "o"}]}}, 2),
    node("Sw1", "switch", {"mode": "rules", "rules": {"rules": [{"output": 2}]}, "fallbackOutput": 3}, 1),
    node("Loop", "splitInBatches", {"batchSize": 10}, 3),
    node(
        "Sched",
        "scheduleTrigger",
        {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}, {"field": "cronExpression", "expression": "*/5 * * * *"}]}},
        1.2,
    ),
    node(
        "Cron",
        "cron",
        {"triggerTimes": {"item": [{"mode": "everyX", "value": 2, "unit": "minutes"}, {"mode": "custom", "cronExpression": "0 */2 * * * *"}]}},
        1,
    ),
    node("Every", "interval", {"interval": 30, "unit": "seconds"}, 1),
    node("Code", "code", {"jsCode": 'const apiKey = "Q1w2E3r4T5y6U7i8";\nreturn $("Gone").all();', "language": "javaScript", "mode": "runOnceForEachItem"}, 2),
    node("Py", "code", {"pythonCode": "return []", "language": "python"}, 2),
    node("Func", "function", {"functionCode": "return items;"}, 1),
    node("Sub", "executeWorkflow", {"source": "database", "workflowId": {"value": "", "cachedResultName": "x"}, "workflowJson": "", "workflowPath": ""}, 1),
    node("Reply", "respondToWebhook", {"respondWith": "json"}, 1.1),
    node("Set", "set", {"assignments": {"assignments": [{"name": "a", "value": "={{ $json.a }}"}]}, "fields": {"values": []}}, 3.4),
    node("Note", "stickyNote", {"content": "n8n-doctor-disable N8D302"}),
    node(
        "Raw",
        "httpRequest",
        {"url": "https://a.example"},
        4.2,
        disabled=False,
        notes="n8n-doctor-disable",
        onError="continueErrorOutput",
        retryOnFail=False,
        continueOnFail=False,
        credentials={"httpHeaderAuth": {"id": "", "name": "c"}},
    ),
]


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Every key path inside ``value`` (containers included), so each field can be replaced."""
    out: list[tuple[Any, ...]] = []
    items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    for key, child in items:
        out.append((*prefix, key))
        out += _paths(child, (*prefix, key))
    return out


def _replaced(value: Any, path: tuple[Any, ...], new: Any) -> Any:
    out = copy.deepcopy(value)
    target = out
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = new
    return out


def _odd_workflow(odd: Any) -> dict[str, Any]:
    """Every template node, and one copy of it per field with that field set to ``odd``, all connected."""
    nodes: list[dict[str, Any]] = [trigger()]
    for template in TEMPLATES:
        nodes.append(template)
        for path in _paths(template):
            if path[0] in ("name", "position") or (path[0] == "type" and isinstance(odd, str) and len(odd) > 1000):
                continue  # names and long types are checked when the file is loaded (see test_shapes)
            changed = _replaced(template, path, odd)
            changed["name"] = f"{template['name']} {'.'.join(map(str, path))}"
            nodes.append(changed)
    names = [n["name"] for n in nodes]
    conns: dict[str, Any] = {}
    for a, b in itertools.pairwise(names):
        conns[a] = {"main": [[{"node": b, "type": "main", "index": 0}], [{"node": names[0], "type": "main", "index": odd}]]}
    conns["Gone"] = {"main": [[{"node": names[1], "type": odd, "index": 0}]]}
    return workflow(
        nodes,
        conns,
        name=odd if isinstance(odd, str) and len(odd) < 1000 else "Odd",  # longer names are refused (see test_shapes)
        id=odd if isinstance(odd, (int, float)) or (isinstance(odd, str) and len(odd) < 1000) else "7",
        active=odd,
        settings={"errorWorkflow": odd, "timezone": odd, "executionTimeout": odd, "saveDataErrorExecution": odd},
        pinData={names[1]: odd, "Gone": [odd]},
    )


@pytest.mark.parametrize("odd", ODD, ids=lambda v: repr(v)[:16])
def test_odd_values_in_every_field_never_raise(odd: Any) -> None:
    flows = from_data(_odd_workflow(odd), "odd.json")
    found = run(flows)
    rules = [r.meta for r in RULES]
    for text in (
        render_text(found, labels(flows), Style(True), verbose=True),
        render_json(found, labels(flows)),
        render_sarif(found, rules),
        render_github(found),
        outline(flows[0]),
        outline(flows[0], unicode=False),
        mermaid(flows[0]),
        json.dumps(as_dict(flows[0])),
    ):
        text.encode("utf-8")  # lone surrogates are escaped or replaced in every output
    result = fix_workflow(flows[0])
    (result.diff + "".join(result.changes)).encode("utf-8")
    json.dumps(result.patch)


@pytest.mark.parametrize("odd", ODD, ids=lambda v: repr(v)[:16])
def test_odd_values_through_the_command_line(odd: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "odd.json"
    path.write_text(json.dumps(_odd_workflow(odd)), encoding="utf-8", errors="surrogatepass")
    commands = [["lint", "-f", f] for f in ("text", "json", "sarif", "github")]
    commands += [["explain", "-f", f] for f in ("text", "json", "mermaid")] + [["fix"], ["fix", "-f", "json"]]
    for command in commands:
        code = main([*command, "--no-config", str(path)])
        out, err = capsys.readouterr()
        assert code in (0, 1) and "internal error" not in err, (command, err)
        if command[-1] in ("json", "sarif"):
            json.loads(out)


@pytest.mark.parametrize("value", [10**400, -(10**400), 1e308, -math.inf, math.nan, 10**13], ids=lambda v: repr(v)[:12])
def test_numbers_beyond_any_use_are_reported(value: Any) -> None:
    nodes = [trigger(), node("Wait", "wait", {"resume": "timeInterval", "amount": value, "unit": "weeks"}, value)]
    flows = from_data(workflow(nodes, {"Start": {"main": [[{"node": "Wait", "type": "main", "index": 0}]]}}), "n.json")
    found = {f.rule.id: f.message for f in run(flows)}
    assert flows[0].nodes[1].type_version == 1  # read as version 1
    assert "typeVersion" in found["N8D213"]
    assert found["N8D214"].startswith("the amount is")
