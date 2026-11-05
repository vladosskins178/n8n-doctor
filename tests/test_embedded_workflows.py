"""Workflows embedded in a parameter (Execute Workflow 'Define below', Tool Workflow, the n8n node) are their own scope."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.fix import fix_workflow
from n8n_doctor.workflow import from_data

from .conftest import link, node, of, trigger, workflow

_INNER = {
    "nodes": [
        {"name": "Inner Start", "type": "n8n-nodes-base.executeWorkflowTrigger", "typeVersion": 1, "position": [0, 0], "parameters": {}},
        {
            "name": "Use",
            "type": "n8n-nodes-base.set",
            "typeVersion": 3.4,
            "position": [200, 0],
            "parameters": {"value": "={{ $('Inner Start').item.json.q }}", "plain": "{{ $('Inner Start').item.json.q }}"},
        },
    ],
    "connections": {"Inner Start": {"main": [[{"node": "Use", "type": "main", "index": 0}]]}},
}


def _outer(type_: str, version: float, key: str, embedded: Any, **params: Any) -> dict[str, Any]:
    sub = node("Sub", type_, {key: embedded, **params}, version)
    return workflow([trigger(), sub, node("Inner Stat", "noOp")], link("Start", "Sub", "Inner Stat"))


_CASES = [
    ("executeWorkflow", 1.2, "workflowJson", {"source": "parameter"}),
    ("@n8n/n8n-nodes-langchain.toolWorkflow", 2.2, "workflowJson", {"source": "parameter"}),
    ("@n8n/n8n-nodes-langchain.toolWorkflow", 1.3, "workflowJson", {"source": "parameter"}),
    ("n8n", 1, "workflowObject", {"operation": "create"}),
]


@pytest.mark.parametrize("as_text", [True, False], ids=["string", "object"])
@pytest.mark.parametrize(("type_", "version", "key", "params"), _CASES, ids=[c[0] for c in _CASES])
def test_embedded_workflow_is_not_linted_or_fixed_as_the_outer_one(type_: str, version: float, key: str, params: dict[str, Any], as_text: bool) -> None:
    embedded = json.dumps(_INNER, indent=2) if as_text else json.loads(json.dumps(_INNER))
    data = _outer(type_, version, key, embedded, **params)
    assert of(data, "N8D212") == [] and of(data, "N8D207") == []
    result = fix_workflow(from_data(data, "x.json")[0])
    assert result.fixed["nodes"][1]["parameters"][key] == embedded
    assert not [c for c in result.changes if "N8D212" in c or "N8D207" in c]


def test_an_expression_in_the_field_is_still_the_outer_workflows() -> None:
    data = _outer("executeWorkflow", 1.2, "workflowJson", "={{ JSON.stringify($('Inner Stt').item.json) }}", source="parameter")
    assert [f.rule.id for f in of(data, "N8D207")] == ["N8D207"]
