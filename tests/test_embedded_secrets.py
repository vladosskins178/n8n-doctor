"""Secrets inside embedded workflows (text or object form) are found and masked like the parent workflow's own."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.executions import render_text, summarize
from n8n_doctor.explain import as_dict, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.report import Style
from n8n_doctor.rules import known_secrets
from n8n_doctor.workflow import from_data

from .conftest import link, node, of, trigger, workflow

HEADER = "Tr0ub4dorQzPlain77"
PASSWORD = "CorrectHorse-Battery9"


def _inner(*nodes: dict[str, Any]) -> dict[str, Any]:
    return workflow([trigger("Inner"), *nodes])


def _http() -> dict[str, Any]:
    entry = {"name": "X-Custom-Auth", "value": HEADER}
    return node("Call", "httpRequest", {"url": "https://x.example.com", "headerParameters": {"parameters": [entry]}}, 4.2)


def _code() -> dict[str, Any]:
    return node("Run", "code", {"jsCode": f'const password = "{PASSWORD}";\nreturn [];'}, 2)


FIELDS = [("executeWorkflow", "workflowJson", 1.2), ("@n8n/n8n-nodes-langchain.toolWorkflow", "workflowJson", 2.2), ("n8n", "workflowObject", 1)]


def _outer(embedded: Any, type_: str = "executeWorkflow", key: str = "workflowJson", version: float = 1.2) -> dict[str, Any]:
    return workflow([trigger(), node("Sub", type_, {"source": "parameter", key: embedded}, version)], link("Start", "Sub"))


def _forms(inner: dict[str, Any]) -> list[Any]:
    return [json.dumps(inner), json.dumps(inner, indent=2), inner, "=" + json.dumps(inner)]


@pytest.mark.parametrize(("type_", "key", "version"), FIELDS, ids=[f[0] for f in FIELDS])
@pytest.mark.parametrize("form", range(4), ids=["text", "indented", "object", "equals"])
@pytest.mark.parametrize(("make", "secret"), [(_http, HEADER), (_code, PASSWORD)], ids=["header", "code"])
def test_secret_of_an_embedded_workflow_is_reported_and_known(type_: str, key: str, version: float, form: int, make: Any, secret: str) -> None:
    data = _outer(_forms(_inner(make()))[form], type_, key, version)
    found = of(data, "N8D101")
    assert len(found) == 1 and found[0].node == "Sub" and found[0].parameter is not None and found[0].parameter.startswith(key + ".nodes[1].parameters.")
    assert secret not in found[0].message
    assert secret in known_secrets(from_data(data, "x.json")[0])


def _client(embedded: Any, message: str) -> Any:
    class Client:
        base = "https://n8n.example.com/api/v1"

        def executions(self, *args: Any, **kwargs: Any) -> Any:
            yield {
                "id": "1",
                "workflowId": "w",
                "startedAt": "t",
                "workflowData": _outer(embedded),
                "data": {"resultData": {"error": {"message": message}, "lastNodeExecuted": "Sub"}},
            }

        def workflow(self, wid: str) -> Any:
            raise AssertionError("the execution carries its workflow")

    return Client()


@pytest.mark.parametrize("as_text", [True, False], ids=["text", "object"])
@pytest.mark.parametrize(("make", "secret"), [(_http, HEADER), (_code, PASSWORD)], ids=["header", "code"])
def test_executions_mask_a_secret_of_an_embedded_workflow(make: Any, secret: str, as_text: bool) -> None:
    inner = _inner(make())
    result = summarize(_client(json.dumps(inner) if as_text else inner, f"rejected value {secret} by the server"), None, 10)
    assert secret not in json.dumps(result) and secret not in render_text(result, Style(False))
    assert result["groups"][0]["example"].startswith("rejected value") and not result["groups"][0]["message_hidden"]


@pytest.mark.parametrize("as_text", [True, False], ids=["text", "object"])
def test_explain_mcp_and_fix_review_mask_it(as_text: bool, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    inner = _inner(_http(), _code())
    data = _outer(json.dumps(inner) if as_text else inner)
    data["nodes"].append(node(f"Named {HEADER}", "set", {"plain": "{{ $json.x }}", "note": PASSWORD}))
    wf = from_data(data, "x.json")[0]
    result = fix_workflow(wf)
    shown = "\n".join([outline(wf), json.dumps(as_dict(wf)), result.diff, *result.changes])
    assert HEADER not in shown and PASSWORD not in shown
    monkeypatch.chdir(tmp_path)
    (tmp_path / "wf.json").write_text(json.dumps(data))
    for tool in ("n8n_lint", "n8n_explain", "n8n_fix"):
        text = mcp.call_tool(tool, {"path": "wf.json"})["content"][0]["text"]
        assert HEADER not in text and PASSWORD not in text


@pytest.mark.parametrize("as_text", [True, False], ids=["text", "object"])
def test_fix_never_edits_the_embedded_workflow(as_text: bool) -> None:
    inner = _inner(_http(), node("Use", "set", {"plain": "{{ $('Inne').item.json.q }}"}))
    embedded = json.dumps(inner) if as_text else inner
    data = _outer(embedded)
    assert of(data, "N8D212") == [] and of(data, "N8D207") == []
    result = fix_workflow(from_data(data, "x.json")[0])
    assert result.fixed["nodes"][1]["parameters"]["workflowJson"] == embedded


def test_a_token_in_the_text_is_reported_once() -> None:
    token = "ghp_" + "a1B2c3D4e5" * 4
    inner = _inner(node("Call", "httpRequest", {"url": "https://x.example.com", "note": token}, 4.2))
    assert len(of(_outer(json.dumps(inner)), "N8D101")) == 1
    assert len(of(_outer(inner), "N8D101")) == 1


def test_embedded_inside_embedded() -> None:
    inner = _inner(_http())
    middle = _inner(node("Sub2", "executeWorkflow", {"source": "parameter", "workflowJson": json.dumps(inner)}, 1.2))
    data = _outer(json.dumps(middle))
    assert len(of(data, "N8D101")) == 1
    assert HEADER in known_secrets(from_data(data, "x.json")[0])


def test_escaped_spellings_in_the_text_are_masked() -> None:
    secret = 'Qx7"Zp2\\Lm9Vb4Nn'  # a quote and a backslash: the embedded text spells them escaped, twice when nested
    entry = {"name": "X-Custom-Auth", "value": secret}
    inner = _inner(node("Call", "httpRequest", {"headerParameters": {"parameters": [entry]}}, 4.2))
    middle = _inner(node("Sub2", "executeWorkflow", {"source": "parameter", "workflowJson": json.dumps(inner)}, 1.2))
    wf = from_data(_outer(json.dumps(middle)), "x.json")[0]
    assert "Zp2" not in json.dumps(as_dict(wf)) and "Zp2" not in outline(wf)


def test_unicode_escaped_spelling_in_the_text_is_masked() -> None:
    text = json.dumps(_inner(_http())).replace(HEADER, "\\u0054" + HEADER[1:])
    data = _outer(text)
    assert len(of(data, "N8D101")) == 1
    wf = from_data(data, "x.json")[0]
    masked = fix_workflow(wf)
    assert HEADER[1:] not in json.dumps(as_dict(wf)) and HEADER[1:] not in masked.diff
    from n8n_doctor.rules import secret_masker

    assert HEADER[1:] not in secret_masker(wf)(text)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps(_inner(_http()))[:-20],  # cut short
        json.dumps({"nodes": "no list", "extra": {"name": "X-Custom-Auth", "value": HEADER}}),
        '{"nodes": [{"parameters": {"headerParameters": {"parameters": [{"value": "' + HEADER + '", "name": "X-Custom-Auth"}]}}}], }',
    ],
    ids=["truncated", "not-a-workflow", "trailing-comma"],
)
def test_text_that_cannot_be_parsed_is_scanned_raw(text: str) -> None:
    data = _outer(text)
    assert len(of(data, "N8D101")) == 1
    assert HEADER in known_secrets(from_data(data, "x.json")[0])


def test_code_in_text_that_cannot_be_parsed_is_scanned_raw() -> None:
    data = _outer(json.dumps(_inner(_code()))[:-20])
    assert len(of(data, "N8D101")) == 1
    assert PASSWORD in known_secrets(from_data(data, "x.json")[0])


def test_a_large_embedded_workflow_is_parsed_past_the_value_limit() -> None:
    filler = node("Fill", "set", {"note": "x" * 600_000})
    data = _outer(json.dumps(_inner(filler, _http(), filler)))
    assert any(f.parameter and f.parameter.endswith("parameters[0].value") for f in of(data, "N8D101"))
    assert HEADER in known_secrets(from_data(data, "x.json")[0])


def test_embedded_workflow_over_a_limit_falls_back_to_the_raw_scan() -> None:
    token = "ghp_" + "a1B2c3D4e5" * 4
    inner = _inner(node("Call", "httpRequest", {"note": token}, 4.2))
    inner["nodes"] = inner["nodes"] * 6000  # over max_nodes for the embedded workflow only
    data = _outer(json.dumps(inner))
    assert any(f.parameter == "workflowJson" and "ghp_" in f.message for f in of(data, "N8D101"))


def test_field_on_another_node_type_is_not_a_workflow() -> None:
    inner = _inner(_code())
    data = workflow([trigger(), node("Set", "set", {"workflowJson": json.dumps(inner)})], link("Start", "Set"))
    assert PASSWORD not in known_secrets(from_data(data, "x.json")[0])


def test_an_expression_in_the_field_is_not_parsed() -> None:
    data = _outer("={{ JSON.stringify($json.workflow) }}")
    assert of(data, "N8D101") == []
