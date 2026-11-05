"""Embedded text that cannot be read as JSON is scanned as text, and that scan finds what reading it would."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.explain import outline
from n8n_doctor.lint import run
from n8n_doctor.rules import known_secrets
from n8n_doctor.workflow import from_data

from .conftest import node, trigger, workflow

SECRET = "Qz7vK2mPx9Lw4Tb"


def _http(*entries: dict[str, Any]) -> dict[str, Any]:
    return node("Call", "httpRequest", {"url": "https://x.example.com", "headerParameters": {"parameters": list(entries)}}, 4.2)


def _outer(text: Any) -> dict[str, Any]:
    return workflow([trigger(), node("Sub", "executeWorkflow", {"source": "parameter", "workflowJson": text}, 1.2)])


def _secrets(text: Any) -> tuple[list[str], list[str]]:
    flow = from_data(_outer(text), "x.json")[0]
    reported = [f.message for f in run([flow]) if f.rule.id == "N8D101" and f.severity.label == "error"]
    return reported, known_secrets(flow)


def _assert_found(text: Any, secret: str = SECRET) -> None:
    reported, known = _secrets(text)
    assert reported, text
    assert secret in known, (secret, known)
    assert secret not in outline(from_data(_outer(text), "x.json")[0])


AUTH = {"name": "Authorization", "value": SECRET}
INNER = workflow([trigger("In"), _http(AUTH), node("Note", "stickyNote", {"content": f"Header to send:\nAuthorization: {SECRET}"})])


def test_pretty_printed_text_that_does_not_parse() -> None:
    text = json.dumps(INNER, indent=2)[:-3]
    with pytest.raises(ValueError):
        json.loads(text)
    _assert_found(text)


@pytest.mark.parametrize("indent", [4, 8, 40])
def test_deep_indents(indent: int) -> None:
    _assert_found(json.dumps(INNER, indent=indent)[:-3])


def test_a_sticky_note_of_the_outer_workflow_repeating_it_is_masked() -> None:
    data = _outer(json.dumps(INNER, indent=2)[:-3])
    data["nodes"].append(node("Mine", "stickyNote", {"content": f"# the key is {SECRET} ok"}))
    flow = from_data(data, "x.json")[0]
    assert SECRET not in outline(flow)
    assert SECRET in known_secrets(flow)


def test_unquoted_expression_breaking_the_parse() -> None:
    text = json.dumps(INNER, indent=2).replace('"name": "Test"', '"name": {{ $json.a }}')
    with pytest.raises(ValueError):
        json.loads(text)
    _assert_found(text)
    compact = json.dumps(INNER).replace('"name": "Test"', '"name": {{ $json.a }}')
    _assert_found(compact)


def test_scan_of_long_whitespace_is_linear() -> None:
    import time

    text = ('"name"' + " " * 500 + ":") * 30_000 + ('"value"' + " " * 500 + ":") * 30_000
    started = time.perf_counter()
    _secrets(text)
    assert time.perf_counter() - started < 20


def _cut(*entries: dict[str, Any]) -> str:
    return json.dumps(workflow([trigger("In"), _http(*entries)]))[:-3]


def test_bearer_with_a_short_token() -> None:
    _assert_found(_cut({"name": "Authorization", "value": "Bearer abc123xy"}), "abc123xy")
    _assert_found('{"headers": {"X": "Bearer abc123xy"}, ', "abc123xy")


def test_bearer_before_a_word_is_prose() -> None:
    assert _secrets('{"note": "Bearer token", ')[0] == []


def test_cookie_entry() -> None:
    _assert_found(_cut({"name": "Cookie", "value": f"sid={SECRET}; lang=en"}))


def test_a_key_between_name_and_value() -> None:
    _assert_found(_cut({"name": "Authorization", "type": "header", "enabled": True, "value": SECRET}))
    _assert_found(_cut({"value": SECRET, "type": "header", "name": "Authorization"}))


def test_escaped_names() -> None:
    _assert_found(_cut(AUTH).replace('"Authorization"', '"\\u0041uthorization"'))
    _assert_found(_cut(AUTH).replace('"name"', '"n\\u0061me"'))


def test_sticky_labels() -> None:
    inner = workflow([trigger("In"), node("Note", "stickyNote", {"content": f"password: {SECRET}\nthanks"})])
    _assert_found(json.dumps(inner)[:-3])


def test_entries_in_text_inside_text() -> None:
    inner = json.dumps(workflow([trigger("In"), _http(AUTH)]))
    middle = workflow([node("Deep", "executeWorkflow", {"source": "parameter", "workflowJson": inner}, 1.2)])
    _assert_found(json.dumps(middle)[:-3])


def test_duplicate_keys_scan_the_earlier_value() -> None:
    other = "Different9Value2Here"
    text = json.dumps(INNER).replace(f'"value": "{SECRET}"', f'"value": "{SECRET}", "value": "{other}"')
    assert json.loads(text)  # it parses: only the last value is kept
    reported, known = _secrets(text)
    assert reported and SECRET in known and other in known


def test_duplicate_password_key() -> None:
    other = "Different9Value2Here"
    inner = workflow([trigger("In"), node("S", "set", {"password": other})])
    text = json.dumps(inner).replace(f'"password": "{other}"', f'"password": "{SECRET}", "password": "{other}"')
    reported, known = _secrets(text)
    assert reported and SECRET in known and other in known


@pytest.mark.parametrize(
    "literal",
    [
        json.dumps(INNER),
        "{name: 'Authorization', value: '" + SECRET + "'}",
        "{'name': 'Authorization', 'value': '" + SECRET + "'}",
    ],
    ids=["json", "bare", "single"],
)
def test_embedded_as_an_expression(literal: str) -> None:
    _assert_found("={{ JSON.stringify(" + literal + ") }}")


def test_an_expression_field_with_no_secret_is_quiet() -> None:
    assert _secrets("={{ $json.workflow }}")[0] == []
    assert _secrets('={{ JSON.stringify({"name": "Authorization", "value": $json.token}) }}')[0] == []
