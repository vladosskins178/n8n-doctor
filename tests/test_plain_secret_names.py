"""Plain parameters named for a secret, entries named pass/passphrase/cookie, and label-style secrets in sticky notes."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.explain import as_dict, outline
from n8n_doctor.rules import known_secrets
from n8n_doctor.workflow import from_data

from .conftest import link, node, of, trigger, workflow

GENERATED = "aZ3kP9qL2xV7mN4t"
NAMES = ["token", "pwd", "pass", "refreshToken", "botToken", "sessionToken", "x-api-key", "passphrase", "encryptionKey", "licenseKey", "cookie"]


def _set(params: dict[str, Any], type_: str = "set") -> dict[str, Any]:
    return workflow([trigger(), node("S", type_, params)], link("Start", "S"))


def _known(data: dict[str, Any]) -> list[str]:
    return known_secrets(from_data(data, "x.json")[0])


@pytest.mark.parametrize("name", NAMES)
def test_plain_parameter_with_a_generated_value(name: str) -> None:
    data = _set({"options": {name: GENERATED}})
    assert len(of(data, "N8D101")) == 1 and GENERATED in _known(data)


@pytest.mark.parametrize("name", NAMES)
def test_plain_parameter_with_a_generated_value_in_a_literal_expression(name: str) -> None:
    assert GENERATED in _known(_set({name: "={{ '" + GENERATED + "' }}"}))


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("value", ["next", "yes", "/home/app/data", "user@example.com", "={{ $json.token }}", "$API_TOKEN", "true-or-false"])
def test_plain_parameter_with_an_ordinary_value(name: str, value: str) -> None:
    data = _set({name: value})
    assert of(data, "N8D101") == [] and value not in _known(data)


@pytest.mark.parametrize("name", ["pageToken", "nextToken", "bypass", "compass", "tokenizer", "cookieName", "passes"])
def test_other_names_are_not_secret_names(name: str) -> None:
    assert of(_set({name: GENERATED}), "N8D101") == []


@pytest.mark.parametrize("name", ["pass", "PASS", "passphrase", "Passphrase", "cookie", "Cookie"])
def test_name_value_entry(name: str) -> None:
    data = _set({"headerParameters": {"parameters": [{"name": name, "value": GENERATED}]}}, "httpRequest")
    assert len(of(data, "N8D101")) == 1 and GENERATED in _known(data)


@pytest.mark.parametrize("name", ["pass", "passphrase"])
def test_entry_with_a_plain_password(name: str) -> None:
    data = _set({"parameters": [{"name": name, "value": "hunter2hunter"}]}, "httpRequest")
    assert len(of(data, "N8D101")) == 1


def test_cookie_entry_with_several_pairs() -> None:
    data = _set({"parameters": [{"name": "Cookie", "value": f"theme=dark; sid={GENERATED}; lang=en"}]}, "httpRequest")
    assert len(of(data, "N8D101")) == 1
    known = _known(data)
    assert GENERATED in known


@pytest.mark.parametrize("value", ["theme=dark", "lang=en-US; theme=dark"])
def test_cookie_entry_without_a_generated_value_is_not_reported(value: str) -> None:
    assert of(_set({"parameters": [{"name": "Cookie", "value": value}]}, "httpRequest"), "N8D101") == []


def _note(text: str) -> dict[str, Any]:
    return workflow([trigger(), node("Note", "stickyNote", {"content": text})])


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("password: hunter2", "hunter2"),
        ("Login\nPassword = hunter2\nThanks", "hunter2"),
        ("**password:** `hunter2`", "hunter2"),
        ("user: admin, password: hunter2, host: db", "hunter2"),
        ("pwd: hunter2.", "hunter2"),
        ("Passphrase: swordfish", "swordfish"),
        ("API key: abc123def", "abc123def"),
        ("token = abc123def (prod)", "abc123def"),
    ],
)
def test_label_in_a_sticky_note(text: str, secret: str) -> None:
    data = _note(text)
    found = of(data, "N8D101")
    assert len(found) == 1 and secret not in found[0].message
    wf = from_data(data, "x.json")[0]
    assert secret in known_secrets(wf)
    assert secret not in outline(wf) and secret not in json.dumps(as_dict(wf))


@pytest.mark.parametrize(
    "text",
    [
        "The password: see the vault",
        "password: required",
        "Password: none",
        "token: your_token_here",
        "password: <your-password>",
        "api key: {{ $env.KEY }}",
        "secret: $API_SECRET",
        "Set the password in the credential.",
        "password:\nnext line",
        "pass: n/a",
        "compass: north123",
    ],
)
def test_prose_in_a_sticky_note_is_left_alone(text: str) -> None:
    assert of(_note(text), "N8D101") == []


def test_label_in_another_field_is_not_a_label() -> None:
    assert of(_set({"text": "password: hunter2"}), "N8D101") == []
