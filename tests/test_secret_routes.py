"""More places a secret sits: a node's notes, query entries, shell commands, object literals in expressions, token prefixes."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from n8n_doctor.explain import outline
from n8n_doctor.lint import run
from n8n_doctor.rules import known_secrets, redact, secret_masker
from n8n_doctor.workflow import from_data

from .conftest import link, node, trigger, workflow

KEY = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iLxYz"


def _hex(seed: str, size: int) -> str:
    return (hashlib.sha256(seed.encode()).hexdigest() * 4)[:size]


def _mixed(seed: str, size: int) -> str:
    return "".join(c.upper() if i % 3 == 0 else c for i, c in enumerate(_hex(seed, size)))


def _found(*nodes: dict[str, Any]) -> list[str]:
    wf = from_data(workflow([trigger(), *nodes], link("Start", nodes[0]["name"])), "x.json")[0]
    return [f.message for f in run([wf]) if f.rule.id == "N8D101"]


def _http(**params: Any) -> dict[str, Any]:
    return node("H", "httpRequest", {"url": "https://a.example.com", **params}, 4.2)


def _entries(field: str, flag: str, name: str, value: str) -> dict[str, Any]:
    return _http(**{flag: True, field: {"parameters": [{"name": name, "value": value}]}})


def test_the_notes_of_a_node_are_scanned_and_masked() -> None:
    for notes, secret in [("password: hunter22", "hunter22"), (f"OPENAI_API_KEY={KEY}", KEY), ("token ghp_" + "a1B2" * 9, "ghp_" + "a1B2" * 9)]:
        raw = {**node("S", "set", {}), "notes": notes}
        wf = from_data(workflow([trigger(), raw], link("Start", "S")), "x.json")[0]
        found = [f for f in run([wf]) if f.rule.id == "N8D101"]
        assert found and found[0].parameter == "notes" and found[0].node == "S", notes
        assert secret in known_secrets(wf)
    assert not _found({**node("S", "set", {}), "notes": "Sends the password reset mail"})


def test_the_notes_of_an_embedded_node_are_scanned() -> None:
    inner = {**node("I", "set", {}), "notes": "password: hunter22"}
    assert _found(node("E", "executeWorkflow", {"workflowJson": workflow([inner])}))


@pytest.mark.parametrize("name", ["hapikey", "appid", "sig", "signature"])
def test_query_entries_named_for_a_key(name: str) -> None:
    assert _found(_entries("queryParameters", "sendQuery", name, KEY))


@pytest.mark.parametrize("name", ["appid", "sig"])
def test_plain_values_of_the_vaguer_entry_names_are_quiet(name: str) -> None:
    assert not _found(_entries("queryParameters", "sendQuery", name, "my-application"))


@pytest.mark.parametrize(
    "command",
    [
        f'curl -H "X-Api-Key: {KEY}" https://a.example.com',
        f"curl --header 'Authorization: token {KEY}' https://a.example.com",
        f'curl -H "Authorization: Bearer {KEY}" https://a.example.com',
        f"API_KEY={KEY} ./run.sh",
        f"export OPENAI_API_KEY='{KEY}'; ./run.sh",
        f"cd /app && DB_PASSWORD={KEY} ./run.sh",
    ],
)
def test_secrets_in_a_shell_command(command: str) -> None:
    assert _found(node("X", "executeCommand", {"command": command}))
    wf = from_data(workflow([node("X", "executeCommand", {"command": command})]), "x")[0]
    assert KEY not in secret_masker(wf)(command)


@pytest.mark.parametrize(
    "command",
    [
        'curl -H "X-Api-Key: $API_KEY" https://a.example.com',
        'curl -H "Content-Type: application/json" https://a.example.com',
        f'curl -H "X-Request-Id: {KEY}" https://a.example.com',
        "API_KEY=$(cat /run/key) ./run.sh",
        "MAX_TOKENS=1234567890 ./run.sh",
        "PATH=/usr/local/bin ./run.sh",
        "NEXT_TOKEN=abc123def456 ./run.sh",
    ],
)
def test_shell_commands_without_a_secret_stay_quiet(command: str) -> None:
    assert not _found(node("X", "executeCommand", {"command": command}))


@pytest.mark.parametrize("literal", ["{'api_key':'%s'}", "{api_key:'%s'}", '{"token": "%s"}', "{ headers: { 'X-Api-Key': '%s' } }"])
@pytest.mark.parametrize("field", ["jsonBody", "note"])
def test_an_object_literal_in_an_expression(literal: str, field: str) -> None:
    value = "={{ " + literal % KEY + " }}"
    assert _found(_http(**{field: value}))
    wf = from_data(workflow([_http(**{field: value})]), "x")[0]
    assert KEY in known_secrets(wf)


def test_an_expression_that_only_reads_a_key_stays_quiet() -> None:
    assert not _found(_http(jsonBody="={{ {'api_key': $env.API_KEY, 'token': 'next', 'a': $json.token} }}"))


@pytest.mark.parametrize("password", ["correct horse battery staple", "my pass phrase 12", "Tr0ub4dor and 3"])
def test_passwords_with_spaces_are_reported_and_masked(password: str) -> None:
    assert _found(node("S", "set", {"options": {"password": password}}))
    assert _found(node("S", "set", {"assignments": {"assignments": [{"name": "password", "value": password}]}}))
    assert _found(_entries("bodyParameters", "sendBody", "password", password))
    wf = from_data(workflow([node("S", "set", {"options": {"password": password}})]), "x")[0]
    assert password not in outline(wf)


@pytest.mark.parametrize("value", ["your password here", "Enter your password", "not a secret value for the header"])
def test_spaces_only_count_in_a_field_named_for_a_password_and_not_for_a_template(value: str) -> None:
    fields = [_entries("headerParameters", "sendHeaders", "X-Custom-Thing", value)]
    if "password" in value:
        fields.append(node("S", "set", {"options": {"password": value}}))
    for field in fields:
        assert not _found(field), field


TOKENS = {
    "stripe webhook": "whsec_" + _mixed("w", 32),
    "digitalocean": "dop_v1_" + _hex("d", 64),
    "linear": "lin_api_" + _mixed("l", 40),
    "tavily": "tvly-" + _mixed("tv", 32),
    "tavily dev": "tvly-dev-" + _mixed("tv", 32),
    "supabase": "sbp_" + _hex("sb", 40),
    "pinecone": "pcsk_" + _mixed("pc", 50),
    "atlassian": "ATATT3x" + _mixed("at", 60),
    "facebook": "EAAB" + _mixed("fb", 100),
    "sentry": "sntrys_" + _mixed("se", 60),
    "slack app": "xapp-1-A0123-" + _hex("x", 40),
    "notion legacy": "secret_" + _mixed("nn", 43),
}


@pytest.mark.parametrize("token", TOKENS.values(), ids=TOKENS)
def test_more_token_prefixes(token: str) -> None:
    assert _found(_http(note=token))
    assert token not in redact(f"the token {token} here")


@pytest.mark.parametrize(
    "text",
    [
        "whsec_short",
        "secret_key",
        "secret_" + "a" * 20,
        "key-" + _hex("m", 32),
        "tvly-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "lin_api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "dop_v1_" + "0" * 64,
        "EAAB" + "x" * 90,
    ],
)
def test_what_only_looks_like_those_prefixes_stays_quiet(text: str) -> None:
    assert not _found(_http(note=text))


@pytest.mark.parametrize("name", ["X-Requester-Api-Key", "X-Tracer-Token", "X-Public-Api-Token"])
def test_a_header_that_only_contains_a_harmless_word_is_checked(name: str) -> None:
    assert _found(_entries("headerParameters", "sendHeaders", name, KEY))


@pytest.mark.parametrize(
    "name",
    [
        "X-Request-Id",
        "Idempotency-Key",
        "X-Idempotency-Key",
        "X-Correlation-Id",
        "X-Trace-Id",
        "Sec-WebSocket-Key",
        "X-Cache-Key",
        "X-Page-Token",
        "X-Next-Token",
        "X-Public-Key",
        "X-Amz-Request-Id",
    ],
)
def test_a_header_whose_exact_name_holds_an_id_stays_quiet(name: str) -> None:
    assert not _found(_entries("headerParameters", "sendHeaders", name, KEY))


@pytest.mark.parametrize("name", ["PAGE_TOKEN", "page_token", "webpage_token", "my_next_token"])
def test_a_token_variable_is_not_skipped_by_part_of_its_name(name: str) -> None:
    assert _found(node("C", "code", {"jsCode": f'const {name} = "{KEY}";'}, 2))


@pytest.mark.parametrize("name", ["NEXT_TOKEN", "nextToken", "pageToken", "nextPageToken", "continuationToken", "next_page_token"])
def test_a_paging_variable_stays_quiet(name: str) -> None:
    assert not _found(node("C", "code", {"jsCode": f'const {name} = "{KEY}";'}, 2))
