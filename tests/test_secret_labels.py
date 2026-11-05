"""Sticky-note labels, provider token prefixes, percent-encoded spellings, and names that hold no secret."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.executions import render_text, summarize
from n8n_doctor.explain import outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.report import Style
from n8n_doctor.rules import known_secrets, redact
from n8n_doctor.workflow import from_data

from .conftest import link, node, of, trigger, workflow

SECRET = "Qz7vK2mPx9Lw4Tb"


def _note(text: str) -> dict[str, Any]:
    return workflow([trigger(), node("Note", "stickyNote", {"content": text})])


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"X-Api-Key: {SECRET}", SECRET),
        (f"x-api-key: `{SECRET}`", SECRET),
        (f"Authorization: {SECRET}", SECRET),
        (f"Authorization: Bearer {SECRET}", SECRET),
        ("Authorization: Basic Ym9iOmh1bnRlcjI=", "Ym9iOmh1bnRlcjI="),
        (f"the password is {SECRET}", SECRET),
        (f"The API key is {SECRET}.", SECRET),
        ("password is hunter2", "hunter2"),
        (f"| password | {SECRET} |", SECRET),
        (f"| name | value |\n|---|---|\n| **password** | `{SECRET}` |", SECRET),
        (f"| X-Api-Key | {SECRET} |", SECRET),
        ("password: hunter2", "hunter2"),
        ("Password: Hunter2", "Hunter2"),
        ("Password: ADMINPASS", "ADMINPASS"),
    ],
)
def test_a_labelled_value_is_reported_and_masked(text: str, secret: str) -> None:
    data = _note(text)
    assert of(data, "N8D101"), text
    flow = from_data(data, "x.json")[0]
    assert secret in known_secrets(flow) and secret not in outline(flow)


@pytest.mark.parametrize(
    "text",
    [
        "API key: OpenAI",
        "Token: Telegram",
        "**API key:** SerpAPI",
        "Password: 1Password",
        "Pass: Next",
        "Token: OAuth2",
        "Authorization: Header",
        "Authorization: Bearer",
        "Authorization: required",
        "X-Api-Key: required",
        "the password is required",
        "the password is stored",
        "The password is correct.",
        "| password | string |",
        "| password | required |",
        "| Password | Yes |",
        "| password | ------ |",
        "| Name | Type |",
    ],
)
def test_a_label_with_a_word_is_quiet(text: str) -> None:
    assert of(_note(text), "N8D101") == [], text
    assert known_secrets(from_data(_note(text), "x.json")[0]) == []


TOKENS = [
    "glpat-" + "aB3dE6gH9jK2mN5pQ8sT",
    "hf_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3h",
    "shpat_" + "0123456789abcdef0123456789abcdef",
    "npm_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6",
    "ya29." + "a0AfB_byC3dE6gH9jK2mN5pQ8sT1vW4yZ7b",
    "pplx-" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6lN9",
    "r8_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6l",
    "xai-" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6lN9qS2uV5xA8",
    "sk_test_" + "aB3dE6gH9jK2mN5pQ8sT1vW4",
]


@pytest.mark.parametrize("token", TOKENS)
def test_token_prefixes_in_free_text(token: str) -> None:
    data = workflow([trigger(), node("S", "set", {"note": f"call it with {token} please"})])
    assert of(data, "N8D101")
    assert token not in redact(f"call it with {token} please")
    assert token in known_secrets(from_data(data, "x.json")[0])


@pytest.mark.parametrize("word", ["npm_config_registry", "hf_hub_download", "xai-grok-beta", "sk_test_", "ya29.", "r8_", "glpat-your-token-here-please"])
def test_near_token_words_are_quiet(word: str) -> None:
    assert of(workflow([trigger(), node("S", "set", {"note": f"use {word} here"})]), "N8D101") == []


def test_azure_account_key() -> None:
    key = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6lN9qS2uV5xA8c+/dEf1gH2iJ3kL4mN5oP6qR7sT8uV9w=="
    text = f"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={key};EndpointSuffix=core.windows.net"
    assert of(workflow([trigger(), node("S", "set", {"note": text})]), "N8D101")
    assert key not in redact(text)


def test_redis_url_with_no_user() -> None:
    url = "redis://:Qz7vK2mPx9@cache.example.com:6379/0"
    assert of(workflow([trigger(), node("S", "set", {"note": url})]), "N8D101")
    assert "Qz7vK2mPx9" not in redact(url)
    assert of(workflow([trigger(), node("S", "set", {"note": "http://:8080/a@b"})]), "N8D101") == []


class _Client:
    base = "https://n8n.example.com/api/v1"

    def __init__(self, message: str, secret: str) -> None:
        entry = {"name": "Authorization", "value": secret}
        call = node("Call", "httpRequest", {"url": "https://x.example.com", "headerParameters": {"parameters": [entry]}}, 4.2)
        self.data = workflow([trigger(), call], link("Start", "Call"))
        self.message = message

    def executions(self, *args: Any, **kwargs: Any) -> Any:
        error = {"message": self.message}
        yield {"id": "1", "workflowId": "w", "startedAt": "t", "workflowData": self.data, "data": {"resultData": {"error": error, "lastNodeExecuted": "Call"}}}

    def workflow(self, wid: str) -> Any:
        raise AssertionError("the execution carries its workflow")


@pytest.mark.parametrize(
    ("secret", "spelled"), [("p@ss/w0rd+Qz7!", "p%40ss%2Fw0rd%2BQz7%21"), ("p@ss/w0rd+Qz7!", "p%40ss%2fw0rd%2bQz7!"), ("a b+c/d9e8f7", "a+b%2Bc%2Fd9e8f7")]
)
def test_executions_mask_a_percent_encoded_secret(secret: str, spelled: str) -> None:
    client: Any = _Client(f"request to https://x.example.com/?q={spelled} failed", secret)
    text = render_text(summarize(client, None, 10), Style(False))
    assert "failed" in text and spelled not in text


@pytest.mark.parametrize("name", ["nextPageToken", "pageToken", "next_page_token", "NextToken", "continuationToken"])
def test_paging_names_hold_no_secret(name: str) -> None:
    query = {"parameters": [{"name": name, "value": "CAESBgoEQWJjZDEyMw"}]}
    data = workflow([trigger(), node("Call", "httpRequest", {"url": "https://x.example.com", "queryParameters": query}, 4.2)])
    assert of(data, "N8D101") == []
    assert known_secrets(from_data(data, "x.json")[0]) == []
    code = workflow([trigger(), node("Run", "code", {"jsCode": f'const {name.replace("-", "_")} = "CAESBgoEQWJjZDEyMw";\nreturn [];'}, 2)])
    assert of(code, "N8D101") == []


@pytest.mark.parametrize("name", ["X-Key-Id", "X-Auth-Scheme", "x-key-id", "X-Auth-Scheme"])
def test_header_names_that_describe_a_key(name: str) -> None:
    entry = {"name": name, "value": "kid-2024-Qz7vK2mPx9"}
    data = workflow([trigger(), node("Call", "httpRequest", {"url": "https://x.example.com", "headerParameters": {"parameters": [entry]}}, 4.2)])
    assert of(data, "N8D101") == []
    assert known_secrets(from_data(data, "x.json")[0]) == []


def test_fix_moves_a_leading_space_instead_of_doubling_the_equals_sign() -> None:
    data = workflow([trigger(), node("S", "set", {"value": " ={{ $json.a }}", "other": " {{ $json.b }}"})])
    result = fix_workflow(from_data(data, "x.json")[0])
    params = result.fixed["nodes"][1]["parameters"]
    assert params["value"] == "={{ $json.a }}"
    assert params["other"] == "= {{ $json.b }}"
    assert not of(json.loads(result.fixed_text), "N8D212")


def test_an_empty_object_is_no_node() -> None:
    found = of(workflow([trigger(), {}]), "N8D213")
    assert [f.message for f in found] == ["nodes[1] is an empty object, not a node object"]
    assert all(f.rule.id != "N8D101" for f in run(from_data(workflow([{}]), "x.json")))


@pytest.mark.parametrize(
    "label",
    [
        "OPENAI_API_KEY=",
        "export OPENAI_API_KEY=",
        "client_secret: ",
        "DB_PASSWORD=",
        "access_token: ",
        "accessToken: ",
        "clientSecret: ",
        "APIKEY=",
        "MY_SECRET=",
        "GROQ_API_KEY: ",
        "SMTP_PASSWORD: ",
        "bot_token: ",
        "**client_secret:** ",
        "- api_token: ",
        "`DB_PASSWORD`: ",
        'OPENAI_API_KEY="',
        "ClientSecret = ",
        "my-api-key: ",
    ],
)
@pytest.mark.parametrize("value", [SECRET, "hunter22"])
def test_prefixed_and_environment_labels_are_reported_and_masked(label: str, value: str) -> None:
    wf = from_data(_note(f"Setup:\n{label}{value}\nthen run it"), "x.json")[0]
    assert [f for f in run([wf]) if f.rule.id == "N8D101"], label
    assert value not in outline(wf)


def test_a_secret_with_a_slash_after_an_environment_label() -> None:
    value = "wJalrXUtnFEM/K7MDENG+bPxRfiCYzzz"
    wf = from_data(_note(f"AWS_SECRET_ACCESS_KEY={value}"), "x.json")[0]
    assert any(f.rule.id == "N8D101" for f in run([wf])) and value not in outline(wf)


@pytest.mark.parametrize(
    "text",
    [
        "password: string",
        "token: string,",
        "Token: 4096",
        "max token: 4096",
        "max_token: 4096",
        "MAX_TOKENS=4096",
        "maxTokens: 128000",
        "Token: gpt-4o",
        "token: claude-3",
        "Secret: (none)",
        "client_secret: string",
        "access_token: required",
        "OPENAI_API_KEY=your_api_key_here",
        "OPENAI_API_KEY=<your key>",
        "OPENAI_API_KEY=$OPENAI_API_KEY",
        "DB_PASSWORD={{ $env.PW }}",
        "secret_name: production",
        "token_url: https://a.example.com/token",
        "next_token: abc123def",
        "compass: north1234",
        "bypass=abc12345",
    ],
)
def test_labels_that_hold_no_secret_stay_quiet(text: str) -> None:
    wf = from_data(_note(text), "x.json")[0]
    assert not [f for f in run([wf]) if f.rule.id == "N8D101"], text
