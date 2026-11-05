"""Names and values at the edges of N8D101, and the fields fix leaves alone (N8D212)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.rules import known_secrets
from n8n_doctor.workflow import from_data

from .conftest import link, node, of, trigger, workflow

GENERATED = "aZ3kP9qL2xV7mN4tR8wY"
ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
PRIVATE = "0x" + "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"


def _http(**params: Any) -> dict[str, Any]:
    return workflow([trigger(), node("H", "httpRequest", {"url": "https://a.io", **params})], link("Start", "H"))


def _entry(name: str, value: str) -> dict[str, Any]:
    return _http(sendHeaders=True, headerParameters={"parameters": [{"name": name, "value": value}]})


def _set_field(name: str, value: str) -> dict[str, Any]:
    return workflow([trigger(), node("S", "set", {"assignments": {"assignments": [{"name": name, "value": value}]}})], link("Start", "S"))


def _json_headers(name: str, value: str) -> dict[str, Any]:
    return _http(sendHeaders=True, specifyHeaders="json", jsonHeaders=json.dumps({name: value}))


def _json_body(name: str, value: str) -> dict[str, Any]:
    return _http(sendBody=True, specifyBody="json", jsonBody=json.dumps({"a": 1, name: value}))


def _command(name: str, value: str) -> dict[str, Any]:
    return workflow([trigger(), node("C", "executeCommand", {"command": f"curl -H '{name}: {value}' https://a.io"})], link("Start", "C"))


def _raw(name: str, value: str) -> dict[str, Any]:
    text = '{"headers": [{"name": "%s", "value": "%s"},]}' % (name, value)  # noqa: UP031  (does not parse: read as raw text)
    return workflow([trigger(), node("W", "executeWorkflow", {"source": "parameter", "workflowJson": text})], link("Start", "W"))


def _note(content: str) -> dict[str, Any]:
    return workflow([trigger(), node("Note", "stickyNote", {"content": content})])


SHAPES = [_entry, _set_field, _json_headers, _json_body, _command]


# A1: a trailing APIKEY, APITOKEN or AUTHTOKEN segment


@pytest.mark.parametrize("name", ["X-MBX-APIKEY", "MBX-APIKEY", "x-acme-apitoken", "ACME_AUTHTOKEN"])
@pytest.mark.parametrize("shape", [_entry, _set_field, _json_headers, _json_body])
def test_a_trailing_key_word_is_a_secret_name(shape: Any, name: str) -> None:
    assert of(shape(name, "plainword123"), "N8D101")


def test_a_trailing_key_word_after_a_space() -> None:
    assert of(_set_field("My APIKEY", "plainword123"), "N8D101")


@pytest.mark.parametrize("shape", [_command, _raw])
def test_x_mbx_apikey_in_commands_and_raw_text(shape: Any) -> None:
    assert of(shape("X-MBX-APIKEY", GENERATED), "N8D101")


def test_x_mbx_apikey_is_masked() -> None:
    assert GENERATED in known_secrets(from_data(_entry("X-MBX-APIKEY", GENERATED), "x.json")[0])


@pytest.mark.parametrize("name", ["apikey_hint", "APIKEY-Label", "myapikeyring", "authtokenizer"])
def test_those_words_elsewhere_in_a_name_do_not_count_for_a_plain_value(name: str) -> None:
    assert not of(_entry(name, "plainword"), "N8D101")


# A2: JSON text reads names as key/value entries do


JSON_NAMES = [
    "xi-api-key",
    "Ocp-Apim-Subscription-Key",
    "PRIVATE-TOKEN",
    "X-TOKEN",
    "api_token",
    "apiToken",
    "secret_key",
    "access_key",
    "bot_token",
    "session_token",
    "webhook_secret",
    "consumer_secret",
    "license_key",
]


@pytest.mark.parametrize("name", JSON_NAMES)
@pytest.mark.parametrize("shape", [_json_headers, _json_body, _entry])
def test_json_reads_the_same_names_as_entries(shape: Any, name: str) -> None:
    data = shape(name, GENERATED)
    assert of(data, "N8D101")
    assert GENERATED in known_secrets(from_data(data, "x.json")[0])


@pytest.mark.parametrize("shape", [_json_headers, _json_body])
@pytest.mark.parametrize("value", ["session=" + GENERATED, "a=b; session=" + GENERATED + "; c=d"])
def test_a_cookie_in_json(shape: Any, value: str) -> None:
    assert of(shape("Cookie", value), "N8D101")


@pytest.mark.parametrize("shape", [_json_headers, _json_body])
@pytest.mark.parametrize("value", ["theme=dark", "a=b; c=d", "{{ $json.cookie }}"])
def test_a_plain_cookie_in_json_is_quiet(shape: Any, value: str) -> None:
    assert not of(shape("Cookie", value), "N8D101")


@pytest.mark.parametrize("shape", [_json_headers, _json_body])
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("xi-api-key", "insert elevenlabs api key"),
        ("access_key", "ACCESS_KEY"),
        ("api_token", "YOUR_API_TOKEN"),
        ("secret_key", "your-secret-key"),
        ("bot_token", "plainword"),
        ("X-TOKEN", "{{ $json.token }}"),
        ("X-Request-Id", GENERATED),
        ("object_key", GENERATED),
        ("next_token", GENERATED),
    ],
)
def test_placeholders_and_other_names_in_json_are_quiet(shape: Any, name: str, value: str) -> None:
    assert not of(shape(name, value), "N8D101")


@pytest.mark.parametrize("shape", [_entry, _set_field, _json_body])
def test_the_digit_of_n8n_makes_no_generated_value(shape: Any) -> None:
    assert not of(shape("monitorKey", "n8n-hiring-watch"), "N8D101")


# A3: sticky-note URLs


@pytest.mark.parametrize(
    "content",
    [
        "Call `https://a.io/run?token=YOUR_API_TOKEN`",
        "*https://a.io/run?token=YOUR_API_TOKEN*",
        "**https://a.io/run?token=YOUR_API_TOKEN**",
        "See https://a.io/run?token=YOUR_API_TOKEN.",
        "(see https://a.io/run?token=YOUR_API_TOKEN)",
        "(`https://a.io/run?token=YOUR_API_TOKEN`).",
        "URL: `https://a.io/news?q=YOUR_TOPICS&apiKey=YOUR_KEY&pageSize=3`",
        "URL: https://a.io/news?apiKey=YOUR_KEY&pageSize=3",
        "my_api_key=YOUR_KEY&pageSize=3",
    ],
)
def test_note_urls_with_a_placeholder_are_quiet(content: str) -> None:
    assert not of(_note(content), "N8D101")


@pytest.mark.parametrize(
    "content",
    [
        f"Call `https://a.io/run?token={GENERATED}`",
        f"*https://a.io/run?token={GENERATED}*",
        f"See https://a.io/run?token={GENERATED}.",
        f"(see https://a.io/run?token={GENERATED})",
        f"URL: `https://a.io/news?apiKey={GENERATED}&pageSize=3`",
    ],
)
def test_note_urls_with_a_real_value_report_the_value_alone(content: str) -> None:
    data = _note(content)
    assert of(data, "N8D101")
    assert GENERATED in known_secrets(from_data(data, "x.json")[0])


def test_a_url_token_keeps_its_inner_punctuation() -> None:
    jwt_like = "abc123def.ghi456jkl.mno789pqr"
    assert jwt_like in known_secrets(from_data(_http(url=f"https://a.io/run?token={jwt_like}"), "x.json")[0])


# A4: a Teams webhook URL that only shows where it goes


@pytest.mark.parametrize("path", ["your-teams-incoming-webhook", "YOUR_TEAMS_WEBHOOK_URL_PATH", "your-webhook-goes-here-please"])
def test_teams_webhook_placeholder(path: str) -> None:
    assert not of(_http(url=f"https://outlook.office.com/webhook/{path}"), "N8D101")


def test_a_real_teams_webhook_is_reported() -> None:
    url = "https://outlook.office.com/webhook/0f8fad5b-d9cb-469f-a165-70867728950e@1f8fad5b-d9cb-469f-a165-70867728950e/IncomingWebhook/a1b2c3d4"
    assert of(_http(url=url), "N8D101")


# A5: public token addresses


@pytest.mark.parametrize("name", ["token_address", "USDT ERC-20 Token Address", "tokenAddress", "Token-Address"])
@pytest.mark.parametrize("shape", [_entry, _set_field, _json_headers, _json_body])
def test_a_token_address_is_no_secret(shape: Any, name: str) -> None:
    assert not of(shape(name, ADDRESS), "N8D101")


@pytest.mark.parametrize("name", ["private_key", "PRIVATE_KEY", "wallet_private_key", "privateKey"])
def test_a_private_key_in_hex_is_a_secret(name: str) -> None:
    assert of(_set_field(name, PRIVATE), "N8D101")
    assert of(_json_body(name, PRIVATE), "N8D101")


# More header names


@pytest.mark.parametrize("name", ["X-Authorization", "Authentication", "OK-ACCESS-PASSPHRASE", "CB-ACCESS-PASSPHRASE"])
@pytest.mark.parametrize("shape", [_entry, _json_headers])
def test_more_header_names(shape: Any, name: str) -> None:
    assert of(shape(name, GENERATED), "N8D101")


@pytest.mark.parametrize("name", ["X-Authorization", "Authentication"])
def test_those_headers_take_any_scheme_word(name: str) -> None:
    data = _entry(name, f"SSWS {GENERATED}")
    assert of(data, "N8D101")
    assert GENERATED in known_secrets(from_data(data, "x.json")[0])


@pytest.mark.parametrize("value", ["genericCredentialType", "predefinedCredentialType", "headerAuth", "basicAuth", "oAuth2Api", "none"])
@pytest.mark.parametrize("shape", [_entry, _set_field, _json_body])
def test_authentication_modes_are_quiet(shape: Any, value: str) -> None:
    assert not of(shape("authentication", value), "N8D101")


# Generic names on ordinary values


@pytest.mark.parametrize("name", ["Sheet Key", "spreadsheet_key", "product_key", "price_key", "Public Key", "Next Token", "Secret Name", "spreadsheetKey"])
@pytest.mark.parametrize("shape", [_entry, _set_field, _json_body])
def test_generic_names_on_ordinary_values_are_quiet(shape: Any, name: str) -> None:
    assert not of(shape(name, "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"), "N8D101")


def test_a_provider_token_under_a_generic_name_is_reported() -> None:
    assert of(_set_field("Sheet Key", "ghp_" + "aZ3kP9qL2xV7mN4tR8wYaZ3kP9qL2xV7mN4t"), "N8D101")


# N8D212: what fix leaves alone


def _fixable(data: dict[str, Any]) -> list[bool]:
    return [f.autofix for f in of(data, "N8D212")]


def test_ui_cache_fields_are_skipped() -> None:
    locator = {"__rl": True, "mode": "list", "value": "{{ $datatable_id }}", "cachedResultUrl": "/projects/{{ $project }}/t", "cachedResultName": "{{ $x }}"}
    data = workflow([trigger(), node("D", "set", {"dataTableId": locator})], link("Start", "D"))
    found = of(data, "N8D212")
    assert [f.parameter for f in found] == ["dataTableId.value"]


LONG = "You build workflows. Input: {{ $json.a }}\n" + "Follow these rules carefully.\n" * 60 + 'Example: "value": "={{ $json.output }}"\n'


@pytest.mark.parametrize(
    "params",
    [
        {"text": LONG},
        {"prompt": LONG},
        {"options": {"systemMessage": LONG}},
        {"message": LONG},
        {"messages": {"values": [{"content": LONG}]}},
    ],
)
def test_a_long_prompt_is_reported_but_not_fixed(params: dict[str, Any]) -> None:
    data = workflow([trigger(), node("A", "set", params)], link("Start", "A"))
    assert _fixable(data) == [False]


@pytest.mark.parametrize(
    "params",
    [{"text": "Hello {{ $json.name }}"}, {"options": {"systemMessage": "Answer for {{ $json.user }}"}}, {"description": LONG}],
)
def test_short_prompts_and_other_fields_are_still_fixed(params: dict[str, Any]) -> None:
    data = workflow([trigger(), node("A", "set", params)], link("Start", "A"))
    assert _fixable(data) == [True]
