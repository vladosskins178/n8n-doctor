"""What counts as a placeholder for a secret, and masking that does not depend on it."""

from __future__ import annotations

import json
import random
import string
import time
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.rules import _looks_secret_value, _passes_filter, _placeholder, known_secrets
from n8n_doctor.workflow import from_data

from .conftest import link, load, node, of, trigger, workflow

# real passwords that hold a word a template might use ("enter", "your", "add", "example") or are written in capitals
REAL_PASSWORDS = [
    "Enter-The-Dragon-99",
    "Your.Pass.2024!x",
    "add-me-2024!",
    "addMe2024!",
    "Prod-Example-77",
    "insert-coin-42!",
    "ADMINPASS",
    "SUPERSECRETPASSWORD",
    "CORPAUTHPWD",
    "MYAPIKEYVALUE",
]


def _fix_outputs(data: dict[str, Any]) -> str:
    """The fix diff (API and MCP n8n_fix) of a workflow whose fix touches the line after the secret."""
    wf = from_data(data, "x.json")[0]
    diff = fix_workflow(wf).diff
    assert diff, "the test workflow needs at least one fix so there is a diff"
    return diff + "\n" + json.dumps(mcp.call_tool("n8n_fix", {"workflow": data, "output": "diff"}))


def _password_field(value: str) -> dict[str, Any]:
    """A Set node whose password sits in the diff context: N8D212 fix adds = to the next line."""
    return workflow([trigger(), node("S", "set", {"options": {"password": value, "note": "{{ $json.x }}"}}, 3.4)], link("Start", "S"))


def _secret_routes(value: str) -> list[dict[str, Any]]:
    """Workflows with ``value`` in each kind of secret-named field."""
    header = {"name": "Authorization", "value": value}
    return [
        _password_field(value),
        workflow([trigger(), node("H", "httpRequest", {"sendHeaders": True, "headerParameters": {"parameters": [header]}}, 4.2)], link("Start", "H")),
        workflow([trigger(), node("H", "httpRequest", {"specifyHeaders": "json", "jsonHeaders": json.dumps({"X-Api-Key": value})}, 4.2)], link("Start", "H")),
        workflow([trigger(), node("Code", "code", {"jsCode": f'const apiKey = "{value}";\nreturn [];'}, 2)], link("Start", "Code")),
    ]


@pytest.mark.parametrize("password", REAL_PASSWORDS)
def test_real_passwords_are_flagged_and_masked(password: str) -> None:
    routes = _secret_routes(password)
    for data in routes[:3]:  # a Code assignment also needs a generated-looking value to be reported
        assert of(data, "N8D101")
    for data in routes:
        assert password in known_secrets(load(data))
    assert password not in _fix_outputs(_password_field(password))


@pytest.mark.parametrize(
    "value",
    ["POSTIZ_API_KEY", "enter-your-api-key", "<YOUR_TOKEN>", "%API_KEY%", "REPLACE_ME", "changeme", "AKIAIOSFODNN7EXAMPLE"],
)
def test_values_not_reported_are_still_masked_in_secret_fields(value: str) -> None:
    for data in _secret_routes(value):
        assert of(data, "N8D101") == []
        assert value in known_secrets(load(data))
    assert value not in _fix_outputs(_password_field(value))


@pytest.mark.parametrize(
    "value",
    [
        "YOUR_API_KEY",
        "your-api-key",
        "[your token]",
        "put_your_secret",
        "replace-with-your-password",
        "xxxxxxxx",
        "********",
        "placeholder",
        "example",
        "CLIENTSECRET",
        "ACCESSTOKEN",
        "MY_SERVICE_TOKEN",
        "%MY_PASSWORD%",
    ],
)
def test_template_forms_are_placeholders(value: str) -> None:
    assert not _looks_secret_value(value)


@pytest.mark.parametrize("value", ["API_KEY_7Q2W9E4R8T1Y", "PROD_DB_PASS", "SECRET_SAUCE", "ENTER_YOUR_KEY_123", "my-example-password-1"])
def test_capitals_and_words_alone_do_not_make_a_placeholder(value: str) -> None:
    assert _looks_secret_value(value)


_ALNUM = string.ascii_letters + string.digits
# (pattern, prefix, alphabet, length of the random part)
_PROVIDERS = [
    ("an OpenAI API key", "sk-", _ALNUM + "_-", 48),
    ("an OpenAI API key", "sk-proj-", _ALNUM + "_-", 48),
    ("an Anthropic API key", "sk-ant-", _ALNUM + "_-", 40),
    ("a GitHub token", "ghp_", _ALNUM, 36),
    ("a GitHub token", "github_pat_", _ALNUM + "_", 60),
    ("an AWS access key", "AKIA", string.ascii_uppercase + string.digits, 16),
    ("an AWS access key", "ASIA", string.ascii_uppercase + string.digits, 16),
    ("a Slack token", "xoxb-", _ALNUM + "-", 40),
    ("a Stripe live key", "sk_live_", _ALNUM, 24),
    ("a Stripe live key", "rk_live_", _ALNUM, 24),
    ("a Google API key", "AIza", _ALNUM + "_-", 35),
]


@pytest.mark.parametrize(("what", "prefix", "alphabet", "size"), _PROVIDERS, ids=[p[1] for p in _PROVIDERS])
def test_random_provider_tokens_are_never_placeholders(what: str, prefix: str, alphabet: str, size: int) -> None:
    rng = random.Random(f"{prefix}{size}")
    skipped = [t for t in (prefix + "".join(rng.choices(alphabet, k=size)) for _ in range(10_000)) if not _passes_filter(what, t)]
    assert skipped == []


# --- B3: template forms with "here", verbs, camel case, separators; real passwords stay secrets -------------------

TEMPLATE_PLACEHOLDERS = [
    "your_api_key_here",
    "API_KEY_HERE",
    "your-api-key-here",
    "PASTE_YOUR_KEY_HERE",
    "YourAPIKeyHere",
    "api-key-goes-here",
    "Bearer YOUR_ACCESS_TOKEN_HERE",
    "my-api-key",
    "00000000-0000-0000-0000-000000000000",
    "<<API_KEY>>",
    "YOUR-API-KEY-HERE",
    "xxx-xxx-xxx",
    "add_your_api_key_here",
    "put-your-key-here",
    "example-api-key",
    "test-api-key",
    "{{your_token}}",
    "[secret]",
    "%password%",
    "insert-your-token-here",
    "enter_api_key_here",
]


@pytest.mark.parametrize("value", TEMPLATE_PLACEHOLDERS)
def test_template_placeholders_are_not_reported_but_masked(value: str) -> None:
    header = {"name": "X-API-Key", "value": value}
    data = workflow([trigger(), node("H", "httpRequest", {"sendHeaders": True, "headerParameters": {"parameters": [header]}}, 4.2)], link("Start", "H"))
    assert of(data, "N8D101") == []
    secrets = known_secrets(load(data))
    assert value in secrets or value.split()[-1] in secrets or "{{" in value


@pytest.mark.parametrize("password", REAL_PASSWORDS)
def test_real_passwords_next_to_the_placeholders_stay_secrets(password: str) -> None:
    assert _looks_secret_value(password)


# --- B1: secrets in Code -------------------------------------------------------------------------------------------

_CODE_FORMS = [
    ("headers: { 'X-Api-Key': '{v}' }", "Enter-The-Dragon-99"),
    ('headers: { "Authorization": "Basic {v}" }', "aHVudGVyOmh1bnRlcjI="),
    ('JSON.stringify({ "password": "{v}" })', "Tr0ub4dor&3"),
    ("auth: { username: 'svc', password: '{v}' }", "Blue-Sky-Rain-77"),
    ("params.set('token', '{v}');", "Moon-River-2024"),
    ('headers.append("X-Api-Key", "{v}");', "Enter-The-Dragon-99"),
    ('const db = "Server=db;User Id=sa;Password={v};";', "Winter-Is-Coming-1"),
    ("const pass = '{v}';", "Purple-Monkey-Dishwasher"),
    ("const pwd = '{v}';", "Purple-Monkey-Dishwasher"),
    ("const dbPasswd = '{v}';", "Purple-Monkey-Dishwasher"),
]


@pytest.mark.parametrize(("template", "secret"), _CODE_FORMS, ids=[t for t, _ in _CODE_FORMS])
def test_code_secret_forms_are_flagged_and_masked(template: str, secret: str) -> None:
    code = "const res = await this.helpers.httpRequest({ " + template.replace("{v}", secret) + " });\nreturn [];"
    data = workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"))
    assert of(data, "N8D101"), template
    assert secret in known_secrets(load(data))


@pytest.mark.parametrize("code", ["const pass = 'YOUR_PASSWORD';", "params.set('token', '{{token}}');", "const pass = process.env.DB_PASS;"])
def test_code_placeholders_are_not_flagged(code: str) -> None:
    data = workflow([trigger(), node("Code", "code", {"jsCode": code + "\nreturn [];"}, 2)], link("Start", "Code"))
    assert of(data, "N8D101") == []


# --- B2: JSON text in any field, URL query values ----------------------------------------------------------------------


def test_json_text_in_any_field_is_scanned() -> None:
    build = node(
        "Build", "set", {"mode": "raw", "jsonOutput": '{"api_key":"Enter-The-Dragon-99","password":"Blue-Sky-Rain-77","email":"{{ $json.email }}"}'}, 3.4
    )
    raw = node("Raw", "httpRequest", {"sendBody": True, "contentType": "raw", "body": '={"token":"Moon-River-2024","q":"{{ $json.q }}"}'}, 4.2)
    for n in (build, raw):
        data = workflow([trigger(), n], link("Start", n["name"]))
        assert of(data, "N8D101"), n["name"]
    secrets = known_secrets(load(workflow([trigger(), build, raw])))
    assert {"Enter-The-Dragon-99", "Blue-Sky-Rain-77", "Moon-River-2024"} <= set(secrets)


@pytest.mark.parametrize("name", ["access_token", "password", "passwd", "pwd", "api_key", "apikey", "token", "secret", "client_secret"])
def test_secret_named_query_values_are_flagged_without_digits(name: str) -> None:
    url = f"https://api.x.io/graphql?{name}=Purple-Monkey-Dishwasher&q={{{{ $json.q }}}}"
    data = workflow([trigger(), node("GQL", "httpRequest", {"url": url}, 4.2)], link("Start", "GQL"))
    assert of(data, "N8D101")


@pytest.mark.parametrize("url", ["https://x.io/a?token=YOUR_TOKEN", "https://x.io/a?key=customer_name", "https://x.io/a?access_token={{ $json.t }}"])
def test_query_placeholders_and_weak_names_are_not_flagged(url: str) -> None:
    data = workflow([trigger(), node("G", "httpRequest", {"url": url}, 4.2)], link("Start", "G"))
    assert of(data, "N8D101") == []


@pytest.mark.parametrize("header", ["x-apikey", "X-APIKEY", "X-ApiKey"])
def test_apikey_header_names(header: str) -> None:
    params = {"sendHeaders": True, "headerParameters": {"parameters": [{"name": header, "value": "Enter-The-Dragon-99"}]}}
    data = workflow([trigger(), node("H", "httpRequest", params, 4.2)], link("Start", "H"))
    assert of(data, "N8D101")


# --- over-masking: weak known secrets are masked as whole tokens only ---------------------------------------------------


def test_short_secrets_are_masked_as_whole_tokens_only() -> None:
    from n8n_doctor.rules import secret_masker

    data = workflow([trigger(), node("S", "set", {"options": {"password": "Pa55"}}, 3.4)], link("Start", "S"))
    mask = secret_masker(load(data))
    assert mask("Pa55") == "***" and mask("pass='Pa55';") == "pass='***';"
    assert mask("Pa55word reset") == "Pa55word reset" and mask("XPa55") == "XPa55"
    strong = workflow([trigger(), node("S", "set", {"options": {"password": "Zq8!vR2#kL9@"}}, 3.4)], link("Start", "S"))
    assert secret_masker(load(strong))("aZq8!vR2#kL9@b") == "a***b"  # a strong secret is masked anywhere


# --- change-me and bracketed "your ..." forms, in every place a secret is looked for -----------------------------------

CHANGE_ME_AND_BRACKETED = [
    "CHANGE-ME-app-secret",
    "change_me",
    "changeme-please",
    "changeme-123-token",
    "Change-Me",
    "please-change-me",
    "[your-api-key]",
    "[your-telegram-bot-token]",
    "bot[your-telegram-bot-token]",
    "<your-api-key>",
    "{your-api-key}",
    "{your_app_secret}",
    "[change-me]",
]


def _every_route(value: str) -> dict[str, dict[str, Any]]:
    """Workflows with ``value`` in each field-name path N8D101 checks (named fields, headers, JSON keys, Code, URLs)."""
    params = dict.fromkeys(("app_secret", "token", "api_token", "password", "client_secret", "access_token"), value)
    headers = [{"name": "X-API-Key", "value": value}, {"name": "Authorization", "value": "Bearer " + value}]
    body = json.dumps({"X-Api-Key": value, "app_secret": value, "token": value, "password": value})
    code = f'const apiKey = "{value}";\nconst password = "{value}";\nheaders["x-api-key"] = "{value}";\nreturn [];'
    url = f"https://api.telegram.org/bot{value}/sendMessage?token={value}&api_token={value}"
    one = {
        "named fields": node("S", "set", {"options": params}, 3.4),
        "headers": node("H", "httpRequest", {"sendHeaders": True, "headerParameters": {"parameters": headers}}, 4.2),
        "json keys": node("H", "httpRequest", {"specifyHeaders": "json", "jsonHeaders": body, "jsonBody": body}, 4.2),
        "code": node("Code", "code", {"jsCode": code}, 2),
        "python": node("Code", "code", {"language": "python", "pythonCode": code.replace("const ", "").replace(";", "")}, 2),
        "url": node("H", "httpRequest", {"url": url}, 4.2),
    }
    return {where: workflow([trigger(), n], link("Start", n["name"])) for where, n in one.items()}


@pytest.mark.parametrize("value", CHANGE_ME_AND_BRACKETED)
def test_change_me_and_bracketed_forms_are_placeholders_everywhere(value: str) -> None:
    assert not _looks_secret_value(value)
    reported = {where: [f.message for f in of(data, "N8D101")] for where, data in _every_route(value).items()}
    assert reported == {where: [] for where in reported}
    for where in ("named fields", "headers"):
        assert value in known_secrets(load(_every_route(value)[where])), where  # still masked in output
    assert value not in _fix_outputs(_password_field(value))


@pytest.mark.parametrize("password", [*REAL_PASSWORDS, "Change-Me-Not-2024!", "changeme123", "[Winter-77]x"])
def test_real_passwords_stay_reported_in_every_route(password: str) -> None:
    for where in ("named fields", "headers", "json keys"):
        assert of(_every_route(password)[where], "N8D101"), where


def test_change_me_check_is_fast_on_long_word_lists() -> None:
    start = time.perf_counter()
    assert _looks_secret_value("change me " * 10_000 + "!") is False  # spaces: not a secret either way
    assert _placeholder("change-me-" * 10_000 + "x!") is False
    assert time.perf_counter() - start < 0.5


@pytest.mark.parametrize(
    "value",
    [
        "YOUR_API_HERE",
        "YOUR_API",
        "YOUR_CREDENTIAL_HERE",
        "PROXY_AUTH",
        "Bearer [REDACTED_API_TOKEN]",
        "[REDACTED]",
        "=<__PLACEHOLDER_VALUE__fal Key__>",
        "<__PLACEHOLDER_VALUE__Your API key__>",
        "your_api_key_add_here",
        "enter-your-jotfomr-api",
    ],
)
def test_more_template_placeholders_are_no_findings(value: str) -> None:
    for data in _secret_routes(value):
        wf = from_data(data, "x.json")[0]
        assert not [f for f in run([wf]) if f.rule.id == "N8D101"], (value, data)


# --- a word with digits in the middle, and a typo of "your" ----------------------------------------------------------

_NAMED_PLACEHOLDERS = [
    "YOUR_N8N_API_KEY_HERE",
    "your-n8n-api-key-here",
    "YOUR_N8N_API_KEY",
    "YOUR_S3_SECRET_KEY_HERE",
    "YOUR_GPT4_TOKEN",
    "<YOUR_N8N_API_KEY>",
    "YOU_API_KEY_HERE",
]


@pytest.mark.parametrize("value", [*_NAMED_PLACEHOLDERS, "Bearer YOUR_N8N_API_KEY_HERE"])
def test_a_word_with_digits_keeps_a_placeholder_one(value: str) -> None:
    assert _placeholder(value)
    routes = [
        workflow(
            [trigger(), node("S", "set", {"assignments": {"assignments": [{"id": "1", "name": "n8n_api_key", "type": "string", "value": value}]}}, 3.4)],
            link("Start", "S"),
        ),
        *_secret_routes(value),
    ]
    for data in routes:
        assert of(data, "N8D101") == [], data


@pytest.mark.parametrize(
    "password",
    ["your-2024-password", "add_99_password", "Your2024Key", "you-key-here-99", "your-n8n-api-key-here-99", "your_n8n_api_key_now"],
)
def test_digits_alone_do_not_make_a_placeholder(password: str) -> None:
    assert not _placeholder(password)


# --- private keys that show only where the key goes ---------------------------------------------------------------


@pytest.mark.parametrize("body", ["...", "…", "[INSERT YOUR KEY HERE]", "YOUR_KEY_HERE", "<your-private-key>"])
@pytest.mark.parametrize("line_end", ["\n", "\\n"])
def test_a_private_key_with_a_placeholder_body_is_no_secret(body: str, line_end: str) -> None:
    pem = f"-----BEGIN PRIVATE KEY-----{line_end}{body}{line_end}-----END PRIVATE KEY-----{line_end}"
    for data in (
        workflow([trigger(), node("S", "set", {"private_key": pem, "text": pem}, 1)], link("Start", "S")),
        workflow([trigger(), node("C", "code", {"jsCode": f"const privateKey = `{pem}`;"}, 2)], link("Start", "C")),
        workflow([trigger(), node("H", "httpRequest", {"jsonBody": json.dumps({"private_key": pem})}, 4.2)], link("Start", "H")),
    ):
        assert of(data, "N8D101") == [], data


@pytest.mark.parametrize("body", ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "abcd...", "YOUR_KEY_HERE\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"])
def test_a_private_key_with_a_body_is_a_secret(body: str) -> None:
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    data = workflow([trigger(), node("S", "set", {"text": pem}, 1)], link("Start", "S"))
    assert of(data, "N8D101")
    assert pem in known_secrets(load(data))
