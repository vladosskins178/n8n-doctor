"""Passwords in URLs whole, curl flags of curl only, public token fields, text in expressions, retry settings kept."""

from __future__ import annotations

import pytest

from n8n_doctor.fix import fix_workflow
from n8n_doctor.rules import known_secrets, redact

from .conftest import link, load, node, of, trigger, workflow

PASSWORDS = ["Admin12!", "Pass123!", "hunter2!", "Winter..2024x", "Pa!!w0rd12", "Secret!!Rest123", "SuperSecret!!Rest123"]
SOL = "So11111111111111111111111111111111111111112"
EVM = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


def _url(url: str) -> dict[str, object]:
    return workflow([node("H", "httpRequest", {"url": url}, 4)])


def _command(command: str) -> dict[str, object]:
    return workflow([node("E", "executeCommand", {"command": command})])


def _header(name: str, value: str) -> dict[str, object]:
    params = {"url": "https://a.example", "sendHeaders": True, "headerParameters": {"parameters": [{"name": name, "value": value}]}}
    return workflow([node("H", "httpRequest", params, 4)])


@pytest.mark.parametrize("name", ["password", "passwd", "pwd", "pass", "db_password", "user-pass", "passphrase"])
@pytest.mark.parametrize("value", PASSWORDS)
def test_a_password_in_a_url_is_reported_and_masked_whole(name: str, value: str) -> None:
    url = f"https://a.example/login?u=a&{name}={value}"
    assert len(of(_url(url), "N8D101")) == 1
    assert value in known_secrets(load(_url(url)))
    assert redact(url) == f"https://a.example/login?u=a&{name}=***"


@pytest.mark.parametrize("stop", ["&x=1", "#top", " next", "'", '"', "}", "<", ">", "`"])
def test_a_password_in_a_url_ends_at_its_delimiters(stop: str) -> None:
    assert redact(f"https://a.example/?password=Admin12!{stop}") == f"https://a.example/?password=***{stop}"


def test_a_short_password_before_a_delimiter_still_counts_but_not_before_an_expression() -> None:
    assert redact("x?password=abcd`") == "x?password=***`"
    assert of(_url("https://a.example/?password=abcd{{ $json.x }}"), "N8D101") == []


@pytest.mark.parametrize("value", ["{{ $json.password }}", "<password>", "YOUR_PASSWORD", "your-password!", "changeme"])
def test_placeholders_in_a_password_field_of_a_url_stay_quiet(value: str) -> None:
    assert of(_url(f"https://a.example/?password={value}"), "N8D101") == []


def test_a_working_directory_is_no_password() -> None:
    assert of(_url("https://a.example/run?pwd=/home/app/data"), "N8D101") == []


@pytest.mark.parametrize("name", ["token", "api_key", "client_secret", "access_token"])
def test_token_and_key_names_still_stop_at_punctuation(name: str) -> None:
    value = "Zq7Lm2Xp9Rt4Vw8Ny3Kb"
    assert redact(f"see https://a.example/?{name}={value}.") == f"see https://a.example/?{name}=***."
    assert redact(f"(https://a.example/?{name}={value})") == f"(https://a.example/?{name}=***)"


@pytest.mark.parametrize(
    "command",
    [
        "nuclei -u https://example.com",
        "sqlmap -u https://example.com/a?id=1 --batch",
        "ffuf -u https://example.com/FUZZ -w words.txt",
        "gobuster dir -u https://example.com -w words.txt",
        "httpx -u https://example.com",
        "docker run -u node:node1234 alpine",
        "curl https://a.example; nuclei -u http://target.example",
        "curl -u https://example.com",
    ],
)
def test_other_tools_u_flag_is_no_curl_password(command: str) -> None:
    assert of(_command(command), "N8D101") == []


@pytest.mark.parametrize(
    "command",
    [
        "curl -u admin:Secret123 https://a.example",
        "curl --user=admin:Secret123 https://a.example",
        '/usr/bin/curl -H "Content-Type: application/json; charset=utf-8" -u admin:Secret123 https://a.example',
        'curl "https://a.example/x?a=1&b=2" -u admin:Secret123',
        "curl https://a.example/x?a=1&b=2 -u admin:Secret123",
        "curl -sS \\\n  -d '{\n \"a\": 1\n}' \\\n  -u admin:Secret123 https://a.example",
    ],
)
def test_curl_passwords_are_still_found(command: str) -> None:
    found = of(_command(command), "N8D101")
    assert len(found) == 1 and "a password in a curl command" in found[0].message


def test_atlassian_no_check_is_a_fixed_value() -> None:
    for name in ("X-Atlassian-Token", "x-atlassian-token"):
        assert of(_header(name, "no-check"), "N8D101") == []
    assert of(_header("X-Figma-Token", "no-check1"), "N8D101")


@pytest.mark.parametrize("name", ["fromToken", "toToken", "baseToken", "quoteToken", "from_token", "to-token", "base_token_address", "quoteTokenAddress"])
@pytest.mark.parametrize("value", [SOL, EVM])
def test_token_addresses_are_public(name: str, value: str) -> None:
    assert of(_header(name, value), "N8D101") == []
    body = {"url": "https://a.example", "sendBody": True, "contentType": "json", "specifyBody": "json", "jsonBody": f'{{"{name}": "{value}"}}'}
    assert of(workflow([node("H", "httpRequest", body, 4)]), "N8D101") == []
    assert of(workflow([node("C", "code", {"jsCode": f'const {name.replace("-", "_")} = "{value}";'}, 2)]), "N8D101") == []


def test_a_key_in_a_token_field_still_counts() -> None:
    assert of(_header("toToken", "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cF"), "N8D101")


def _expression_flow(expression: str) -> dict[str, object]:
    return workflow([trigger(), node("S", "set", {"text": expression}, 3)], link("Start", "S"))


@pytest.mark.parametrize(
    "expression",
    [
        """={{ "<script>$('title').text()</script>" }}""",
        """={{ '<b>' + "$('title')" }}""",
        """={{ `$('title')` }}""",
        """={{ /* $('title') */ 1 }}""",
    ],
)
def test_text_in_an_expression_is_no_reference(expression: str) -> None:
    assert of(_expression_flow(expression), "N8D207") == []


@pytest.mark.parametrize(
    "expression",
    [
        "={{ $('Gone').item.json.a }}",
        """={{ "a" + $('Gone').item.json.a + "b" }}""",
        """={{ `x ${$('Gone').item.json.a} y` }}""",
        """={{ $json.q === "it's" ? $("Gone").first().json.a : 'n' }}""",
        """=text {{ $('Gone').item.json.a }} it's""",
    ],
)
def test_a_reference_in_an_expression_still_counts(expression: str) -> None:
    assert len(of(_expression_flow(expression), "N8D207")) == 1


def _http(**settings: object) -> dict[str, object]:
    return workflow([trigger(), {**node("H", "httpRequest", {"url": "https://a.example"}, 4.2), **settings}], link("Start", "H"))


def test_retry_fix_adds_only_what_is_missing() -> None:
    result = fix_workflow(load(_http(maxTries=5)), {"N8D303"})
    raw = result.fixed["nodes"][1]
    assert (raw["retryOnFail"], raw["maxTries"], raw["waitBetweenTries"]) == (True, 5, 1000)
    assert sorted(p["path"].rsplit("/", 1)[1] for p in result.patch) == ["retryOnFail", "waitBetweenTries"]
    assert result.changes == ['N8D303 "H": retry on fail, 1000 ms apart (GET)']

    raw = fix_workflow(load(_http(waitBetweenTries=2500)), {"N8D303"}).fixed["nodes"][1]
    assert (raw["retryOnFail"], raw["maxTries"], raw["waitBetweenTries"]) == (True, 3, 2500)


def test_retry_fix_on_a_new_node_is_unchanged() -> None:
    assert fix_workflow(load(_http()), {"N8D303"}).changes == ['N8D303 "H": retry on fail, 3 tries, 1000 ms apart (GET)']


def test_explicit_retry_off_is_the_users_choice() -> None:
    found = of(_http(retryOnFail=False, maxTries=5), "N8D303")
    assert len(found) == 1 and not found[0].fixable
    result = fix_workflow(load(_http(retryOnFail=False, maxTries=5)), {"N8D303"})
    assert result.changes == [] and result.patch == []
    assert result.fixed["nodes"][1]["retryOnFail"] is False and result.fixed["nodes"][1]["maxTries"] == 5


@pytest.mark.parametrize("name", ["password", "db_password", "passwd", "pwd", "dbPass", "passphrase", "--password"])
def test_long_password_values_show_no_prefix_under_a_name(name: str) -> None:
    value = "Hx7!Purple-Monkey-Dish-42"
    for found in (of(_header(name, value), "N8D101"), of(_command(f'FOO={value} mytool {name} "{value}"'), "N8D101")):
        for finding in found:
            assert value[:4] not in finding.message
            assert "***" in finding.message
    assert of(_header(name, value), "N8D101")


@pytest.mark.parametrize(
    "flow",
    [
        _url("https://a.example/?password=Hx7!Purple-Monkey-Dish-42"),
        _url("https://u:Hx7!Purple-Monkey-Dish-42@a.example/"),
        _command("curl -u admin:Hx7!Purple-Monkey-Dish-42 https://a.example"),
        _command("mysql 'Server=db;Password=Hx7!Purple-Monkey-Dish-42;'"),
        workflow([node("C", "code", {"jsCode": 'const password = "Hx7!Purple-Monkey-Dish-42";'}, 2)]),
        workflow([node("N", "stickyNote", {"content": "password: Hx7!Purple-Monkey-Dish-42"})]),
        workflow([node("N", "stickyNote", {"content": "pass: Hx7!Purple-Monkey-Dish-42"})]),
    ],
)
def test_long_passwords_show_no_prefix_on_any_route(flow: dict[str, object]) -> None:
    found = of(flow, "N8D101")
    assert found
    assert all("Hx7!" not in f.message and "*** (" in f.message for f in found)


def test_long_tokens_keep_their_prefix() -> None:
    found = of(_header("X-Api-Key", "Zq7Lm2Xp9Rt4Vw8Ny3Kb1234"), "N8D101")
    assert found[0].message.endswith("Zq7L... (24 chars)")
