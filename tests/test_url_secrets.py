"""Secret names in URL query strings, and short passwords in URLs and curl -u."""

from __future__ import annotations

import pytest

from n8n_doctor.rules import known_secrets

from .conftest import load, node, of, workflow

STRONG = "Zq7Lm2Xp9Rt4Vw8Ny3Kb"


def _url(url: str) -> dict[str, object]:
    return workflow([node("H", "httpRequest", {"url": url}, 4)])


def _command(command: str) -> dict[str, object]:
    return workflow([node("E", "executeCommand", {"command": command})])


@pytest.mark.parametrize(
    "name",
    [
        "api_secret",
        "app_secret",
        "shared_secret",
        "webhook_secret",
        "signing_secret",
        "secret_token",
        "oauth_token",
        "bot_token",
        "app_key",
        "appkey",
        "license_key",
        "my_api_key",
        "rapidapi-key",
    ],
)
@pytest.mark.parametrize("value", [STRONG, "abc12345"])
def test_secret_names_in_a_query_string(name: str, value: str) -> None:
    data = _url(f"https://a.io/x?q=1&{name}={value}")
    assert of(data, "N8D101"), name
    assert value in known_secrets(load(data))


@pytest.mark.parametrize("name", ["next_token", "nextToken", "page_token", "pageToken", "next_page_token", "continuation_token", "prev_page_token"])
def test_paging_names_stay_quiet(name: str) -> None:
    assert not of(_url(f"https://a.io/x?{name}={STRONG}"), "N8D101")


@pytest.mark.parametrize("name", ["sort_key", "user_key_name", "partition_key", "group_auth"])
def test_weak_names_with_plain_values_stay_quiet(name: str) -> None:
    assert not of(_url(f"https://a.io/x?{name}=created_at_desc"), "N8D101")


def test_weak_name_with_a_generated_value_is_reported() -> None:
    assert of(_url(f"https://a.io/x?sort_key={STRONG}"), "N8D101")


@pytest.mark.parametrize(
    "url",
    [
        "postgres://admin:admin@db",
        "mysql://root:hunter2@db",
        "mongodb+srv://bob:Zq7Kp2@cluster0.x.mongodb.net/app",
        "https://bob:hunter2@a.io",
        "redis://u:abcd@cache:6379",
    ],
)
def test_short_passwords_in_urls_are_reported(url: str) -> None:
    assert of(_url(url), "N8D101"), url


@pytest.mark.parametrize(
    "url",
    [
        "postgres://user:password@host/db",
        "postgres://user:pass@host/db",
        "postgres://user:<password>@host/db",
        "postgres://user:PASSWORD@host/db",
        "postgres://user:your_password@host/db",
        "postgres://user:xxxx@host/db",
        "postgres://user:****@host/db",
        "postgres://user:$DB_PASS@host/db",
        "postgres://user:[password]@host/db",
        "https://example.com:8080/path@v1",
        "https://a.io/x?email=a:b@c.io",
        "postgres://user:%s@host/db",
        "http://td-customer-username:user@example.com:9999",
        "ftp://admin:hunter2@example.com/files",
    ],
)
def test_placeholders_in_urls_stay_quiet(url: str) -> None:
    assert not of(_url(url), "N8D101"), url


@pytest.mark.parametrize(
    "command",
    [
        "curl -u bob:hunter2 https://a.io",
        "curl --user bob:hunter2 https://a.io",
        "curl --user=bob:hunter2 https://a.io",
        "curl -X POST \\\n  -u bob:abcd https://a.io",
        "git clone https://bob:hunter2@github.com/a/b.git",
    ],
)
def test_short_passwords_in_commands_are_reported(command: str) -> None:
    assert of(_command(command), "N8D101"), command


@pytest.mark.parametrize(
    "command",
    [
        "curl -u user:password https://a.io",
        "curl -u user:pass https://a.io",
        "curl -u bob:<password> https://a.io",
        "curl -u $USER:$PASS https://a.io",
        "docker run -u 1000:1000 alpine",
        "docker run -u node:node alpine",
        "git clone https://user:password@github.com/a/b.git",
    ],
)
def test_placeholders_and_other_tools_in_commands_stay_quiet(command: str) -> None:
    assert not of(_command(command), "N8D101"), command


@pytest.mark.parametrize("url", ["https://a.io/x?pwd=abcd", "https://a.io/x?a=1&pwd=hunter2"])
def test_a_short_pwd_in_a_query_string_is_reported(url: str) -> None:
    assert of(_url(url), "N8D101")


def test_a_folder_in_pwd_is_quiet() -> None:
    assert not of(_url("https://a.io/x?pwd=/tmp"), "N8D101")
