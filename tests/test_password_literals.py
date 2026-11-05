"""Short passwords in password-named fields, password flags in commands, and the values that say nothing."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from n8n_doctor.rules import _placeholder, known_secrets

from .conftest import load, node, of, workflow

REPORTED = ["hunter2", "admin", "1234", "qwerty"]
QUIET = [
    "required",
    "optional",
    "none",
    "null",
    "undefined",
    "true",
    "false",
    "string",
    "plaintext",
    "password",
    "Password",
    "={{ $json.pw }}",
    "{{ $json.pw }}",
]


def _entries(field: str, name: str, value: str) -> dict[str, Any]:
    return {f"{field}Parameters": {"parameters": [{"name": name, "value": value}]}}


SHAPES: dict[str, Any] = {
    "header": lambda name, value: node("H", "httpRequest", _entries("header", name, value), 4),
    "body": lambda name, value: node("H", "httpRequest", _entries("body", name, value), 4),
    "query": lambda name, value: node("H", "httpRequest", _entries("query", name, value), 4),
    "set": lambda name, value: node("H", "set", {"assignments": {"assignments": [{"id": "1", "name": name, "value": value, "type": "string"}]}}, 3.4),
    "set_old": lambda name, value: node("H", "set", {"values": {"string": [{"name": name, "value": value}]}}, 2),
    "json_body": lambda name, value: node("H", "httpRequest", {"jsonBody": json.dumps({name: value})}, 4),
    "plain": lambda name, value: node("H", "someService", {name: value}, 1),
    "code": lambda name, value: node("H", "code", {"jsCode": f"const c = {{ {name}: {json.dumps(value)} }};"}, 2),
    "python": lambda name, value: node("H", "code", {"language": "python", "pythonCode": f"{name} = {json.dumps(value)}"}, 2),
}


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("value", REPORTED)
def test_short_literal_of_a_password_field_is_reported(shape: str, value: str) -> None:
    data = workflow([SHAPES[shape]("password", value)])
    assert of(data, "N8D101"), (shape, value)
    assert value in known_secrets(load(data))


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("value", QUIET)
def test_non_values_of_a_password_field_are_quiet(shape: str, value: str) -> None:
    if "{{" in value and shape in ("code", "python", "json_body"):
        return  # no expression there
    assert of(workflow([SHAPES[shape]("password", value)]), "N8D101") == [], (shape, value)


@pytest.mark.parametrize("name", ["db_password", "userPassword", "X-Db-Password", "passwd"])
def test_prefixed_names_count(name: str) -> None:
    assert of(workflow([node("H", "httpRequest", _entries("header", name, "admin"), 4)]), "N8D101")


@pytest.mark.parametrize("name", ["api_key", "token", "secret", "key"])
def test_generic_names_keep_their_length_limit(name: str) -> None:
    assert of(workflow([node("H", "someService", {name: "admin"}, 1)]), "N8D101") == []
    assert of(workflow([node("H", "code", {"jsCode": f"const {name} = 'admin';"}, 2)]), "N8D101") == []


def test_three_characters_stay_quiet() -> None:
    assert of(workflow([node("H", "someService", {"password": "abc"}, 1)]), "N8D101") == []


def test_query_string_short_password() -> None:
    assert of(workflow([node("H", "httpRequest", {"url": "https://x.io/login?user=a&password=admin"}, 4)]), "N8D101")
    assert of(workflow([node("H", "httpRequest", {"url": "https://x.io/login?require_password=true"}, 4)]), "N8D101") == []
    assert of(workflow([node("H", "httpRequest", {"url": "https://x.io/login?password=required"}, 4)]), "N8D101") == []


def test_placeholder_in_a_password_field_is_quiet() -> None:
    for value in ("YOUR_PASSWORD", "<password>", "changeme", "****"):
        assert of(workflow([node("H", "someService", {"password": value}, 1)]), "N8D101") == [], value


def test_comparison_in_code_is_no_assignment() -> None:
    assert of(workflow([node("H", "code", {"jsCode": "if (password === 'admin') { return []; }"}, 2)]), "N8D101") == []


def _command(text: str, type_: str = "executeCommand") -> list[str]:
    data = workflow([node("Run", type_, {"command": text}, 1)])
    return [f.message for f in of(data, "N8D101")]


@pytest.mark.parametrize(
    ("command", "secret"),
    [
        ("mysql -u root --password=s3cret db", "s3cret"),
        ("mysql -u root -ps3cret db", "s3cret"),
        ("mysqldump -uroot -p's3 cret!' db > out.sql", "s3 cret!"),
        ('docker exec db sh -c "mysql -uroot -ps3cret"', "s3cret"),
        ("/usr/bin/mariadb -uroot -ps3cret", "s3cret"),
        ("sshpass -p s3cret ssh me@host", "s3cret"),
        ("sshpass -ps3cret ssh -p 2222 me@host", "s3cret"),
        ("sshpass -v -p 's3cret' ssh me@host", "s3cret"),
        ("wget --password=s3cret https://x.io/a", "s3cret"),
        ("wget --http-password=s3cret https://x.io/a", "s3cret"),
        ("docker login -p s3cret reg.io", "s3cret"),
        ("docker login -u me -p s3cret reg.io", "s3cret"),
        ("docker login --username me --password s3cret", "s3cret"),
        ("redis-cli -h db -a s3cret ping", "s3cret"),
        ("ssh --password=s3cret me@host", "s3cret"),
    ],
)
def test_password_flags_are_reported_and_masked(command: str, secret: str) -> None:
    assert _command(command), command
    assert _command(command, "ssh"), command
    data = workflow([node("Run", "executeCommand", {"command": command}, 1)])
    assert secret in known_secrets(load(data))
    assert secret not in json.dumps([f.message for f in of(data, "N8D101")])


@pytest.mark.parametrize(
    "command",
    [
        "mkdir -p /tmp/out",
        "mkdir -pv out",
        "ssh -p 22 me@host",
        "ssh -p 2222 me@host uptime",
        "scp -P 2222 a me@host:b",
        "sshpass -e ssh -p 2222 me@host",
        "sshpass -f pw.txt ssh -p 2222 me@host",
        "mysql -p db",
        "mysql -u root -p mydb",
        "mysql -P 3306 -h db",
        "mysql -e 'select 1' && mkdir -pout",
        "psql --no-password mydb",
        "ansible-playbook --ask-pass site.yml",
        "docker login --password-stdin reg.io",
        "docker run -p 8080:80 nginx",
        "docker login reg.io && docker run -p 8080:80 nginx",
        "redis-cli -p 6379 ping",
        "ls -a /tmp/backup",
        "tar -a -cf out.tgz dir",
        "curl -p https://x.io",
        "mysql --password=$MYSQL_PWD db",
        'mysql --password="$MYSQL_PWD" db',
        "mysql -p$MYSQL_PWD db",
        'mysql -p"$MYSQL_PWD" db',
        "sshpass -p $PW ssh me@host",
        'sshpass -p "${PW}" ssh me@host',
        "docker login -p $(cat pw) reg.io",
        "wget --password=`cat pw` https://x.io",
        "mysql --password={{ $json.pw }} db",
        "={{ 'mysql --password=' + $json.pw }}",
        "mysql --password=<password> db",
        "wget --password=required https://x.io",
    ],
)
def test_ordinary_flags_and_expressions_are_quiet(command: str) -> None:
    assert _command(command) == [], command


@pytest.mark.parametrize("name", ["bypass", "compass", "trespass", "encompass", "Bypass", "COMPASS", "ByPass"])
def test_words_ending_in_pass_are_no_password_names(name: str) -> None:
    data = workflow([node("C", "code", {"jsCode": f"const {name} = 'a1b2c3d4e5f6g7h8';"}, 2)])
    assert of(data, "N8D101") == [], name


@pytest.mark.parametrize("name", ["dbPass", "db_pass", "db-pass", "pass", "DB_PASS", "ftpPass"])
def test_pass_as_its_own_word_counts(name: str) -> None:
    data = workflow([node("C", "code", {"jsCode": f"const c = {{ {json.dumps(name)}: 'hunter2hunter' }};"}, 2)])
    assert of(data, "N8D101"), name


@pytest.mark.parametrize(
    "value",
    ["REDACTED", "redacted", "PASTE_YOUR_NIXGUARD_API_KEY_HERE", "paste-your-custom-license-here", "Paste your thing here", "undefined", "required"],
)
def test_placeholders(value: str) -> None:
    assert _placeholder(value)
    assert of(workflow([node("H", "someService", {"apiKey": value}, 1)]), "N8D101") == []
    assert of(workflow([node("H", "httpRequest", _entries("header", "X-Api-Key", value), 4)]), "N8D101") == []


@pytest.mark.parametrize(
    "value",
    ["REDACTED-prod-99x", "PASTEYOURKEYHERE9", "pasta-your-key-here", "requiredPass1", "undefined2"],
)
def test_real_values_near_placeholders_are_reported(value: str) -> None:
    assert not _placeholder(value)
    assert of(workflow([node("H", "someService", {"password": value}, 1)]), "N8D101")


@pytest.mark.parametrize("note", ["(token: your_api_key_here)", "(password: required)", "see (api key: REDACTED)", "(password: <password>)"])
def test_sticky_values_with_a_closing_bracket(note: str) -> None:
    assert of(workflow([node("N", "stickyNote", {"content": note}, 1)]), "N8D101") == [], note


def test_sticky_value_with_a_closing_bracket_is_reported_without_it() -> None:
    data = workflow([node("N", "stickyNote", {"content": "the login (password: hunter2)"}, 1)])
    assert of(data, "N8D101")
    assert "hunter2" in known_secrets(load(data))
    assert "hunter2)" not in known_secrets(load(data))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("password_created_at", "2024-01-15T10:00:00Z"),
        ("password_created_at", "2024-01-15"),
        ("passwordCreatedAt", "20240115T100000Z"),
        ("password_format", "plaintext"),
        ("password_format", "bcrypt"),
        ("password_manager", "1Password"),
        ("password_manager", "Bitwarden"),
        ("password", "1Password"),
    ],
)
@pytest.mark.parametrize("shape", ["plain", "body", "json_body", "code"])
def test_descriptive_fields_are_quiet(shape: str, name: str, value: str) -> None:
    assert of(workflow([SHAPES[shape](name, value)]), "N8D101") == [], (shape, name, value)


def test_descriptive_field_with_a_generated_value_is_reported() -> None:
    assert of(workflow([SHAPES["plain"]("password_format", "a1B2c3D4e5F6g7H8")]), "N8D101")


@pytest.mark.parametrize(
    "command",
    [
        "mysql --password mydb",
        "mysql -u root --password mydb",
        "mysqldump --password mydb > out.sql",
        "mariadb --password mydb",
        "psql --password mydb",
        "psql -U bob --password mydb",
        "./run --first-pass out.log",
        "./run --second-pass out.log",
    ],
)
def test_a_flag_followed_by_no_value_is_quiet(command: str) -> None:
    assert not of(workflow([node("E", "executeCommand", {"command": command})]), "N8D101")


@pytest.mark.parametrize(
    "command",
    ["mysql --password=hunter2 mydb", "psql --password=hunter2 mydb", "docker login --password hunter2", "./run --db-pass hunter2", "./run --password hunter2"],
)
def test_a_flag_with_a_value_stays_reported(command: str) -> None:
    assert of(workflow([node("E", "executeCommand", {"command": command})]), "N8D101")


def _basic(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize("pair", ["your_email@domain.com:your_user_api_token", "user:password", "username:<password>", "me:YOUR_API_KEY"])
def test_basic_over_a_placeholder_is_quiet(pair: str) -> None:
    encoded = _basic(pair)
    header = node("H", "httpRequest", {"headerParameters": {"parameters": [{"name": "Authorization", "value": f"Basic {encoded}"}]}}, 4)
    note = node("N", "stickyNote", {"content": f"Authorization: Basic {encoded}"})
    assert not of(workflow([header, note]), "N8D101")


def test_basic_over_real_credentials_stays_reported() -> None:
    header = node("H", "httpRequest", {"headerParameters": {"parameters": [{"name": "Authorization", "value": f"Basic {_basic('bob:hunter2')}"}]}}, 4)
    assert of(workflow([header]), "N8D101")
