"""What a name = 'value' pair in code is not: a ternary, a status word, a selector, a validation rule, a message."""

from __future__ import annotations

import pytest

from .conftest import node, of, workflow


def _code(text: str) -> list[object]:
    return list(of(workflow([node("C", "code", {"jsCode": text}, 2)]), "N8D101"))


@pytest.mark.parametrize(
    "text",
    [
        "const s = ok ? 'pass' : 'fail';",
        "const s = ok\n  ? 'pass'\n  : 'fail';",
        "const s = ok ? pass : 'fail';",
        "const f = isEmail ? 'password' : 'email';",
        "const colors = {pass:'green',fail:'red'};",
        "const css = {pass:'#00ff00'};",
        "const f = {password:'#pwd'};",
        "const f = {password:'.pw-input'};",
        "const f = {password:'#login-password'};",
        "const f = {password:'input[name=pw]'};",
        "errors.password='Invalid';",
        "errors.password = 'Required';",
        "const r = {password:'required|min:8'};",
        "const r = {password:'string|min:8|max:64'};",
        "const r = {password:'min:8'};",
        "const l = {password:'Пароль'};",
        "const l = {password:'Contraseña'};",
        "const l = {password:'密码'};",
        "const l = {password:'Passwort'};",
        "errors.password = 'Must have 8 letters';",
        "errors['password'] = 'Too short';",
        "const w = {password:'missing'};",
        "let db_pass = 'green';",
    ],
)
def test_ordinary_javascript_is_quiet(text: str) -> None:
    assert not _code(text)


@pytest.mark.parametrize(
    "text",
    [
        "const password = 'hunter2';",
        "const c = {password: 'admin123'};",
        "const DB_PASSWORD = 'S3cur3-Pa55';",
        "const c = {password: 'admin'};",
        "const c = {password: 'qwerty'};",
        "const c = {password: '1234'};",
        "const c = {pass: 'Zq7Kp2xw'};",
        "const pass = 'hunter2';",
        "let db_pass = 'S3cur3-Pa55';",
        "const c = {password: '#Hunter2'};",
        "const c = {password: 'пароль123'};",
        "const u = cond ? other : password = 'hunter2';",
    ],
)
def test_real_passwords_in_code_stay_reported(text: str) -> None:
    assert _code(text)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("password_auth", "enabled"),
        ("password_auth", "basic"),
        ("password_protected", "yes"),
        ("password_valid", "nope"),
        ("password_count", "many"),
        ("qa_pass", "approved"),
        ("all_pass", "approved"),
        ("all_pass", "Hunter99"),
    ],
)
def test_descriptive_names_with_plain_values_are_quiet(name: str, value: str) -> None:
    data = workflow([node("H", "set", {"assignments": {"assignments": [{"id": "1", "name": name, "value": value, "type": "string"}]}}, 3.4)])
    assert not of(data, "N8D101")


def test_a_described_password_that_looks_generated_is_still_reported() -> None:
    data = workflow(
        [node("H", "set", {"assignments": {"assignments": [{"id": "1", "name": "password_auth", "value": "Zq7Lm2Xp9Rt4Vw8Ny3Kb", "type": "string"}]}}, 3.4)]
    )
    assert of(data, "N8D101")


def test_qa_pass_with_a_password_is_still_reported() -> None:
    data = workflow([node("H", "set", {"assignments": {"assignments": [{"id": "1", "name": "qa_pass", "value": "hunter2", "type": "string"}]}}, 3.4)])
    assert of(data, "N8D101")


_GENERATED = "a8f3k2l9x7q1m5z0"


@pytest.mark.parametrize("name", ["OPENWEATHER_KEY", "OPENAI_KEY", "MY_APP_KEY", "consumerKey", "stripeKey"])
def test_secret_suffixed_names_with_a_generated_value(name: str) -> None:
    assert _code(f"const {name} = '{_GENERATED}';")
    assert _code(f"const o = {{{name}: '{_GENERATED}'}};")


@pytest.mark.parametrize("value", ["created_at", "user-profile", "abc12345", "YOUR_KEY_HERE", "uploads/2024/a1b2c3d4e5f6.png"])
@pytest.mark.parametrize("name", ["OPENWEATHER_KEY", "consumerKey"])
def test_secret_suffixed_names_need_a_generated_value(name: str, value: str) -> None:
    assert _code(f"const {name} = '{value}';") == []


@pytest.mark.parametrize(
    "name",
    [
        "sort_key",
        "cacheKey",
        "primaryKey",
        "publicKey",
        "sortKey",
        "CACHE_KEY",
        "SORT_KEY",
        "PUBLIC_KEY",
        "PRIMARY_KEY",
        "fileKey",
        "s3Key",
        "objectKey",
        "partitionKey",
        "idempotencyKey",
        "siteKey",
        "Key",
        "KEY",
        "monkey",
        "MONKEY",
    ],
)
def test_other_key_names_stay_quiet(name: str) -> None:
    assert _code(f"const {name} = '{_GENERATED}';") == []
