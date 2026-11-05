"""Base64 secrets with slashes, Basic credentials in code, key names holding field names, signed URLs in pinned data."""

from __future__ import annotations

import base64
import json
import random
import string
from typing import Any

import pytest

from n8n_doctor.fix import fix_workflow
from n8n_doctor.model import Severity
from n8n_doctor.rules import _placeholder, _random_looking, known_secrets, redact
from n8n_doctor.workflow import from_data

from .conftest import findings, load, node, of, trigger, workflow

AWS = "wJalrXUtnFEMI/K7MDENGbPxRfiCYq8Zt2LmvXyA"
BASE64_ALPHABET = string.ascii_letters + string.digits + "+/"


def _code(code: str) -> dict[str, Any]:
    return workflow([node("C", "code", {"jsCode": code}, 2)])


def _set(name: str, value: str) -> dict[str, Any]:
    assignment = {"id": "1", "name": name, "value": value, "type": "string"}
    return workflow([node("S", "set", {"assignments": {"assignments": [assignment]}}, 3.4)])


@pytest.mark.parametrize(
    "code",
    [
        f"const AWS_SECRET_ACCESS_KEY='{AWS}';",
        f"const apiKey='{AWS}';",
        f"const secret='{AWS}';",
        f"return {{secretAccessKey:'{AWS}'}};",
        "const OPENAI_KEY='aB3+dE6/gH9jK2mN5pQ8sT1vW4yZ7cF0';",
    ],
)
def test_base64_secrets_with_slashes_in_code(code: str) -> None:
    wf = _code(code)
    assert of(wf, "N8D101"), code
    assert known_secrets(load(wf))


def test_base64_secret_with_a_slash_in_a_set_field() -> None:
    assert of(_set("AWS_SECRET_ACCESS_KEY", AWS), "N8D101")


def test_nearly_all_random_base64_counts() -> None:
    rng = random.Random(21)
    values = ["".join(rng.choices(BASE64_ALPHABET, k=40)) for _ in range(2000)]
    assert sum(_random_looking(v) for v in values) >= 1980


@pytest.mark.parametrize(
    "value",
    [
        "application/json",
        "application/vnd.api+json",
        "application/x-www-form-urlencoded",
        "image/png",
        "image/svg+xml",
        "video/mp4",
        "/usr/local/bin",
        "/usr/local/lib/python3/site-packages",
        "/opt/n8n/Zq7Lm2Xp9Rt4Vw8Ny3Kb",
        "/home/App2/Data2024/Reports2025/Keys",
        "src/components/Button2/IndexPage",
        "Reports2024/FinalDraft2/Summary1",
        "drive/folders/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74",
        "https://a.io/x/Zq7Lm2Xp9Rt4Vw8Ny3Kb",
        "//cdn.a.io/Zq7Lm2Xp9Rt4Vw8Ny3Kb",
        "a7/Zq7L",
        "2024/01/15",
        "plain text/Zq7Lm2Xp9Rt4Vw8Ny3Kb and more",
    ],
)
def test_paths_urls_and_mime_types_are_not_random(value: str) -> None:
    assert not _random_looking(value)
    assert not of(_code(f"const contentKey2='{value}'; const apiKey='{value}';"), "N8D101")


@pytest.mark.parametrize(
    "code",
    [
        "const h = Buffer.from('admin:SuperSecret9').toString('base64');",
        'const h = Buffer.from("admin:SuperSecret9", "utf8").toString("base64");',
        "const h = btoa('admin:SuperSecret9');",
        "const h = `Basic ${btoa('admin:SuperSecret9')}`;",
        "const h = btoa(':SuperSecret9');",
        "const h = btoa('admin:hunter2');",
        "const h = btoa('admin:admin');",
    ],
)
def test_literal_credentials_being_encoded(code: str) -> None:
    wf = _code(code)
    secret = code.split(":")[1].split("'")[0].split('"')[0]
    messages = " ".join(f.message for f in of(wf, "N8D101"))
    assert messages and secret not in messages
    assert secret in known_secrets(load(wf))


@pytest.mark.parametrize("name", ["auth", "h", "basicHeader"])
def test_encoded_basic_header_in_any_variable(name: str) -> None:
    encoded = base64.b64encode(b"admin:SuperSecret9").decode()
    wf = _code(f"const {name}='Basic {encoded}';")
    messages = " ".join(f.message for f in of(wf, "N8D101"))
    assert messages and encoded not in messages
    assert encoded in known_secrets(load(wf))


@pytest.mark.parametrize(
    "code",
    [
        "Buffer.from(someVar).toString('base64');",
        "Buffer.from(user + ':' + pass).toString('base64');",
        "Buffer.from('hello world').toString('base64');",
        "Buffer.from('hello').toString('base64');",
        "Buffer.from('user:' + pass).toString('base64');",
        "Buffer.from(`${user}:${pass}`).toString('base64');",
        "Buffer.from('key:value').toString('base64');",
        "Buffer.from('foo:bar').toString('base64');",
        "Buffer.from('user:password').toString('base64');",
        "Buffer.from('YOUR_USER:YOUR_PASSWORD').toString('base64');",
        "Buffer.from('10:30:00').toString('base64');",
        "Buffer.from('https://a.io/Zq7L9').toString('base64');",
        "Buffer.from('data:image/png;base64,iVBORw0KGgo').toString('base64');",
        "btoa('status:active');",
        "btoa('role:admin');",
        "btoa('type:imageFile');",
        "btoa('2024-01-01T10:30:00Z');",
        "btoa(input);",
        "const t='Basic information';",
        "const t='Basic Authentication';",
        "const t='Basic SGVsbG8gdGhlcmU=';",  # no colon once decoded
        f"const t='Basic {base64.b64encode(b'user:your_password').decode()}';",
    ],
)
def test_other_text_being_encoded_stays_quiet(code: str) -> None:
    assert not of(_code(code), "N8D101"), code


@pytest.mark.parametrize(
    "code",
    [
        "const m = {promptKey:'imagePrompt2'};",
        "const COUNTRY_KEY='countryCode2';",
        "const m = {outputKey:'final_result_v2'};",
        "const m = {columnKey:'customerName123'};",
        "const m = {labelKey:'Image-Prompt-2'};",
    ],
)
def test_key_names_holding_field_names_stay_quiet(code: str) -> None:
    assert not of(_code(code), "N8D101"), code


@pytest.mark.parametrize(
    "code",
    [
        "const OPENWEATHER_KEY='9f8e7d6c5b4a39281706f5e4d3c2b1a0';",
        "const OPENWEATHER_KEY='a3f09c7e12b84d6fa0e15c9b7d3248ce';",
        "const consumerKey='Zq7Lm2Xp9Rt4Vw8Ny3Kb';",
        "const WEATHER_KEY='kq7xz2mvp9rt4wn8yb3cdf6h';",
    ],
)
def test_key_names_holding_generated_values_are_reported(code: str) -> None:
    assert of(_code(code), "N8D101"), code


def _duplicates(nodes: list[dict[str, Any]]) -> list[str]:
    return [f.message for f in of(workflow(nodes), "N8D206")]


def test_duplicate_names_leave_out_sticky_notes() -> None:
    assert not _duplicates([trigger(), node("Note", "stickyNote"), node("Note", "stickyNote")])
    assert not _duplicates([trigger(), node("Same", "stickyNote"), node("Same", "set")])
    assert _duplicates([trigger(), node("Same", "set"), node("Same", "set")]) == ['2 nodes are named "Same"']


def test_duplicate_names_report_a_real_node_when_a_note_shares_the_name() -> None:
    data = workflow([trigger(), node("Same", "stickyNote"), node("Same", "set"), node("Same", "set")])
    found = of(data, "N8D206")
    assert [f.message for f in found] == ['2 nodes are named "Same"']
    assert found[0].node_type == "n8n-nodes-base.set"


SIGNATURE = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"


def _pinned(urls: dict[str, list[str]]) -> dict[str, Any]:
    pin = {name: [{"json": {"url": u}} for u in items] for name, items in urls.items()}
    return workflow([trigger(), node("Read", "set"), node("Other", "set")], pinData=pin)


def _signed(i: int, name: str = "X-Amz-Signature") -> str:
    return f"https://b.s3.amazonaws.com/f{i}.png?X-Amz-Date=20250101T000000Z&{name}={SIGNATURE[:-2]}{i:02d}"


@pytest.mark.parametrize("name", ["X-Amz-Signature", "x-amz-signature", "signature", "sig"])
def test_signed_urls_in_pinned_data_are_one_warning_per_node(name: str) -> None:
    urls = {"Read": [_signed(i, name) for i in range(30)], "Other": [_signed(90, name)]}
    found = of(_pinned(urls), "N8D101")
    assert sorted((f.node or "", f.severity) for f in found) == [("Other", Severity.WARNING), ("Read", Severity.WARNING)]
    text = json.dumps([[f.message, f.fix_hint] for f in found])
    assert "N8D211" in text and SIGNATURE[:-2] not in text
    assert "30 signed URLs" in text and "1 signed URL:" in text


def test_signed_urls_are_masked_in_free_text() -> None:
    assert SIGNATURE[:-2] not in redact(_signed(1))


def test_fix_does_not_show_signed_urls() -> None:
    wf = from_data(_pinned({"Read": [_signed(1)]}), "test.json")[0]
    result = fix_workflow(wf)
    assert SIGNATURE[:-2] not in result.diff + " ".join(result.changes)
    assert result.fixed["pinData"] == {}


def test_credentials_in_pinned_data_stay_errors_beside_signatures() -> None:
    url = _signed(1) + "&X-Amz-Credential=ASIAIOSFODNN7ABCDEFG%2F20250101"
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3lN6"
    data = _pinned({"Read": [url, token]})
    found = of(data, "N8D101")
    assert sorted(f.severity for f in found) == [Severity.WARNING, Severity.ERROR, Severity.ERROR]
    assert not any("ASIAIOSFODNN7ABCDEFG" in f.message or token in f.message for f in found)


def test_allow_list_covers_signed_urls() -> None:
    from n8n_doctor.config import Config

    cfg = Config(options={"N8D101": {"allow": ["9f8e7d6c"]}})
    assert not [f for f in findings(_pinned({"Read": [_signed(1)]}), cfg) if f.rule.id == "N8D101"]


def test_signature_parameters_outside_pinned_data_stay_errors() -> None:
    wf = workflow([node("H", "httpRequest", {"url": _signed(1)}, 4)])
    assert [f.severity for f in of(wf, "N8D101")] == [Severity.ERROR]


@pytest.mark.parametrize("value", ["CHANGE_ME_TO_A_LONG_RANDOM_SECRET_32+_CHARS", "change-me-32+", "CHANGE_ME_12+_CHARS"])
def test_change_me_with_a_length_hint_is_a_placeholder(value: str) -> None:
    assert _placeholder(value)
    assert not of(_code(f"const secret='{value}';"), "N8D101")


@pytest.mark.parametrize("value", ["CHANGE_ME_Pass+word1", "change_me+Zq7Lm2Xp9", "x+change_me"])
def test_plus_inside_a_word_is_no_length_hint(value: str) -> None:
    assert not _placeholder(value)
