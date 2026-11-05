"""What ordinary workflows hold: secrets under ordinary names, node references, fan-out, what fix may change."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import cli, mcp
from n8n_doctor.cli import main
from n8n_doctor.executions import mask_message
from n8n_doctor.fix import fix_workflow
from n8n_doctor.rules import RULES, known_secrets
from n8n_doctor.workflow import WorkflowError, from_data, parse_text

from .conftest import EXAMPLES, link, load, merge, node, of, trigger, workflow

GENERATED = "aB3dE6gH9jK2mN5pQ8sT1vW4"
HOOK = {"path": "a", "responseMode": "responseNode", "authentication": "headerAuth"}


def _entry(name: str, value: str) -> dict[str, Any]:
    return workflow(
        [trigger(), node("H", "httpRequest", {"url": "https://x.example", "headerParameters": {"parameters": [{"name": name, "value": value}]}}, 4.2)]
    )


def _code(text: str) -> dict[str, Any]:
    return workflow([trigger(), node("C", "code", {"jsCode": text}, 2)])


def _param(**params: Any) -> dict[str, Any]:
    return workflow([trigger(), node("H", "httpRequest", {"options": {"timeout": 1}, **params}, 4.2)])


def _secrets(data: dict[str, Any]) -> list[str]:
    return known_secrets(from_data(data, "x.json")[0])


# A1: names that hold a password


@pytest.mark.parametrize(
    "name",
    ["db_password", "SMTP_PASSWORD", "admin_password", "userPassword", "ftp_pass", "X-Password", "Client-Password", "X-Db-Password", "dbPass", "password_old"],
)
def test_prefixed_password_names(name: str) -> None:
    assert of(_entry(name, "Summer2024!"), "N8D101")
    assert "Summer2024!" in _secrets(_entry(name, "Summer2024!"))


@pytest.mark.parametrize(
    "name",
    [
        "bypass",
        "compass",
        "passenger",
        "bypass_token_cache",
        "boarding_pass",
        "ByPass",
        "passwordless",
        "password_policy",
        "passwordField",
        "password_min_length",
        "reset_password_url",
    ],
)
def test_words_that_are_no_password_names(name: str) -> None:
    assert not of(_entry(name, "Summer2024!"), "N8D101")


@pytest.mark.parametrize("name", ["db_password", "smtpPassword"])
def test_json_keys_named_for_a_password(name: str) -> None:
    assert of(_param(jsonBody=json.dumps({name: "hunter2hunter"})), "N8D101")


def test_plain_parameter_named_for_a_password() -> None:
    assert of(_param(db_password="hunter2hunter"), "N8D101")
    assert not of(_param(pwd="/home/app/data"), "N8D101")  # pwd alone can be a folder


def test_code_names_for_a_password() -> None:
    assert of(_code("const db_password_old = 'hunter2hunter';"), "N8D101")
    assert not of(_code("const passwordField = 'input[name=pass]';"), "N8D101")


@pytest.mark.parametrize(
    "message",
    [
        'db_password="hunter2hunter"',
        "SMTP_PASSWORD=hunter2hunter",
        "userPassword: hunter2hunter",
        "ftp_pass=hunter2hunter",
        "X-Password: hunter2hunter",
        '{"smtpPassword": "hunter2hunter"}',
    ],
)
def test_executions_mask_those_names(message: str) -> None:
    assert "hunter2hunter" not in mask_message(message)


def test_executions_leave_other_words() -> None:
    assert mask_message("compass=north") == "compass=north"
    assert mask_message("bypass=north") == "bypass=north"


# A2: Authorization under any scheme word

SCHEMES = ["Bot", "OAuth", "Klaviyo-API-Key", "Zoho-oauthtoken", "SSWS", "GenieKey", "Foo"]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_authorization_header_with_any_scheme(scheme: str) -> None:
    found = of(_entry("Authorization", f"{scheme} {GENERATED}"), "N8D101")
    assert found and scheme not in found[0].message.split("contains")[1]
    assert GENERATED in _secrets(_entry("Authorization", f"{scheme} {GENERATED}"))


@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize(
    "text",
    [
        "const h = {Authorization: '%s'};",
        "const h = {'Authorization': \"%s\"};",
        "h['Authorization'] = '%s';",
        "h.set('Proxy-Authorization', '%s');",
    ],
)
def test_authorization_in_code_with_any_scheme(scheme: str, text: str) -> None:
    data = _code(text % f"{scheme} {GENERATED}")
    assert of(data, "N8D101")
    assert GENERATED in _secrets(data)


def test_authorization_in_json_and_commands() -> None:
    assert of(_param(jsonHeaders=json.dumps({"Authorization": f"Bot {GENERATED}"})), "N8D101")
    command = workflow([trigger(), node("C", "executeCommand", {"command": f"curl -H 'Authorization: SSWS {GENERATED}' https://x.example"})])
    assert of(command, "N8D101")


@pytest.mark.parametrize(
    "value",
    [
        "=Bot {{ $json.token }}",
        "={{ 'OAuth ' + $json.token }}",
        "Bot YOUR_BOT_TOKEN",
        "OAuth <token>",
        "SSWS your-api-token",
        "Bearer",
        "=GenieKey {{ $vars.key }}",
        "=Bearer <token> //move this up",
        "Bearer $(gcloud auth print-access-token)",
        "Bearer <__PLACEHOLDER_VALUE__Your API Key__>",
    ],
)
def test_authorization_exempt_values(value: str) -> None:
    assert not of(_entry("Authorization", value), "N8D101")


def test_authorization_scheme_word_of_an_expression_is_no_secret() -> None:
    assert "OAuth" not in _secrets(_entry("Authorization", "={{ 'OAuth ' + $json.token }}"))
    assert not of(_code("const h = {Authorization: 'Bot ' + token};"), "N8D101")


def test_short_literal_authorization_is_reported() -> None:
    assert of(_entry("Authorization", "Bot abc1"), "N8D101")


# A3: Edit Fields v3.0-3.2 typed values (fields.values[]: stringValue, numberValue, booleanValue, arrayValue, objectValue)


def _fields(entry: dict[str, Any]) -> dict[str, Any]:
    return workflow([trigger(), node("S", "set", {"mode": "manual", "fields": {"values": [entry]}, "options": {}}, 3.2)])


@pytest.mark.parametrize("name", ["password", "apiKey", "db_password"])
def test_string_value_of_edit_fields(name: str) -> None:
    data = _fields({"name": name, "stringValue": "hunter2hunter"})
    assert of(data, "N8D101")
    assert "hunter2hunter" in _secrets(data)


@pytest.mark.parametrize("key", ["arrayValue", "numberValue"])
def test_other_typed_values_in_text_form(key: str) -> None:
    assert of(_fields({"name": "password", key: "hunter2hunter"}), "N8D101")


def test_object_value_of_edit_fields() -> None:
    assert of(_fields({"name": "config", "type": "objectValue", "objectValue": json.dumps({"password": "hunter2hunter"})}), "N8D101")


def test_typed_value_of_a_plain_name_is_no_secret() -> None:
    assert not of(_fields({"name": "city", "stringValue": "hunter2hunter"}), "N8D101")


# A4: URL query names and raw form bodies


@pytest.mark.parametrize(
    "name", ["consumer_secret", "pass", "userPassword", "x-goog-api-key", "auth_key", "authkey", "user_key", "client_key", "sessionToken", "db_password"]
)
def test_query_names(name: str) -> None:
    assert of(_param(url=f"https://x.example/a?x=1&{name}=hunter2hunter"), "N8D101")


def test_query_word_in_a_longer_name_is_not_taken() -> None:
    assert not of(_param(url="https://x.example/a?bypass=hunter2hunter&compass=hunter2hunter"), "N8D101")


@pytest.mark.parametrize("body", ["password=abc&x=1", "x=1&password=abc", "db_password=hunter2hunter&x=1", "token=hunter2hunter&x=1", "=password=abc&x=1"])
def test_raw_form_body(body: str) -> None:
    assert of(_param(method="POST", sendBody=True, contentType="raw", body=body), "N8D101")


@pytest.mark.parametrize(
    "body", ["password={{ $json.p }}&x=1", "x=1&y=2", "name=compass&bypass=abc", "just text with password=abc inside", "password=YOUR_PASSWORD&x=1"]
)
def test_raw_form_body_without_a_secret(body: str) -> None:
    assert not of(_param(method="POST", sendBody=True, contentType="raw", body=body), "N8D101")


# A5: node names are no secrets


@pytest.mark.parametrize(
    "value",
    [
        "=Bearer {{ $('Login').item.json.token }}",
        '=Bearer {{ $("Login").item.json.token }}',
        "=Bearer {{ $node['Login'].json.token }}",
        '=Bearer {{ $node["Login"].json.token }}',
        "=Bearer {{ $items('Login')[0].json.token }}",
        "=Bearer {{ $items('Login', 0, 0)[0].json.token }}",
        "={{ $json['Login'] }}",
        "={{ $('Get').item.json['Login'] }}",
        "={{ $fromAI('Login', 'the Login field', 'string') }}",
    ],
)
def test_references_are_no_secrets(value: str) -> None:
    data = _entry("Authorization", value)
    assert not {"Login", "the Login field"} & set(_secrets(data))
    assert not of(data, "N8D101")


def test_literals_beside_a_reference_still_count() -> None:
    assert "a1B2c3D4e5F6g7H8" in _secrets(_entry("Authorization", "={{ $('Login').item.json.t || 'a1B2c3D4e5F6g7H8' }}"))
    assert "a1B2c3D4e5F6g7H8" in _secrets(_entry("Authorization", "={{ ['a1B2c3D4e5F6g7H8'][0] }}"))
    assert "a1B2c3D4e5F6g7H8" in _secrets(_entry("Authorization", "={{ $ifEmpty($json.t, 'a1B2c3D4e5F6g7H8') }}"))


# A6: fix leaves timeouts alone unless asked


def _http() -> dict[str, Any]:
    return workflow([trigger(), node("H", "httpRequest", {"url": "https://x.example", "method": "POST"}, 4.2)], link("Start", "H"))


def test_timeout_is_reported_but_not_fixed_by_default() -> None:
    wf = load(_http())
    found = of(_http(), "N8D302")
    assert found and not found[0].fixable
    assert not [c for c in fix_workflow(wf).changes if "N8D302" in c]
    assert "timeout" not in fix_workflow(wf).fixed["nodes"][1]["parameters"].get("options", {})


def test_timeout_with_the_opt_in() -> None:
    result = fix_workflow(load(_http()), set_timeout=120000)
    assert result.changes[0] == 'N8D302 "H": timeout 120000 ms'
    assert result.fixed["nodes"][1]["parameters"]["options"]["timeout"] == 120000


def test_timeout_opt_in_keeps_a_timeout_that_is_set() -> None:
    data = _param(url="https://x.example")
    result = fix_workflow(load(data), {"N8D302"}, set_timeout=120000)
    assert not result.changes


def test_cli_set_timeout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(_http()), encoding="utf-8")
    assert main(["fix", "--no-config", str(path)]) == 0
    assert "timeout" not in capsys.readouterr().out
    assert main(["fix", "--no-config", "--set-timeout", "90000", str(path)]) == 0
    assert 'N8D302 "H": timeout 90000 ms' in capsys.readouterr().out
    assert main(["fix", "--no-config", "--set-timeout", "0", str(path)]) == 2
    assert "--set-timeout" in capsys.readouterr().err


def test_cli_asking_for_the_rule_says_what_it_needs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(_http()), encoding="utf-8")
    assert main(["fix", "--no-config", "--rule", "N8D302", str(path)]) == 0
    assert "--set-timeout" in capsys.readouterr().out


def test_mcp_set_timeout() -> None:
    path = str(EXAMPLES / "lead-intake.json")
    text = mcp.call_tool("n8n_fix", {"path": path, "set_timeout_ms": 90000})["content"][0]["text"]
    assert '"Enrich lead" options.timeout: added 90000' in text
    assert mcp.call_tool("n8n_fix", {"path": path, "set_timeout_ms": 0})["isError"] is True


def test_the_rule_is_listed_as_not_fixable() -> None:
    assert not next(r for r in RULES if r.id == "N8D302").meta.fixable


# A7: fan-out


def _hook(*nodes: dict[str, Any], conns: dict[str, Any]) -> dict[str, Any]:
    return workflow([node("Hook", "webhook", HOOK, 2), *nodes], conns)


def _gaps(data: dict[str, Any]) -> list[str]:
    return [f.message for f in of(data, "N8D209")]


REPLY = node("Reply", "respondToWebhook")
LOG = node("Log", "noOp")
IF = node("If", "if", {}, 2)
OTHER = node("Other", "respondToWebhook")


def test_fan_out_with_a_response_on_one_branch() -> None:
    assert not _gaps(_hook(REPLY, LOG, conns=merge(link("Hook", "Reply"), link("Hook", "Log"))))
    assert not _gaps(_hook(REPLY, LOG, conns=merge(link("Hook", "Log"), link("Hook", "Reply"))))


def test_fan_out_later_in_the_flow_and_both_orders() -> None:
    conns = merge(link("Hook", "A"), link("A", "Log"), link("A", "Reply"))
    assert not _gaps(_hook(node("A", "noOp"), REPLY, LOG, conns=conns))


def test_dead_end_without_a_response_on_the_other_branch_of_if() -> None:
    conns = merge(link("Hook", "If"), link("If", "Reply", output=0), link("If", "Log", output=1))
    gaps = _gaps(_hook(IF, REPLY, LOG, conns=conns))
    assert len(gaps) == 1 and '"Log"' in gaps[0]


def test_unconnected_if_output_is_still_a_gap() -> None:
    gaps = _gaps(_hook(IF, REPLY, conns=merge(link("Hook", "If"), link("If", "Reply", output=0))))
    assert len(gaps) == 1 and '"If" [false]' in gaps[0]


def test_if_answers_on_both_outputs() -> None:
    conns = merge(link("Hook", "If"), link("If", "Reply", output=0), link("If", "Other", output=1))
    assert not _gaps(_hook(IF, REPLY, OTHER, conns=conns))


def test_fan_out_where_only_an_if_output_answers() -> None:
    conns = merge(link("Hook", "If"), link("Hook", "Log"), link("If", "Reply", output=0))
    gaps = _gaps(_hook(IF, REPLY, LOG, conns=conns))
    assert len(gaps) == 1 and '"If" [false]' in gaps[0] and '"Log"' in gaps[0]


def test_fan_out_past_an_if_where_a_sibling_answers() -> None:
    conns = merge(link("Hook", "If"), link("Hook", "Reply"), link("If", "Log", output=0))
    assert not _gaps(_hook(IF, REPLY, LOG, conns=conns))


def test_disabled_respond_does_not_answer() -> None:
    off = node("Off", "respondToWebhook", disabled=True)
    conns = merge(link("Hook", "If"), link("If", "Reply", output=0), link("If", "Off", output=1))
    gaps = _gaps(_hook(IF, REPLY, off, conns=conns))
    assert len(gaps) == 1 and '"Off"' in gaps[0]


def test_loop_body_does_not_count_as_a_gap() -> None:
    loop = node("Loop", "splitInBatches", {}, 3)
    conns = merge(link("Hook", "Loop"), link("Loop", "Reply", output=0), link("Loop", "Body", output=1), link("Body", "Loop"))
    assert not _gaps(_hook(loop, node("Body", "noOp"), REPLY, conns=conns))


# A8: lint -o and its own text and GitHub reports


@pytest.mark.parametrize("fmt", ["text", "github"])
def test_lint_replaces_its_own_report(tmp_path: Path, fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "report.txt"
    workflow_file = EXAMPLES / "lead-intake.json"
    assert main(["lint", "--no-config", "-f", fmt, "--fail-on", "never", "-o", str(report), str(workflow_file)]) == 0
    assert main(["lint", "--no-config", "-f", fmt, "--fail-on", "never", "-o", str(report), str(workflow_file)]) == 0
    assert "N8D101" in report.read_text(encoding="utf-8") or "hardcoded" in report.read_text(encoding="utf-8")
    capsys.readouterr()


def test_header_only_goes_to_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lint", "--no-config", "--fail-on", "never", str(EXAMPLES / "healthy.json")]) == 0
    assert "n8n-doctor report" not in capsys.readouterr().out


def test_lint_still_refuses_other_files_and_names_force(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    other = tmp_path / "notes.txt"
    other.write_text("my notes\n", encoding="utf-8")
    assert main(["lint", "--no-config", "-o", str(other), str(EXAMPLES / "healthy.json")]) == 2
    assert "--force" in capsys.readouterr().err
    assert other.read_text(encoding="utf-8") == "my notes\n"


def test_device_refusal_mentions_stdout(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def refuse(path: Path) -> None:
        raise OSError(22, "directly in the device folder, which holds devices, not files", str(path))

    monkeypatch.setattr(cli, "check_writable", refuse)
    assert main(["lint", "--no-config", "-o", "stream", str(EXAMPLES / "healthy.json")]) == 2
    assert "-o -" in capsys.readouterr().err


# A9: placeholders, names, pinned data, Teams and more prefixes


@pytest.mark.parametrize("value", ['"your_api_key"', "'your_api_key'", '"YOUR_TOKEN"', '"changeme"'])
def test_quoted_placeholders(value: str) -> None:
    assert not of(_entry("X-Api-Key", value), "N8D101")


@pytest.mark.parametrize("name", ["object_key", "file_key", "Object-Key", "fileKey"])
def test_storage_names_are_no_secrets(name: str) -> None:
    data = _entry(name, "a1B2c3D4e5F6/g7H8.png".replace("/", "x").replace(".", "y"))
    assert not of(data, "N8D101")
    assert not _secrets(data)


def test_tokens_in_pinned_data() -> None:
    data = workflow([trigger(), node("H", "noOp")], link("Start", "H"), pinData={"H": [{"json": {"reply": "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"}}]})
    found = of(data, "N8D101")
    assert len(found) == 1 and found[0].node == "H" and "ghp_abcdefghij" not in found[0].message
    assert "pinned" in found[0].message
    assert of(data, "N8D211")


def test_plain_pinned_data_is_not_reported() -> None:
    data = workflow([trigger(), node("H", "noOp")], link("Start", "H"), pinData={"H": [{"json": {"reply": "all is well, 42 items"}}]})
    assert not of(data, "N8D101")


@pytest.mark.parametrize(
    "value",
    [
        "https://contoso.webhook.office.com/"
        + "webhookb2/a1b2c3d4-1111-2222-3333-444455556666@a1b2c3d4-1111-2222-3333-444455556666/"
        + "IncomingWebhook/0123456789abcdef0123456789abcdef/a1b2c3d4-1111-2222-3333-444455556666",
        "https://outlook.office.com/"
        + "webhook/a1b2c3d4-1111-2222-3333-444455556666@a1b2c3d4-1111-2222-3333-444455556666/IncomingWebhook/0123456789abcdef/a1b2c3d4",
        "apify_api_" + "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD3fG6",
        "xkeysib-" + "0123456789abcdef" * 4 + "-aB3dE6gH9jK2mN5p",
        "GOCSPX-" + "aB3dE6gH9jK2mN5pQ8sT1vW4xY7z",
        "ATBB" + "aB3dE6gH9jK2mN5pQ8sT1vW4xY7zA0cD",
        "sb_secret_" + "aB3dE6gH9jK2mN5pQ8sT1v",
    ],
)
def test_more_token_shapes(value: str) -> None:
    assert of(_param(url="https://x.example", note=value), "N8D101")
    assert value in _secrets(_param(url="https://x.example", note=value))


@pytest.mark.parametrize(
    "value", ["GOCSPX-your-client-secret-here-xxxxxxx", "https://contoso.webhook.office.com/webhookb2/xxxxxxxx-xxxx", "ATBBshort", "apify_api_short"]
)
def test_token_shapes_that_are_templates_or_too_short(value: str) -> None:
    assert not of(_param(url="https://x.example", note=value), "N8D101")


# B1: adjacent optional runs


@pytest.mark.parametrize("text", [" " * 32 * 1024, "\t " * 16 * 1024, " " * 32 * 1024 + "|", ("| " * 8 * 1024)])
def test_note_of_spaces_is_linear(text: str) -> None:
    data = workflow([trigger(), node("Note", "stickyNote", {"content": text})])
    started = time.perf_counter()
    of(data, "N8D101")
    assert time.perf_counter() - started < 1.0


def test_file_of_spaces_is_linear() -> None:
    started = time.perf_counter()
    with pytest.raises(WorkflowError):
        parse_text(" " * 64 * 1024, "x.json")
    assert time.perf_counter() - started < 1.0
    with pytest.raises(WorkflowError) as cut:
        parse_text(' [ {"name": "a", ', "x.json")
    assert cut.value.broken_workflow


def test_table_rows_still_read() -> None:
    assert of(workflow([trigger(), node("Note", "stickyNote", {"content": "  |  password  |  hunter2hunter  |\n"})]), "N8D101")
    assert of(workflow([trigger(), node("Note", "stickyNote", {"content": "password | hunter2hunter |\n"})]), "N8D101")


# B4: fix writes no NaN or Infinity


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_fix_refuses_numbers_json_cannot_hold(tmp_path: Path, number: str, capsys: pytest.CaptureFixture[str]) -> None:
    text = json.dumps(_http() | {"pinData": {"H": [{"json": {"a": 1}}]}}).replace('"typeVersion": 4.2', f'"typeVersion": 4.2, "z": {number}')
    source = tmp_path / "wf.json"
    source.write_text(text, encoding="utf-8")
    fixed = tmp_path / "wf.fixed.json"
    assert main(["fix", "--no-config", "--write", str(source)]) == 2
    err = capsys.readouterr().err
    assert "NaN" in err or "Infinity" in err
    assert not fixed.exists()
    assert main(["fix", "--no-config", "--format", "json", "--include-patch", str(source)]) == 2
    capsys.readouterr()
    assert main(["fix", "--no-config", str(source)]) == 0  # the dry run shows no raw value
    assert "cannot be saved" in capsys.readouterr().err


def test_fix_result_says_so() -> None:
    data = _http() | {"pinData": {"H": [{"json": {"a": 1}}]}}
    data["nodes"][1]["z"] = float("nan")
    result = fix_workflow(load(data))
    assert result.changes and result.unwritable and not result.fixed_text
