"""Secrets in every output form: private keys, Unicode, the fix diff and its JSON, explain, MCP, execution messages."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.config import Config
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.rules import redact
from n8n_doctor.workflow import from_data

from .conftest import ROOT, link, node, trigger, workflow

ENCRYPTED_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D4E5F60718293A4B5C6D7E8F9\n\n"
    "LEGACYBODYfirstline0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\nLEGACYBODYsecondline9876543210\n-----END RSA PRIVATE KEY-----"
)


TRUNCATED_PEM = "-----BEGIN PRIVATE KEY-----\nTRUNCBODYMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\nTRUNCBODYmore"


def _http(params: dict[str, Any]) -> dict[str, Any]:
    return node("Send", "httpRequest", {"url": "https://api.example.com/x", "options": {}, **params}, 4.2)  # N8D302 gives a fix


def _outputs(data: dict[str, Any]) -> str:
    """Everything that is meant to be safe to show: explain in all forms, the fix diff (API, CLI JSON field, MCP)."""
    wf = from_data(data, "x.json")[0]
    diff = fix_workflow(wf).diff
    assert diff, "the test workflow needs at least one fix so there is a diff"
    via_mcp = json.dumps(mcp.call_tool("n8n_fix", {"workflow": data, "output": "diff"}))
    explained = json.dumps(mcp.call_tool("n8n_explain", {"workflow": data}))
    return "\n".join([outline(wf), mermaid(wf), json.dumps(as_dict(wf)), diff, via_mcp, explained])


@pytest.mark.parametrize("pem", [ENCRYPTED_PEM, TRUNCATED_PEM], ids=["encrypted", "truncated"])
def test_private_keys_are_masked_with_their_body(pem: str) -> None:
    note = node("Note", "stickyNote", {"content": f"deploy key:\n{pem}"})
    data = workflow([trigger(), _http({"sendBody": True, "bodyParameters": {"parameters": [{"name": "k", "value": pem}]}}), note], link("Start", "Send"))
    out = _outputs(data)
    for marker in ("LEGACYBODY", "TRUNCBODY", "DEK-Info", "0A1B2C3D4E5F"):
        assert marker not in out
    assert [f for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]


def test_other_private_key_formats() -> None:
    ssh2 = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nSSH2BODYabc123\n---- END SSH2 ENCRYPTED PRIVATE KEY ----"
    putty = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nPUTTYBODYxyz\nPrivate-MAC: 00ff"
    pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nPGPBODYlmn\n-----END PGP PRIVATE KEY BLOCK-----\nafter"
    for key, body in ((ssh2, "SSH2BODY"), (putty, "PUTTYBODY"), (pgp, "PGPBODY")):
        assert body not in redact(key) and body not in redact(json.dumps({"k": key}))
    assert redact(pgp).endswith("\nafter") and redact(json.dumps({"k": TRUNCATED_PEM, "n": "x"})).endswith('"n": "x"}')


@pytest.mark.parametrize("password", ["pässwörd\u0080SECRETUNI1", "line SECRETUNI2sep", "ok\u009bSECRETUNI3"])
def test_unicode_secrets_are_masked_in_the_diff(password: str) -> None:
    data = workflow([trigger(), _http({}), node("S", "set", {"options": {"password": password}})], link("Start", "Send", "S"))
    out = _outputs(data)
    assert "SECRETUNI" not in out


def test_allowed_match_does_not_hide_a_longer_secret() -> None:
    data = workflow([trigger(), node("S", "set", {"options": {"password": "AKIAIOSFODNN7EXAMPLE:realSecretPassw0rd"}})], link("Start", "S"))
    cfg = Config(options={"N8D101": {"allow": ["^AKIAIOSFODNN7EXAMPLE$"]}})
    found = [f for f in run(from_data(data, "x"), cfg) if f.rule.id == "N8D101"]
    assert len(found) == 1 and 'literal "password"' in found[0].message


def test_query_string_needs_a_generated_looking_value() -> None:
    def n101(url: str) -> int:
        data = workflow([trigger(), node("H", "httpRequest", {"url": url, "options": {}}, 4.2)], link("Start", "H"))
        return len([f for f in run(from_data(data, "x")) if f.rule.id == "N8D101"])

    assert n101("https://api.example.com/v1/items?key=customer_id") == 0
    assert n101("https://api.example.com/v1/items?key=readonly_access") == 0
    assert n101("https://api.example.com/v1/items?token=readonly_access") == 1  # token= always names a secret
    assert n101("https://api.example.com/v1/items?token=YOUR_TOKEN_HERE") == 0
    assert n101("https://api.example.com/v1/items?key=a1B2c3D4e5F6g7H8") == 1


def test_removed_pin_data_is_summarised_in_the_diff() -> None:
    pin = {"Start": [{"json": {"email": "jane.doe@example.com", "apiToken": "pinnedTok3n"}}, {"json": {"n": 2}}]}
    data = workflow([trigger(), node("S", "noOp")], link("Start", "S"), pinData=pin)
    result = fix_workflow(from_data(data, "x")[0])
    assert "jane.doe@example.com" not in result.diff and "pinnedTok3n" not in result.diff
    assert "pinData: removed 2 pinned records of 1 node" in result.diff
    assert result.fixed["pinData"] == {}


def _summarize(message: str) -> str:
    from n8n_doctor import executions

    class FakeClient:
        base = "https://n8n.example.com/api/v1"

        def executions(self, *args: Any, **kwargs: Any) -> Any:
            yield {"id": "1", "workflowId": "w", "startedAt": "t", "data": {"resultData": {"error": {"message": message}}}}

        def workflow(self, wid: str) -> Any:
            return {"name": "W"}

    return json.dumps(executions.summarize(FakeClient(), None, 5, pattern_only=True))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ('400 body {"password":"hunter2"}', "hunter2"),
        ('400 body {\\"client_secret\\":\\"cs-77\\"}', "cs-77"),
        ("401 Bearer abc123", "abc123"),
        ("401 Token t0k3n", "t0k3n"),
        ("form body username=bob&password=s3cr3t&remember=1", "s3cr3t"),
        ("Authorization: Basic%20" + base64.b64encode(b"admin:pw1").decode().replace("=", "%3D"), "YWRtaW46cHcx"),
        ("x-api-key: k-123456", "k-123456"),
        ("bad key " + ENCRYPTED_PEM, "LEGACYBODY"),
        ("bad key " + TRUNCATED_PEM, "TRUNCBODY"),
        ("x" * 1990 + " AKIAIOSFODNN7EXAMPLE", "IOSFOD"),  # masked before the message is cut at 2,000 characters
        ("key Zx81kQ2mT7vB9pL4 is not valid", "Zx81kQ2mT7vB9pL4"),
        ("access_key_id=Zx81kQ2mT7vB9pL4&x=1", "Zx81kQ2mT7vB9pL4"),
        ("<password>Zx81kQ2mT7vB9pL4</password>", "Zx81kQ2mT7vB9pL4"),
        ('<s:ApiKey type="x">Zx81kQ2mT7vB9pL4</s:ApiKey>', "Zx81kQ2mT7vB9pL4"),
        ("login failed: password=abc Zx81kQ2mT7vB9pL4", "Zx81kQ2mT7vB9pL4"),
        ("token: abc Zx81kQ2mT7vB9pL4 rejected", "Zx81kQ2mT7vB9pL4"),
    ],
)
def test_execution_messages_are_masked(message: str, secret: str) -> None:
    blob = _summarize(message)
    assert secret not in blob


def test_execution_messages_keep_prose() -> None:
    blob = _summarize("Token has expired; Bearer token missing; Basic authentication failed")
    assert "Token has expired" in blob and "Bearer token missing" in blob and "Basic authentication" in blob


def test_execution_messages_keep_prose_around_credential_words() -> None:
    blob = _summarize("the key value is missing; password=abc retrying later; <name>bob</name>")
    assert "the key value is missing" in blob and "retrying later" in blob and "<name>bob</name>" in blob


def test_secret_like_parameter_names_are_masked() -> None:
    token = "gh" + "p_" + "K" * 36
    params = {"url": "https://api.example.com/x", "options": {}, "headers": {token: "{{ $json.x }}"}}
    data = workflow([trigger(), node("Send", "httpRequest", params, 4.2)], link("Start", "Send"))
    found = run(from_data(data, "x"))
    assert any(f.rule.id == "N8D101" and "parameter name" in f.message for f in found)
    shown = " ".join(f"{f.message} {f.parameter}" for f in found)
    assert any(f.rule.id == "N8D212" for f in found) and token not in shown
    assert token not in _outputs(data)


def test_docs_state_the_log_safety_of_fix_json() -> None:
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "`patch` field that\n`fix --format json --include-patch` adds" in security and "**not** safe" in security
    assert "Unreleased" not in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_fix_json_diff_field_is_masked(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from n8n_doctor.cli import main

    data = workflow([trigger(), _http({}), node("S", "set", {"options": {"password": "pässwörd\u0080SECRETUNI1"}})], link("Start", "Send", "S"))
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    main(["fix", "--no-config", "-f", "json", str(path)])
    out = json.loads(capsys.readouterr().out)
    assert "SECRETUNI1" not in out["diff"]


@pytest.mark.parametrize(
    ("message", "secret", "kept"),
    [
        ("401 Authorization: ApiKey SECRETA1, retrying", "SECRETA1", "Authorization: ApiKey ***, retrying"),
        ("Authorization: SSWS 00SECRETA2", "SECRETA2", "SSWS ***"),
        ('Authorization: Digest username="bob", realm="r", nonce="n1", response="SECRETA3"', "SECRETA3", "Digest ***"),
        ("authorization: SECRETA4 and more", "SECRETA4", "authorization: ***"),  # an unknown first word may be the key
        ("token: Bearer SECRETA5", "SECRETA5", "token: Bearer ***"),
        ("Cookie: sid=SECRETA6; theme=SECRETA7", "SECRETA7", "Cookie: ***"),
        ("Set-Cookie: session=SECRETA8; Path=/", "SECRETA8", "Set-Cookie: ***"),
        ("api-token: SECRETA9", "SECRETA9", "api-token: ***"),
        ("PRIVATE-TOKEN: SECRETB1", "SECRETB1", "PRIVATE-TOKEN: ***"),
        ('{"session_token": "SECRETB2"}', "SECRETB2", '"session_token": "***"'),
        ('{"sessionToken": "SECRETB3"}', "SECRETB3", None),
        ("id_token=SECRETB4&state=x", "SECRETB4", "state=x"),
        ("aws_secret_access_key: SECRETB5", "SECRETB5", None),
        ('{"password": ["SECRETB6", "SECRETB7"], "user": "bob"}', "SECRETB7", '"user": "bob"'),
        ("{'password': ['SECRETB8']}", "SECRETB8", None),
        ('{"password":SECRETB9,"user":"bob"}', "SECRETB9", '"user":"bob"'),
        ('config password = "SECRETC1" rejected', "SECRETC1", 'password = "***" rejected'),
        ("token: 'SECRETC2'", "SECRETC2", None),
    ],
)
def test_execution_messages_mask_auth_schemes_and_more_fields(message: str, secret: str, kept: str | None) -> None:
    from n8n_doctor.executions import mask_message

    masked = mask_message(message)
    assert secret not in masked
    if kept:
        assert kept in masked


_CONTROL = "\x1b[31m\x07\x00\x9b\x85"


def test_no_output_holds_control_characters(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from n8n_doctor.cli import main

    switch = node(
        f"Route{_CONTROL}",
        "switch",
        {
            "rules": {"values": [{"renameOutput": True, "outputKey": f"to{_CONTROL}a"}, {"renameOutput": True, "outputKey": "b"}]},
            "options": {"fallbackOutput": "extra", "renameFallbackOutput": f"else{_CONTROL}"},
        },
        3,
    )
    sticky = node("Note", "stickyNote", {"content": f"read{_CONTROL}me"})
    http = _http({"jsonBody": f"x{_CONTROL}"})
    http["name"] = f"Send{_CONTROL}"
    data = workflow(
        [trigger(f"Start{_CONTROL}"), switch, http, sticky, node(f"Lost{_CONTROL}", "noOp")],
        link(f"Start{_CONTROL}", switch["name"], http["name"]),
        name=f"Flow{_CONTROL}",
        settings={"timezone": f"Europe{_CONTROL}", "errorWorkflow": f"err{_CONTROL}"},
    )
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    shown: list[str] = []
    for args in (["lint", "-v", "--color", "never"], ["explain"], ["explain", "--ascii"], ["explain", "-f", "mermaid"], ["explain", "-f", "json"], ["fix"]):
        for fmt in (["-f", "text"], ["-f", "json"], ["-f", "sarif"], ["-f", "github"]) if args[0] == "lint" else ([],):
            main([*args, *fmt, "--no-config", str(path)] if args[0] != "explain" else [*args, str(path)])
            shown.append(capsys.readouterr().out)
    for tool, extra in (("n8n_explain", {}), ("n8n_explain", {"format": "mermaid"}), ("n8n_lint", {}), ("n8n_fix", {"output": "diff"})):
        shown.append(mcp.call_tool(tool, {"workflow": data, **extra})["content"][0]["text"])
    assert "[to?" in shown[4] and "[else?" in shown[4]  # the branch labels are printed, with the controls replaced
    for text in shown:
        bad = [c for c in text if (ord(c) < 32 and c not in "\n\t") or 0x7F <= ord(c) <= 0x9F]
        assert not bad, (bad, text[:300])


def test_fix_diff_names_absolute_and_relative_files_cleanly(tmp_path: Path) -> None:
    from n8n_doctor.fix import _diff_label

    assert _diff_label("/root/flows/a.json") == "/root/flows/a.json"
    assert _diff_label("./flows/a.json") == "flows/a.json"
    assert _diff_label("flows/a.json") == "flows/a.json" and _diff_label("<stdin>") == "<stdin>"
    data = workflow([trigger(), _http({})], link("Start", "Send"))
    wf = from_data(data, str(tmp_path / "wf.json"))[0]
    header = fix_workflow(wf).diff.splitlines()[0]
    assert header == f"{tmp_path}/wf.json:"


def test_non_string_error_workflow_setting_is_masked() -> None:
    token = "ghp_" + "E" * 36
    data = workflow([trigger(), _http({})], link("Start", "Send"), settings={"errorWorkflow": [token, {"id": token}]})
    wf = from_data(data, "x")[0]
    shown = as_dict(wf)["error_workflow"]
    assert token not in json.dumps(shown) and isinstance(shown, list) and shown[1]["id"].startswith("ghp_")
    assert token not in outline(wf) and "error workflow: [" in outline(wf)


def test_http_method_holding_a_secret_keeps_its_case() -> None:
    token = "ghp_" + "f" * 36
    password = "hunterhunterhunter"
    hook = node("Hook", "webhook", {"path": "x", "httpMethod": token})
    data = workflow(
        [trigger(), _http({"method": token}), _http({"method": password, "options": {"password": password}}) | {"name": "Other"}, hook],
        link("Start", "Send"),
        pinData={"Hook": [{"json": {}}]},
    )
    found = run(from_data(data, "x"))
    text = " ".join(f.message for f in found) + _outputs(data)
    assert token.upper() not in text and token not in text and password.upper() not in text and password not in text
    assert any(f.message.startswith("GET request") for f in run(from_data(workflow([trigger(), _http({"method": "get"})], link("Start", "Send")), "x")))


def test_unicode_escaped_json_header_value_is_masked_decoded_too() -> None:
    escaped = "\\u0074ok_" + "Q" * 20  # "tok_QQQ..." in the JSON text n8n sends
    headers = '{"X-Api-Key": "' + escaped + '"}'
    data = workflow([trigger(), _http({"jsonHeaders": headers}), node("Note tok_" + "Q" * 20, "noOp")], link("Start", "Send"))
    found = run(from_data(data, "x"))
    text = " ".join(f"{f.node} {f.message}" for f in found) + _outputs(data)
    assert "tok_" + "Q" * 20 not in text and escaped not in text


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ("Authorization=Bearer abcdefghijklmnop123", "abcdefghijklmnop123"),
        ("Invalid API key: sk12345abc", "sk12345abc"),
        ("request failed: api-key x9y8z7w6v5u4", "x9y8z7w6v5u4"),
        ("key: hunter2zz", "hunter2zz"),
        ("Ocp-Apim-Subscription-Key: 0123abcd4567", "0123abcd4567"),
        ("upstream said secret key=Zx81Zx81Zx81", "Zx81Zx81Zx81"),
    ],
)
def test_execution_messages_mask_named_keys(message: str, secret: str) -> None:
    from n8n_doctor.executions import mask_message

    assert secret not in mask_message(message)
    assert mask_message("the api key is invalid") == "the api key is invalid"


def test_execution_messages_mask_the_workflows_own_secrets() -> None:
    from typing import cast

    from n8n_doctor.executions import summarize

    header = "plainHeaderValue7"  # found by its context (a header value), not by a token pattern
    wf_data = workflow(
        [trigger(), _http({"sendHeaders": True, "headerParameters": {"parameters": [{"name": "X-Api-Key", "value": header}]}})], link("Start", "Send")
    )
    execution = {
        "id": "1",
        "workflowId": "7",
        "workflowData": {**wf_data, "name": f"Sync {header}"},
        "data": {"resultData": {"error": {"message": f"401 for header {header} (rejected)", "node": {"name": f"Send {header}"}}}},
    }

    class Stub:
        base = "https://n8n.example"

        def executions(self, *_: Any, **__: Any) -> Any:
            return iter([execution])

        def workflow(self, wid: str) -> dict[str, Any]:
            return {"name": wid}

    result = summarize(cast(Any, Stub()), None, 10)
    assert header not in json.dumps(result) and "401 for header ***" in result["groups"][0]["example"]


def test_display_masking_uses_the_query_string_filters() -> None:
    assert redact("GET /search?key=customer_id") == "GET /search?key=customer_id"
    assert redact("https://a.example/x?token=placeholder") == "https://a.example/x?token=placeholder"
    assert "k3Yx9Qa7Lm2Pz8Wv" not in redact("GET /x?api_key=k3Yx9Qa7Lm2Pz8Wv")
    data = workflow([trigger("GET /search?key=customer_id"), _http({})], link("GET /search?key=customer_id", "Send"))
    assert 'Flow from "GET /search?key=customer_id"' in outline(from_data(data, "x")[0])


def test_password_written_as_an_expression_without_braces_is_a_literal() -> None:
    data = workflow([trigger(), node("S", "set", {"options": {"password": "=hunter2hunter2"}}), _http({})], link("Start", "S", "Send"))
    found = [f for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]
    assert len(found) == 1 and 'a literal "password"' in found[0].message
    assert "hunter2hunter2" not in _outputs(data)
    braces = workflow([trigger(), node("S", "set", {"options": {"password": "={{ $env.PW }}"}})], link("Start", "S"))
    assert not [f for f in run(from_data(braces, "x")) if f.rule.id == "N8D101"]
