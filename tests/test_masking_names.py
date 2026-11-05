"""Secrets in names, split private keys, odd spellings in execution messages, and which names and values N8D101 reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.workflow import from_data

from .conftest import link, merge, node, trigger, workflow

ANTHROPIC = "sk-" + "ant-api03-" + "A1b2C3d4E5" * 6


SLACK = "xo" + "xb-1234567890-abcdefghijKLMN"


GITHUB = "gh" + "p_" + "G7" * 20


AWS = "AK" + "IA" + "Q2W3E4R5T6Y7U8I9"


PIN_SLACK = "xo" + "xb-9876543210-pinnedKEYabcd"


NAME_SECRETS = (ANTHROPIC, SLACK, GITHUB, AWS, PIN_SLACK)


def _secret_names() -> dict[str, Any]:
    http = node(f"Call {ANTHROPIC}", "httpRequest", {"url": "https://api.example.com/x", "options": {}}, 4.2)
    code = node("Code", "code", {"jsCode": f'return $("Call {ANTHROPIC}").all();'}, 2)
    conns = merge(
        link("Start", http["name"], "Code"),
        {f"ghost {AWS}": {"main": [[{"node": "Code", "type": "main", "index": 0}]]}},
        {"Code": {"main": [[{"node": GITHUB, "type": "main", "index": 0}]]}},
    )
    pin = {f"Webhook {PIN_SLACK}": [{"json": {"n": 1}}], "Start": [{"json": {"n": 2}}]}
    return workflow([trigger(), http, code], conns, name=f"WF {SLACK}", pinData=pin, id=SLACK)


def _assert_clean(text: str) -> None:
    for secret in NAME_SECRETS:
        assert secret not in text, secret
        assert secret[6:20] not in text, secret


def _every_output(data: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> list[str]:
    """What lint (every format), explain (every format), fix (diff, JSON diff and changes) and the MCP tools print."""
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    shown: list[str] = []
    for fmt in ("text", "json", "sarif", "github"):
        main(["lint", "--no-config", "--color", "never", "-v", "-f", fmt, str(path)])
        shown.append(capsys.readouterr().out)
    for fmt in ("text", "json", "mermaid"):
        main(["explain", "-f", fmt, str(path)])
        shown.append(capsys.readouterr().out)
    for fmt in ("diff", "json"):
        main(["fix", "--no-config", "-f", fmt, str(path)])
        out = capsys.readouterr().out
        shown.append(json.dumps(json.loads(out)["changes"]) + json.loads(out)["diff"] if fmt == "json" else out)
    for tool, args in (("n8n_lint", {}), ("n8n_explain", {}), ("n8n_explain", {"format": "json"}), ("n8n_explain", {"format": "mermaid"})):
        shown.append(json.dumps(mcp.call_tool(tool, {"workflow": data, **args})))
    shown.append(json.dumps(mcp.call_tool("n8n_fix", {"workflow": data, "output": "diff"})))
    wf = from_data(data, "x")[0]
    result = fix_workflow(wf)
    shown += [outline(wf), mermaid(wf), json.dumps(as_dict(wf)), "\n".join(result.changes), result.diff]
    shown += [json.dumps(f.to_dict()) for f in run([wf])]
    return shown


def test_secrets_in_names_are_masked_in_every_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = _secret_names()
    shown = _every_output(data, tmp_path, capsys)
    result = fix_workflow(from_data(data, "x")[0])
    assert any("pinned data" in c for c in result.changes) and any("missing node" in c for c in result.changes)
    _assert_clean("\n".join(shown))
    assert "Call sk-a***" in shown[0]  # still recognisable


def test_secrets_found_by_their_context_are_masked_in_names(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # a header value is a secret because of its header name; the same text in a node or workflow name is masked too
    secret = "q7Wz9xLm2Pv4Rt8K"
    headers = {"parameters": [{"name": "X-Api-Key", "value": secret}]}
    http = node(f"Call {secret}", "httpRequest", {"url": "https://api.example.com/x", "sendHeaders": True, "headerParameters": headers, "options": {}}, 4.2)
    switch = node(f"Route {secret}", "switch", {"rules": {"values": [{"renameOutput": True, "outputKey": f"to {secret}"}]}}, 3)
    data = workflow([trigger(), http, switch], link("Start", http["name"], switch["name"]), name=f"Sync {secret}", id=secret)
    shown = "\n".join(_every_output(data, tmp_path, capsys))
    assert secret not in shown and secret[:10] not in shown
    assert "Call ***" in shown and "Sync ***" in shown


@pytest.mark.parametrize("name", ["GET /search?key=customer_id", "Login https://user:<password>@host.example.com", "Use ?token=your_token_here"])
def test_names_that_only_look_like_secrets_are_not_reported(name: str) -> None:
    data = workflow([trigger(), node(name, "noOp")], link("Start", name), name=name)
    assert not [f.message for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]


def test_secret_like_names_are_reported() -> None:
    found = [f.message for f in run(from_data(_secret_names(), "x")) if f.rule.id == "N8D101"]
    for where in ("the workflow name", "the node name", "a connection's missing node name", "a node name in the pinned data"):
        assert any(m.startswith(where) for m in found), where
    _assert_clean("\n".join(found))
    clean = workflow([trigger(), node("Fetch orders", "noOp")], link("Start", "Fetch orders"), name="Order sync")
    assert not [f for f in run(from_data(clean, "x")) if f.rule.id == "N8D101"]


def test_findings_hold_no_raw_secret() -> None:
    data = workflow([trigger(), node("S", "set", {"options": {"password": "hunter2hunter2"}})], link("Start", "S"))
    for f in run(from_data(data, "x")):
        assert "hunter2hunter2" not in repr(f)
        assert not f.extra


def test_fix_and_suppressions_still_find_nodes_with_masked_names() -> None:
    http = node(f"Call {ANTHROPIC}", "httpRequest", {"url": "https://api.example.com/x", "options": {}}, 4.2)
    result = fix_workflow(from_data(workflow([trigger(), http], link("Start", http["name"])), "x")[0], {"N8D302"}, set_timeout=30000)
    assert result.fixed["nodes"][1]["parameters"]["options"]["timeout"] == 30000
    assert result.changes == ['N8D302 "Call sk-a***": timeout 30000 ms']
    quiet = {**http, "notes": "n8n-doctor-disable N8D302"}
    found = run(from_data(workflow([trigger(), quiet], link("Start", http["name"])), "x"))
    assert not [f for f in found if f.rule.id == "N8D302"]


PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"


@pytest.mark.parametrize(
    "code",
    [
        f'const k = "-----BEGIN PRIVATE KEY-----\\n" + "{PEM_BODY}" + "\\n-----END PRIVATE KEY-----"; return $("Old Name").all();',
        f'const k = ["-----BEGIN PRIVATE KEY-----", "{PEM_BODY}", "-----END PRIVATE KEY-----"].join("\\n"); return $("Old Name").all();',
        f'const k = "-----BEGIN PRIVATE KEY-----\\n" + "{PEM_BODY}"; return $("Old Name").all();',
        f"const k = `-----BEGIN RSA PRIVATE KEY-----\n` +\n  '{PEM_BODY}';\nreturn $('Old Name').all();",
    ],
    ids=["concat", "join", "no-end", "template"],
)
def test_private_key_split_over_literals_is_masked(code: str) -> None:
    data = workflow([trigger(), node("Code", "code", {"jsCode": code}, 2), node("Old-Name", "noOp")], link("Start", "Code", "Old-Name"))
    wf = from_data(data, "x")[0]
    result = fix_workflow(wf)
    assert any("Old Name" in c for c in result.changes)
    out = result.diff + json.dumps(mcp.call_tool("n8n_fix", {"workflow": data, "output": "diff"})) + outline(wf) + json.dumps(as_dict(wf))
    assert PEM_BODY[4:30] not in out
    assert [f for f in run([wf]) if f.rule.id == "N8D101" and "private key" in f.message]


def test_redact_masks_split_keys_in_json_text() -> None:
    from n8n_doctor.rules import redact

    line = json.dumps({"jsCode": f'k = "-----BEGIN PRIVATE KEY-----" + "{PEM_BODY}"; x()'})
    assert PEM_BODY not in redact(line) and redact(line).endswith('; x()"}')
    closed = json.dumps({"jsCode": f'k = "-----BEGIN PRIVATE KEY-----" + "{PEM_BODY}" + "-----END PRIVATE KEY-----"; x()'})
    assert PEM_BODY not in redact(closed) and redact(closed).endswith('; x()"}')


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ('{"error":"{\\"access_token\\":\\"ya29.SECRETA\\"}"}', "SECRETA"),
        ('{"error":"{\\\\\\"access_token\\\\\\":\\\\\\"ya29.SECRETB\\\\\\"}"}', "SECRETB"),
        ("login failed, password: SECRETC", "SECRETC"),
        ("{'password': 'SECRETD', 'user': 'bob'}", "SECRETD"),
        ("body access_token%3DSECRETE%26x%3D1", "SECRETE"),
        ('{"\\u0070assword":"SECRETF"}', "SECRETF"),
        ('{"password":"ab\\"SECRETG", "next": "keep"}', "SECRETG"),
    ],
)
def test_execution_messages_mask_nested_and_odd_spellings(message: str, secret: str) -> None:
    from n8n_doctor.executions import mask_message

    masked = mask_message(message)
    assert secret not in masked
    if "next" in message:
        assert '"next": "keep"' in masked


def _n101(params: dict[str, Any], type_: str = "set") -> list[str]:
    data = workflow([trigger(), node("N", type_, params, 4.2 if type_ == "httpRequest" else 2)], link("Start", "N"))
    return [f.message for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]


def test_json_escaped_header_names_are_checked() -> None:
    params = {"url": "https://api.example.com", "options": {}, "sendHeaders": True, "specifyHeaders": "json"}
    assert _n101({**params, "jsonHeaders": '{"X-Api-\\u004bey": "k8Jd93kLmQ2x"}'}, "httpRequest")
    assert not _n101({**params, "jsonHeaders": '{"X-Request-\\u0049d": "k8Jd93kLmQ2x"}'}, "httpRequest")


@pytest.mark.parametrize("name", ["privateKey", "accessKey", "signingKey", "clientSecret", "secretKey", "AWS_SECRET_ACCESS_KEY"])
def test_more_secret_variable_names_in_code(name: str) -> None:
    assert _n101({"jsCode": f"const {name} = 'Zx81kQ0pLm2nB7vC';"}, "code")


@pytest.mark.parametrize("name", ["primaryKey", "sortKey", "cacheKey", "keyName", "tokenUrl", "publicKey"])
def test_other_variable_names_in_code_are_not_secrets(name: str) -> None:
    assert not _n101({"jsCode": f"const {name} = 'Zx81kQ0pLm2nB7vC';"}, "code")


def test_query_values_need_entropy() -> None:
    def n(url: str) -> int:
        return len(_n101({"url": url, "options": {}}, "httpRequest"))

    assert n("https://api.example.com/x?sig=2024-01-01T00") == 0
    assert n("https://api.example.com/x?sig=20240101T000000") == 0
    assert n("https://api.example.com/x?key=aaaa1111aaaa") == 0
    assert n("https://api.example.com/x?token=aaaa1111aaaa") == 1  # a name that can only mean a secret: no entropy needed
    assert n("https://api.example.com/x?sig=a1B2c3D4e5F6g7H8") == 1
    assert n("https://api.example.com/x?token=abc123def456") == 1


def test_gitignore_has_tmp() -> None:
    from .conftest import ROOT

    assert ".tmp/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
