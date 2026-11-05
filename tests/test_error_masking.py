"""Names, keys and paths in error messages (stderr, exceptions, MCP errors) are masked before they are shortened."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main
from n8n_doctor.rules import shorten
from n8n_doctor.workflow import LimitError, from_data

from .conftest import node, trigger, workflow

TOKEN = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"


def _edge(name: str) -> dict[str, Any]:
    return {"node": name, "type": "main", "index": 0}


OVER_LIMIT = [
    workflow([trigger(), node(TOKEN, "switch", {"rules": {"values": [{}] * 1001}}, 3)]),
    workflow([trigger(), node(TOKEN, "switch", {"rules": {"rules": [{}] * 1001}}, 2)]),
    workflow([trigger(TOKEN)], {TOKEN: {"main": [[] for _ in range(1001)]}}),
    workflow([trigger(TOKEN)], {TOKEN: {TOKEN: [[] for _ in range(1001)]}}),  # the connection type too
    workflow([trigger(TOKEN)], {TOKEN: {"main": [[_edge(TOKEN)] * 1001]}}),
    workflow([trigger(), node(TOKEN, "set", {"values": [1] * 10_001})]),
    workflow([trigger(), node(TOKEN, "set", {"k" * 2000: 1})]),
    workflow([trigger(), node("Sw", "switch", {"rules": {"values": [{}] * 1001}}, 3)], name=TOKEN),
]


@pytest.mark.parametrize("data", OVER_LIMIT)
def test_limit_errors_mask_names(data: dict[str, Any]) -> None:
    with pytest.raises(LimitError) as caught:
        from_data(data, f"flows/{TOKEN}.json")
    message = str(caught.value)
    assert TOKEN[:10] not in message, message
    assert "ghp_***" in message


def test_cli_stderr_and_mcp_errors_mask_names(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(OVER_LIMIT[0]))
    assert main(["lint", "--no-config", str(path)]) == 2
    err = capsys.readouterr().err
    assert "1,001 rules" in err and TOKEN[:10] not in err
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("N8N_DOCTOR_MCP_ROOTS", raising=False)
    for args in ({"path": str(path)}, {"workflow": OVER_LIMIT[0]}):
        out = io.StringIO()
        mcp.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "n8n_lint", "arguments": args}}) + "\n"), out)
        reply = json.loads(out.getvalue())["result"]
        assert reply["isError"] and TOKEN[:10] not in reply["content"][0]["text"]


def test_mcp_protocol_errors_mask_method_and_tool_names() -> None:
    out = io.StringIO()
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": TOKEN},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": TOKEN + " x" * 500}},
    ]
    mcp.serve(io.StringIO("".join(json.dumps(m) + "\n" for m in lines)), out)
    text = out.getvalue()
    assert TOKEN[:10] not in text and len(text) < 1000


def test_cli_errors_mask_rule_names(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lint", "--no-config", "--select", TOKEN, "."]) == 2
    assert TOKEN[:10] not in capsys.readouterr().err


def test_config_errors_mask_patterns(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = tmp_path / ".n8n-doctor.toml"
    cfg.write_text(f'[rules.N8D101]\nallow = ["({TOKEN}"]\n')
    (tmp_path / "wf.json").write_text(json.dumps(workflow([trigger()])))
    assert main(["lint", "--config", str(cfg), str(tmp_path / "wf.json")]) == 2
    assert TOKEN[:10] not in capsys.readouterr().err


@pytest.mark.parametrize(
    ("text", "limit", "expected"),
    [
        ("short name", 80, "short name"),
        ("Fetch the customers from the CRM", 20, "Fetch the customers…"),
        (f"Call API with {TOKEN} now", 80, "Call API with ghp_*** now"),
        (f"Call API with {TOKEN} now", 18, "Call API with…"),  # the cut would fall inside the masked token: it goes
        ("x" * 100, 20, "…"),  # a single long word is never cut in half
        ("a\x1b[31mb", 80, "a?[31mb"),
    ],
)
def test_shorten_masks_first_and_never_cuts_a_word(text: str, limit: int, expected: str) -> None:
    assert shorten(text, limit) == expected


def test_shorten_does_not_mask_a_secret_partly() -> None:
    for limit in range(1, 60):
        shown = shorten(f"key {TOKEN} end", limit)
        assert TOKEN[4:8] not in shown
        assert not shown.rstrip("…").endswith(("g", "gh", "ghp", "ghp_", "ghp_*", "ghp_**")), shown


def test_url_password_with_an_at_sign_is_masked_to_the_host() -> None:
    from n8n_doctor.rules import redact

    assert redact("postgres://admin:Hk3!pQ9#vL2@wX7z@db:5432/app") == "postgres://admin:***@db:5432/app"
