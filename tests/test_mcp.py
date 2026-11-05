from __future__ import annotations

import io
import json
from typing import Any

import pytest

from n8n_doctor import mcp

from .conftest import EXAMPLES, ROOT, link, node, trigger, workflow


@pytest.fixture(autouse=True)
def _in_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    """The server only reads below its working directory; run it from the repository."""
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("N8N_DOCTOR_MCP_ROOTS", raising=False)


def _session(*messages: Any) -> list[dict[str, Any]]:
    lines = "".join((m if isinstance(m, str) else json.dumps(m)) + "\n" for m in messages)
    out = io.StringIO()
    mcp.serve(io.StringIO(lines), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def _call(name: str, arguments: Any, msg_id: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


def test_handshake_and_tools() -> None:
    replies = _session(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        {"jsonrpc": "2.0", "id": 4, "method": "nope"},
        "not json",
        "[1, 2]",
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": "bad"},
        _call("rm_rf", {}, 6),
    )
    assert replies[0]["result"]["protocolVersion"] == "2025-03-26"
    assert replies[0]["result"]["serverInfo"]["name"] == "n8n-doctor"
    assert {t["name"] for t in replies[1]["result"]["tools"]} == {"n8n_lint", "n8n_explain", "n8n_fix", "n8n_executions"}
    assert replies[2]["result"] == {}
    assert [r.get("error", {}).get("code") for r in replies[3:]] == [-32601, -32700, -32600, -32602, -32602]


def test_lint_by_path_and_inline() -> None:
    by_path = mcp.call_tool("n8n_lint", {"path": str(EXAMPLES / "lead-intake.json")})
    assert by_path["isError"] is False
    head, body = by_path["content"][0]["text"].split("\n", 1)
    payload = json.loads(body)
    assert "5 error" in head and len(payload["findings"]) == 14 and "N8D101" in payload["fixes"]
    assert all("docs" not in f and None not in f.values() for f in payload["findings"])
    inline = mcp.call_tool("n8n_lint", {"workflow": workflow([trigger()]), "min_severity": "warning"})
    assert json.loads(inline["content"][0]["text"].split("\n", 1)[1])["findings"] == []
    as_text = mcp.call_tool("n8n_lint", {"workflow": json.dumps(workflow([trigger()]))})
    assert as_text["isError"] is False
    folder = mcp.call_tool("n8n_lint", {"path": str(EXAMPLES)})
    assert "in 3 workflows" in folder["content"][0]["text"]


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"path": "x", "workflow": {}},
        {"path": 3},
        {"workflow": 3},
        {"workflow": "{bad"},
        {"path": "/nonexistent/x.json"},
        {"workflow": {}, "min_severity": "loud"},
        "notadict",
    ],
)
def test_lint_bad_arguments_are_tool_errors(args: Any) -> None:
    result = mcp.call_tool("n8n_lint", args)
    assert result["isError"] is True and result["content"][0]["text"].startswith("Error:")


def test_explain_and_fix() -> None:
    text = mcp.call_tool("n8n_explain", {"path": str(EXAMPLES / "order-sync.json")})
    assert "[loop] Shape order" in text["content"][0]["text"]
    chart = mcp.call_tool("n8n_explain", {"path": str(EXAMPLES / "order-sync.json"), "format": "mermaid"})
    assert chart["content"][0]["text"].startswith("flowchart")
    assert mcp.call_tool("n8n_explain", {"path": str(EXAMPLES)})["isError"] is True
    assert mcp.call_tool("n8n_explain", {"path": str(EXAMPLES / "healthy.json"), "format": "png"})["isError"] is True
    fixed = mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "lead-intake.json"), "rules": ["pinned-data"], "output": "patch"})
    text = fixed["content"][0]["text"]
    assert "N8D211" in text and json.loads(text.split("JSON Patch:\n", 1)[1]) == [{"op": "replace", "path": "/pinData", "value": {}}]
    whole = mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "lead-intake.json"), "rules": ["pinned-data"], "output": "workflow"})
    assert json.loads(whole["content"][0]["text"].split("\n\n", 1)[1])["pinData"] == {}
    review = mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "lead-intake.json")})  # the masked change list unless asked otherwise
    text = review["content"][0]["text"]
    assert "Changed values:" in text and '"Enrich lead" retryOnFail: added true' in text and "JSON Patch" not in text
    assert mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "lead-intake.json"), "output": "diff"}) == review  # the old name
    assert mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "lead-intake.json"), "output": "png"})["isError"] is True
    assert mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "healthy.json")})["content"][0]["text"] == "Nothing to fix automatically."
    assert mcp.call_tool("n8n_fix", {"path": str(EXAMPLES / "healthy.json"), "rules": ["N8D999"]})["isError"] is True
    assert sorted(p.name for p in EXAMPLES.iterdir()) == ["healthy.json", "lead-intake.json", "order-sync.json"]


def test_executions_argument_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("N8N_API_URL", raising=False)
    assert mcp.call_tool("n8n_executions", {"limit": 0})["isError"] is True
    assert mcp.call_tool("n8n_executions", {"limit": True})["isError"] is True
    assert mcp.call_tool("n8n_executions", {"workflow_id": 5})["isError"] is True
    result = mcp.call_tool("n8n_executions", {})
    assert result["isError"] is True and "N8N_API_URL" in result["content"][0]["text"]


def test_lint_reports_suppressed_and_can_ignore_notes() -> None:
    from .conftest import node

    hook = node("Hook", "webhook", {"path": "x"}, 2, notes="n8n-doctor-disable N8D102")
    normal = mcp.call_tool("n8n_lint", {"workflow": workflow([hook])})["content"][0]["text"]
    assert "1 suppressed" in normal and '"suppressed":[{"rule":"N8D102"' in normal
    strict = mcp.call_tool("n8n_lint", {"workflow": workflow([hook]), "no_inline_suppress": True})["content"][0]["text"]
    assert '"N8D102"' in strict.split("\n", 1)[1] and "suppressed" not in strict
    assert mcp.call_tool("n8n_lint", {"workflow": workflow([hook]), "no_inline_suppress": "yes"})["isError"] is True


@pytest.mark.parametrize("bad_id", ["true", "[1]", '{"a": 1}', "NaN", "Infinity"])
def test_request_ids_must_be_string_number_or_null(bad_id: str) -> None:
    (reply,) = _session(f'{{"jsonrpc": "2.0", "id": {bad_id}, "method": "ping"}}')
    assert reply["id"] is None and reply["error"]["code"] == -32600 and "id must be" in reply["error"]["message"]


@pytest.mark.parametrize("good_id", ["a", 7, 2.5])
def test_string_and_number_ids_are_answered(good_id: Any) -> None:
    (reply,) = _session({"jsonrpc": "2.0", "id": good_id, "method": "ping"})
    assert reply == {"jsonrpc": "2.0", "id": good_id, "result": {}}


def test_lint_of_a_folder_with_a_broken_file_reports_it_and_the_rest(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "good.json").write_text(json.dumps(workflow([trigger()])))
    (tmp_path / "broken.json").write_text('{"nodes": [}, "connections": {}')
    (reply,) = _session(_call("n8n_lint", {"path": str(tmp_path)}))
    text = reply["result"]["content"][0]["text"]
    assert not reply["result"]["isError"]
    assert "in 1 workflow; 1 file could not be checked (see 'errors')" in text
    assert "broken.json: invalid JSON" in json.loads(text.split("\n", 1)[1])["errors"][0]


def test_request_lines_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "MAX_REQUEST_CHARS", 1000)
    monkeypatch.setattr(mcp, "_SKIP_CHUNK", 64)
    ping = {"jsonrpc": "2.0", "id": 7, "method": "ping"}
    long_line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "pad": "x" * 5000})

    class _Reader(io.StringIO):
        largest = 0

        def readline(self, size: int = -1, /) -> str:  # type: ignore[override]
            line = super().readline(size)
            _Reader.largest = max(_Reader.largest, len(line))
            return line

    out = io.StringIO()
    mcp.serve(_Reader(long_line + "\n" + json.dumps(ping) + "\n" + "y" * 3000), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32600 and "longer than" in replies[0]["error"]["message"]
    assert replies[1]["id"] == 7 and "result" in replies[1]
    assert replies[2]["error"]["code"] == -32600 and len(replies) == 3  # an over-long last line without a newline
    assert _Reader.largest <= 1001  # never more than the limit in memory at once


def test_request_limit_fits_the_largest_inline_workflow() -> None:
    from n8n_doctor.limits import DEFAULT

    assert 2 * DEFAULT.max_file_bytes < mcp.MAX_REQUEST_CHARS


def _deep_workflow(depth: int) -> dict[str, Any]:
    value: Any = "{{ $json.a }}"
    for _ in range(depth):
        value = {"a": value}
    return workflow([trigger(), node("S", "set", {"deep": value, "x": "{{ $json.a }}"})], link("Start", "S"))


def test_bad_paths_are_clean_errors(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "loop1").symlink_to(tmp_path / "loop2")
    (tmp_path / "loop2").symlink_to(tmp_path / "loop1")
    for path in ("a" * 300 + ".json", "loop1", "loop1/x.json"):
        for tool in ("n8n_lint", "n8n_fix", "n8n_explain"):
            reply = mcp.call_tool(tool, {"path": path})
            text = reply["content"][0]["text"]
            assert reply["isError"] and text.startswith("Error: ") and "Internal" not in text, (tool, path, text)


def test_deeply_nested_workflow_is_fixed_or_refused_cleanly(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".n8n-doctor.toml").write_text("[limits]\nmax-depth = 512\n")
    (tmp_path / "deep.json").write_text(json.dumps(_deep_workflow(505)))
    for tool, extra in (("n8n_fix", {}), ("n8n_fix", {"output": "workflow"}), ("n8n_explain", {"format": "json"}), ("n8n_lint", {})):
        reply = mcp.call_tool(tool, {"path": "deep.json", **extra})
        text = reply["content"][0]["text"]
        assert not reply.get("isError"), (tool, text[:200])
    assert "N8D212" in mcp.call_tool("n8n_fix", {"path": "deep.json"})["content"][0]["text"]


@pytest.mark.parametrize("tool", ["n8n_lint", "n8n_explain", "n8n_fix"])
def test_a_path_with_a_nul_is_a_clean_error(tool: str) -> None:
    reply = mcp.call_tool(tool, {"path": "a\0b.json"})
    assert reply["isError"] is True and "NUL" in reply["content"][0]["text"]
    (answer,) = _session(_call(tool, {"path": "a\0b.json"}))
    assert "error" not in answer and answer["result"]["isError"] is True
