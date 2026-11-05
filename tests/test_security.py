"""Hostile workflows, outputs and paths: nothing leaks, hangs, escapes or writes where it should not."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main
from n8n_doctor.explain import as_dict, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import collect, run
from n8n_doctor.report import guard_commands
from n8n_doctor.rules import redact
from n8n_doctor.workflow import from_data

from .conftest import BIG, link, node, trigger, workflow

TELEGRAM = "123456789:AA" + "c" * 33
GITHUB = "gh" + "p_" + "C" * 36


def test_redact_masks_every_pattern() -> None:
    text = f"https://api.telegram.org/bot{TELEGRAM}/send https://admin:Sup3rS3cret@db.example.com Bearer {'k' * 30} {GITHUB}"
    out = redact(text)
    for secret in (TELEGRAM, "Sup3rS3cret", "k" * 30, GITHUB):
        assert secret not in out


def test_explain_and_fix_do_not_print_secrets() -> None:
    h = node(
        "Send",
        "httpRequest",
        {"url": f"https://admin:Sup3rS3cret@api.example.com/bot{TELEGRAM}/x?token=abc123def456", "options": {}},
        4.2,
    )
    data = workflow([trigger(), h], link("Start", "Send"))
    wf = from_data(data, "x.json")[0]
    text = outline(wf) + json.dumps(as_dict(wf))
    assert "Sup3rS3cret" not in text and TELEGRAM not in text and "abc123def456" not in text
    diff = fix_workflow(wf).diff
    assert diff and TELEGRAM not in diff and "Sup3rS3cret" not in diff


def test_webhook_message_masks_secret_paths() -> None:
    hook = node("Hook", "webhook", {"path": f"in/{GITHUB}"}, 2)
    messages = " ".join(f.message for f in run(from_data(workflow([hook]), "x")))
    assert GITHUB not in messages


@pytest.mark.parametrize(
    "value",
    [
        "=$" + "{{" * 40000,
        "eyJ-" * 80000,
        "xoxb-" * 60000,
        "sk-ant-" * 40000,
        "a$" * 50000,
        "a-" * 50000,
        "Bearer " + "A" * 100000 + "{{",
        "https://" * 12000,
        "a:" * 50000,
        "'" * 100000,
        '"a": ' * 20000,
    ],
)
def test_adversarial_strings_lint_quickly(value: str) -> None:
    code = node("Code", "code", {"jsCode": value}, 2)
    h = node("H", "httpRequest", {"url": value, "jsonHeaders": value, "options": {"timeout": 1}}, 4.2)
    s = node("S", "set", {"x": "=" + value}, 3.4)
    data = workflow([trigger(), code, h, s], link("Start", "Code", "H", "S"))
    start = time.monotonic()
    run(from_data(data, "x"))
    outline(from_data(data, "x")[0])
    assert time.monotonic() - start < 5


def test_escape_sequences_never_reach_the_terminal(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    evil = {**node("N", "noOp"), "type": "n8n-nodes-base.x\x1b]52;c;ZWNobyBwd24=\x07"}
    data = workflow([trigger(), evil], link("Start", "N"), settings={"executionTimeout": "\x1b[31m9"})
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    for argv in (["explain", str(path)], ["lint", "--no-config", "-v", "--color", "never", str(path)], ["explain", "-f", "mermaid", str(path)]):
        main(argv)
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\x07" not in out


def test_guard_commands() -> None:
    assert guard_commands("ok\n  ::error::pwn\n::warning x") == "ok\n>   ::error::pwn\n> ::warning x"


def test_text_output_cannot_inject_workflow_commands(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "::error::x.json"
    path.write_text(json.dumps(workflow([node("Hook", "webhook", {"path": "x"}, 2)])))
    main(["lint", "--no-config", "--color", "never", str(tmp_path)])
    out = capsys.readouterr().out
    assert not any(line.lstrip().startswith("::") for line in out.splitlines())


def test_outputs_replace_symlinks_instead_of_writing_through(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    report = tmp_path / "report.sarif"
    report.symlink_to(victim)
    src = tmp_path / "wf.json"
    src.write_text(json.dumps(workflow([trigger()], pinData={"Start": [{"json": {}}]})))
    main(["lint", "--no-config", "-f", "sarif", "-o", str(report), str(src)])
    assert victim.read_text() == "keep" and not report.is_symlink() and json.loads(report.read_text())["version"] == "2.1.0"
    out = tmp_path / "out.json"
    out.symlink_to(victim)
    assert main(["fix", "--write", "-o", str(out), str(src)]) == 2  # exists
    assert main(["fix", "--write", "--force", "-o", str(out), str(src)]) == 0
    assert victim.read_text() == "keep" and not out.is_symlink()
    hard = tmp_path / "hard.json"
    hard.hardlink_to(src)
    before = src.read_text()
    assert main(["fix", "--write", "--force", "-o", str(hard), str(src)]) == 0
    assert src.read_text() == before


def test_deep_folders_and_unreadable_entries(tmp_path: Path) -> None:
    deep = tmp_path
    for _ in range(300):
        deep = deep / "d"
    deep.mkdir(parents=True)
    (deep / "wf.json").write_text(json.dumps(workflow([trigger()])))
    flows, _, errors = collect([tmp_path])
    assert len(flows) == 1 and errors == []
    flows, _, errors = collect([tmp_path], max_files=0)
    assert errors


def test_mcp_paths_are_limited_to_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "wf.json").write_text(json.dumps(workflow([trigger()])))
    project = tmp_path / "project"
    project.mkdir()
    (project / "wf.json").write_text(json.dumps(workflow([trigger()])))
    monkeypatch.chdir(project)
    monkeypatch.delenv("N8N_DOCTOR_MCP_ROOTS", raising=False)
    assert mcp.call_tool("n8n_lint", {"path": "wf.json"})["isError"] is False
    for target in (str(outside / "wf.json"), "../outside/wf.json", "/"):
        result = mcp.call_tool("n8n_lint", {"path": target})
        assert result["isError"] is True and "outside the folders" in result["content"][0]["text"]
    monkeypatch.setenv("N8N_DOCTOR_MCP_ROOTS", str(outside))
    assert mcp.call_tool("n8n_fix", {"path": str(outside / "wf.json")})["isError"] is False


def test_mcp_survives_hostile_lines() -> None:
    deep = "[" * 100000 + "]" * 100000
    lines = deep + "\n" + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n"
    out = io.StringIO()
    mcp.serve(io.StringIO(lines), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert replies[0]["error"]["code"] in (-32700, -32600) and replies[-1]["result"] == {}


def test_deep_api_like_data_is_rejected() -> None:
    from n8n_doctor.workflow import WorkflowError

    nested: Any = []
    for _ in range(500):
        nested = [nested]
    with pytest.raises(WorkflowError):
        from_data({"nodes": [], "connections": {}, "x": nested}, "api")


def test_explain_masks_long_urls_and_sticky_notes() -> None:
    token = "1234567890:AA" + "H" * 33
    h = node("Tg", "httpRequest", {"url": f"https://api.telegram.org/bot{token}/sendMessage", "options": {}}, 4.2)
    sticky = node("Note", "stickyNote", {"content": f"token {GITHUB}"})
    wf = from_data(workflow([trigger(), h, sticky], link("Start", "Tg")), "x")[0]
    text = outline(wf) + json.dumps(as_dict(wf))
    assert token[:20] not in text and GITHUB not in text


def test_executions_mask_error_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    from n8n_doctor import executions

    class FakeClient:
        base = "https://n8n.example.com/api/v1"

        def executions(self, *args: Any, **kwargs: Any) -> Any:
            msg = f"401 for https://u:hunter2pass@api.example.com/x?api_key=AKIA1234 with Bearer {'z' * 40}"
            yield {"id": "1\x1b[31m", "workflowId": "w", "startedAt": "t", "data": {"resultData": {"error": {"message": msg}}}}

        def workflow(self, wid: str) -> Any:
            return {"name": "W"}

    result = executions.summarize(FakeClient(), None, 5)  # type: ignore[arg-type]
    blob = json.dumps(result) + executions.render_text(result, __import__("n8n_doctor.report", fromlist=["Style"]).Style(False))
    assert "hunter2pass" not in blob and "AKIA1234" not in blob and "z" * 40 not in blob and "\x1b" not in blob


def test_json_output_escapes_c1_controls(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(workflow([node("Hook\u009b31m", "webhook", {"path": "x"}, 2)])))
    for argv in (["lint", "--no-config", "-f", "json", str(path)], ["explain", "-f", "json", str(path)]):
        main(argv)
        out = capsys.readouterr().out
        assert "\u009b" not in out and "\\u009b" in out


def test_verbose_skip_list_is_guarded(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "::error title=x::y.json").write_text('{"not": "workflow"}')
    (tmp_path / "wf.json").write_text(json.dumps(workflow([trigger()])))
    main(["lint", "--no-config", "-v", "--color", "never", str(tmp_path)])
    assert not any(line.lstrip().startswith("::") for line in capsys.readouterr().out.splitlines())


def test_report_never_overwrites_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "wf.json"
    original = json.dumps(workflow([trigger()]))
    path.write_text(original)
    assert main(["lint", "--no-config", "-o", str(path), str(path)]) == 2
    assert path.read_text() == original


def test_mcp_ignores_config_above_the_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".n8n-doctor.toml").write_text('disable = ["N8D101"]\n')
    project = tmp_path / "project"
    project.mkdir()
    (project / "wf.json").write_text(json.dumps(workflow([node("H", "httpRequest", {"url": f"https://x.example.com/?k={GITHUB}"}, 4.2)])))
    monkeypatch.chdir(project)
    monkeypatch.delenv("N8N_DOCTOR_MCP_ROOTS", raising=False)
    assert '"N8D101"' in mcp.call_tool("n8n_lint", {"path": "wf.json"})["content"][0]["text"]


def test_utf16_exports_are_read(tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_bytes(json.dumps(workflow([trigger()])).encode("utf-16"))
    flows, skipped, errors = collect([tmp_path])
    assert len(flows) == 1 and not skipped and not errors


def test_expression_refs_only_inside_braces() -> None:
    h = node("Html", "html", {"html": "=<script>$('#btn').click()</script>{{ $json.name }}"}, 1.2)
    assert not [f for f in run(from_data(workflow([trigger(), h], link("Start", "Html")), "x")) if f.rule.id == "N8D207"]


def test_short_passwords_are_fully_masked() -> None:
    h = node("H", "httpRequest", {"url": "postgres://admin:hunter2pass@db.example.com/x"}, 4.2)
    msgs = " ".join(f.message for f in run(from_data(workflow([trigger(), h], link("Start", "H")), "x")))
    assert "hunt" not in msgs and "(11 chars)" in msgs


def test_fix_diff_masks_code_secrets() -> None:
    code = node("Code", "code", {"jsCode": "const password = \"hunter2hunter2xyz\";\nreturn $('old name').all();"}, 2)
    data = workflow([trigger(), node("Old Name", "noOp"), code], link("Start", "Old Name", "Code"))
    diff = fix_workflow(from_data(data, "x.json")[0]).diff
    assert diff and "hunter2hunter2xyz" not in diff and "Old Name" in diff


def test_output_files_get_normal_permissions(tmp_path: Path) -> None:
    import os

    from n8n_doctor.files import write_text

    target = tmp_path / "r.json"
    write_text(target, "{}")
    umask = os.umask(0)
    os.umask(umask)
    assert target.stat().st_mode & 0o777 == 0o666 & ~umask


def _code_with_two_secrets(notes: str | None = None) -> dict[str, Any]:
    code = 'const apiKey = "AbC123dEf456GhI789";\nconst dbPassword = "Zx9Yw8Vu7Ts6Rq5";\nreturn $("Fetch-Data").all();'
    extra = {"notes": notes} if notes else {}
    return workflow(
        [trigger(), node("Fetch data", "noOp"), node("Code", "code", {"jsCode": "=" + code}, 2, **extra)],
        link("Start", "Fetch data", "Code"),
    )


@pytest.mark.parametrize("notes", [None, "n8n-doctor-disable hardcoded-secret"])
def test_fix_diff_masks_every_secret(notes: str | None, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    data = _code_with_two_secrets(notes)
    secrets = ("AbC123dEf456GhI789", "Zx9Yw8Vu7Ts6Rq5")
    result = fix_workflow(from_data(data, "x.json")[0])
    assert result.changes and "Fetch data" in result.diff  # the rename is in the diff
    assert not any(s in result.diff for s in secrets)
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    for fmt in ("diff", "json"):
        main(["fix", "--no-config", "-f", fmt, str(path)])
        out = capsys.readouterr().out
        shown = json.loads(out)["diff"] if fmt == "json" else out  # the JSON Patch is exact by design
        assert "Fetch data" in shown and not any(s in shown for s in secrets)
    via_mcp = json.dumps(mcp.call_tool("n8n_fix", {"workflow": data, "output": "diff"}))
    assert "Fetch data" in via_mcp and not any(s in via_mcp for s in secrets)


def test_fix_diff_masks_allowed_secrets_and_ones_in_comments() -> None:
    from n8n_doctor.config import Config

    code = '// old key: const token = "Q1w2E3r4T5y6U7i8O9p0";\nconst apiKey = "pk_test_9a8b7c6d5e4f";\nreturn $("Fetch-Data").all();'
    data = workflow([trigger(), node("Fetch data", "noOp"), node("Code", "code", {"jsCode": "=" + code}, 2)], link("Start", "Fetch data", "Code"))
    cfg = Config(options={"N8D101": {"allow": ["^pk_test_"]}})
    diff = fix_workflow(from_data(data, "x.json")[0], cfg=cfg).diff
    assert "Fetch data" in diff and "Q1w2E3r4T5y6U7i8O9p0" not in diff and "pk_test_9a8b7c6d5e4f" not in diff


def test_lint_reports_every_distinct_secret() -> None:
    findings = [f for f in run(from_data(_code_with_two_secrets(), "x")) if f.rule.id == "N8D101"]
    assert len(findings) == 2 and all(f.parameter == "jsCode" for f in findings)
    h = node("H", "httpRequest", {"url": f"https://api.example.com/bot{TELEGRAM}/x?api_key=Q1w2E3r4T5y6U7i8O9p0", "options": {}}, 4.2)
    assert len([f for f in run(from_data(workflow([trigger(), h], link("Start", "H")), "x")) if f.rule.id == "N8D101"]) == 2


def test_private_key_body_is_masked() -> None:
    from n8n_doctor.rules import masked_workflow

    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 4
    pem = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    assert body not in redact(json.dumps(pem))
    wf = masked_workflow(from_data(workflow([trigger(), node("S", "set", {"key": pem})]), "x")[0])
    assert body not in json.dumps(wf.data)


def test_explain_masks_secrets_found_by_name_only() -> None:
    h = node("Send", "httpRequest", {"url": "https://api.example.com/v1?password=hunter2hunter2"}, 4.2)
    note = node("Note", "stickyNote", {"content": "key Bearer " + "q1" * 15})
    wf = from_data(workflow([trigger(), h, note], link("Start", "Send")), "x")[0]
    text = outline(wf) + json.dumps(as_dict(wf))
    assert "hunter2hunter2" not in text and "q1" * 15 not in text


def test_executions_mask_basic_auth() -> None:
    import base64

    from n8n_doctor import executions

    token = base64.b64encode(b"admin:s3cretPass!").decode()

    class FakeClient:
        base = "https://n8n.example.com/api/v1"

        def executions(self, *args: Any, **kwargs: Any) -> Any:
            msg = f"request failed with headers Authorization: Basic {token} (Basic authentication)"
            yield {"id": "1", "workflowId": "w", "startedAt": "t", "data": {"resultData": {"error": {"message": msg}}}}

        def workflow(self, wid: str) -> Any:
            return {"name": "W"}

    blob = json.dumps(executions.summarize(FakeClient(), None, 5, pattern_only=True))  # type: ignore[arg-type]
    assert token not in blob and "Basic ***" in blob and "Basic authentication" in blob


def test_expression_scan_is_linear() -> None:
    unit = "{{" + "$a" * 1000 + "}"  # many {{ without }}: each span is looked for once
    value = unit * (2_000_000 // len(unit))
    wf = from_data(workflow([trigger(), node("S", "set", {"value": value})], link("Start", "S")), "x")[0]
    started = time.perf_counter()
    run([wf])
    assert time.perf_counter() - started < 3


def test_reachability_is_linear() -> None:
    count = 8000
    nodes = [node("Agent", "@n8n/n8n-nodes-langchain.agent")] + [node(f"T{i}", "noOp") for i in range(count)]
    conns: dict[str, Any] = {"Start": {"main": [[{"node": "Agent", "type": "main", "index": 0}]]}}
    for i in reversed(range(count)):  # T0 -> Agent, T1 -> T0, ...: a chain of sub-nodes, found in one pass
        target = "Agent" if i == 0 else f"T{i - 1}"
        conns[f"T{i}"] = {"ai_tool": [[{"node": target, "type": "ai_tool", "index": 0}]]}
    wf = from_data(workflow([trigger(), *nodes], conns), "x", limits=BIG)[0]
    started = time.perf_counter()
    reached = wf.reachable_from_triggers()
    assert len(reached) == count + 2 and time.perf_counter() - started < 1


def test_allow_patterns_are_bounded() -> None:
    from n8n_doctor.config import ConfigError, compile_allow

    with pytest.raises(ConfigError):
        compile_allow("a" * 201)
    long_secret = "ghp_" + "A" * 2000
    h = node("S", "set", {"token": long_secret})
    from n8n_doctor.config import Config

    cfg = Config(options={"N8D101": {"allow": ["^ghp_"]}})
    assert [f.rule.id for f in run(from_data(workflow([trigger(), h], link("Start", "S")), "x"), cfg) if f.rule.id == "N8D101"]


def test_lone_surrogates_in_names_reach_every_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = workflow(
        [trigger("Start \ud800"), node("H \udfff", "httpRequest", {"url": "https://a.example"}, 4.2)], link("Start \ud800", "H \udfff"), name="W \ud83d"
    )
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))  # \ud800 escapes in the file, lone surrogates once parsed
    for argv in (["lint", "-f", "sarif"], ["lint", "-f", "json"], ["lint"], ["lint", "-f", "github"], ["explain", "-f", "json"], ["explain"], ["fix"]):
        code = main([*argv, "--no-config", str(path)])
        out, err = capsys.readouterr()
        assert code in (0, 1) and "internal error" not in err, argv
        out.encode("utf-8")
        if "-f" in argv and argv[-1] in ("sarif", "json"):
            assert any(escaped in out for escaped in ("\\ud800", "\\udfff", "\\ud83d"))
            json.loads(out)
    report = tmp_path / "out.sarif"
    assert main(["lint", "--no-config", "-f", "sarif", "-o", str(report), str(path)]) in (0, 1)
    json.loads(report.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "token",
    [
        "pat" + "Zq7Lm2Xp9Rt4Vw." + "Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0SeZq7Lm2Xp9R",  # Airtable
        "gsk_" + "Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0SeZq7Lm2Xp9Rt4Vw8Ny3Kb",  # Groq
        "pat-na1-" + "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",  # HubSpot
        "ntn_" + "Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Seabcdefghijklm",  # Notion
    ],
)
def test_provider_tokens_are_found_and_masked(token: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # built here, not kept in a fixture, so that no whole token sits in the repository for a push scanner to stop
    data = workflow(
        [trigger(), node("N", "set", {"assignments": {"assignments": [{"id": "1", "name": "x", "type": "string", "value": token}]}}, 3.4)], link("Start", "N")
    )
    assert len([f for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]) == 1
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    for command in (["lint"], ["explain"], ["explain", "-f", "json"], ["fix", "-f", "json"]):
        main([*command, "--no-config", str(path)])
        assert token[:16] not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("secret_curl_user_password.json", "S3cr3tPassw0rd"),  # curl -u admin:... in Execute Command
        ("secret_literal_in_header_expression.json", "Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Se"),  # ={{ 'Bearer ' + '...' }}
    ],
)
def test_more_secret_forms_are_found_and_masked(name: str, secret: str, capsys: pytest.CaptureFixture[str]) -> None:
    from .conftest import REGRESSION_FIXTURES

    path = REGRESSION_FIXTURES / name
    found = [f for f in run(from_data(json.loads(path.read_text()), name)) if f.rule.id == "N8D101"]
    assert len(found) == 1, [f.message for f in run(from_data(json.loads(path.read_text()), name))]
    for command in (["lint"], ["explain"], ["explain", "-f", "json"], ["fix", "-f", "json"]):
        main([*command, "--no-config", str(path)])
        assert secret not in capsys.readouterr().out


@pytest.mark.parametrize(
    "code",
    [
        'headers["x-api-key"] = "Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Se";',
        "opts.headers['Authorization'] = 'Bearer Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Se';",
    ],
)
def test_secrets_assigned_by_index_in_code(code: str) -> None:
    for params in ({"jsCode": code}, {"language": "python", "pythonCode": code.rstrip(";")}):
        data = workflow([trigger(), node("Code", "code", params, 2)], link("Start", "Code"))
        assert [f.rule.id for f in run(from_data(data, "x")) if f.rule.id == "N8D101"] == ["N8D101"], params


@pytest.mark.parametrize(
    "query",
    [
        "api_token=Zq7Lm2Xp9Rt4Vw8N",
        "appid=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
        "private_token=Zq7Lm2Xp9Rt4Vw8N",
        "access_key=Zq7Lm2Xp9Rt4Vw8N",
        "x-api-key=Zq7Lm2Xp9Rt4Vw8N",
        "hapikey=1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
        "auth=Zq7Lm2Xp9Rt4Vw8Ny3Kb6",
        "secret_key=Zq7Lm2Xp9Rt4Vw8N",
        "subscription-key=0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
        "X-Amz-Signature=" + "0a1b2c3d4e5f6a7b8c9d" * 3 + "0a1b",
    ],
)
def test_secret_query_parameter_names(query: str) -> None:
    data = workflow([trigger(), node("Http", "httpRequest", {"url": f"https://api.example.com/v1?q=1&{query}"}, 4.2)], link("Start", "Http"))
    assert [f.rule.id for f in run(from_data(data, "x")) if f.rule.id == "N8D101"] == ["N8D101"]
    assert query.split("=")[1] not in redact(f"https://api.example.com/v1?{query}")
