"""Edge cases across commands: execution masker caching and message patterns, names kept out of limit and API
errors, truncated files in a folder, rule false positives, MCP arguments and the GitHub Action's inputs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import executions, mcp
from n8n_doctor.api import ApiError, normalize_base
from n8n_doctor.cli import main
from n8n_doctor.limits import Limits
from n8n_doctor.lint import collect
from n8n_doctor.rules import secret_masker
from n8n_doctor.workflow import LimitError, from_data

from .conftest import link, node, trigger, workflow

SECRET = "hunter2-Pa55w0rd-xyz"


def _execution(i: int, version: str, message: str, secret: str = SECRET) -> dict[str, Any]:
    flow = workflow(
        [
            trigger(),
            node("Call", "httpRequest", {"url": "https://a.example", "headerParameters": {"parameters": [{"name": "X-Api-Key", "value": secret}]}}, 4.2),
        ],
        link("Start", "Call"),
        name="Flow",
        versionId=version,
    )
    return {"id": str(i), "workflowId": "w1", "startedAt": "t", "workflowData": flow, "data": {"resultData": {"error": {"message": message}}}}


class _Client:
    base = "https://n8n.example.com/api/v1"
    _key = "n8n_api_" + "k" * 24

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def executions(self, *args: Any, **kwargs: Any) -> Any:
        yield from self.items

    def workflow(self, wid: str) -> Any:
        raise ApiError("gone")


def test_execution_maskers_are_kept_in_a_small_lru(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[str] = []
    real = secret_masker

    def counting(wf: Any) -> Any:
        built.append(str(wf.data.get("versionId")))
        return real(wf)

    monkeypatch.setattr(executions, "secret_masker", counting)
    # two versions alternating: built once each
    items = [_execution(i, f"v{i % 2}", f"failed with {SECRET}") for i in range(10)]
    result = executions.summarize(_Client(items), None, 100)  # type: ignore[arg-type]
    assert built == ["v0", "v1"] and SECRET not in json.dumps(result)
    # six versions, then the first again: it was evicted and is built again
    built.clear()
    items = [_execution(i, f"v{i}", f"failed with {SECRET}") for i in range(6)] + [_execution(6, "v0", f"failed with {SECRET}")]
    executions.summarize(_Client(items), None, 100)  # type: ignore[arg-type]
    assert built == ["v0", "v1", "v2", "v3", "v4", "v5", "v0"]


def test_execution_masker_work_is_capped_per_run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(executions, "MASKER_BUDGET_CHARS", 3000)
    items = [_execution(i, f"v{i}", f"failed: password={SECRET}{i} and {SECRET}") for i in range(40)]
    built = 0
    real = secret_masker

    def counting(wf: Any) -> Any:
        nonlocal built
        built += 1
        return real(wf)

    monkeypatch.setattr(executions, "secret_masker", counting)
    result = executions.summarize(_Client(items), None, 100, pattern_only=True)  # type: ignore[arg-type]
    err = capsys.readouterr().err
    assert 0 < built < 10 and err.count("pattern") == 1 and "workflow" in err
    blob = json.dumps(result)
    assert f"{SECRET}1" not in blob  # pattern-only masking still hides password=...


@pytest.mark.parametrize(
    ("message", "token"),
    [
        ("Invalid API key provided: sk_test_" + "51HxAbCdEfGh1234567890", "sk_test_" + "51HxAbCdEfGh1234567890"),
        ("The provided key 'q8Zk3LmN0pRt5VwX' is invalid", "q8Zk3LmN0pRt5VwX"),
        ("auth failed for user@example.com:ATATT" + "3xFfGF0aBcDeFgH123", "ATATT" + "3xFfGF0aBcDeFgH123"),
        ("bad signature sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081884c7d659a2feaa0c55ad015"),
        ("Mailgun rejected key-3ax6xnjp29jd6fds4gc373sgvjxteol0", "3ax6xnjp29jd6fds4gc373sgvjxteol0"),
    ],
)
def test_execution_message_patterns(message: str, token: str) -> None:
    assert token not in executions.mask_message(message)


def test_execution_messages_never_show_the_api_key() -> None:
    client = _Client([])
    client.items = [_execution(1, "v", f"echo {client._key} back", secret="unrelated-0000")]
    blob = json.dumps(executions.summarize(client, None, 5))  # type: ignore[arg-type]
    assert client._key not in blob


def test_execution_prose_without_tokens_is_kept() -> None:
    assert executions.mask_message("The provided key 'Enter' is invalid") == "The provided key 'Enter' is invalid"
    assert executions.mask_message("Invalid API key provided") == "Invalid API key provided"


# --- limit errors before a workflow loads: no names --------------------------------------------------


def test_limit_errors_show_node_index_and_length_not_names() -> None:
    name = f"Route {SECRET}"
    switch = node(name, "switch", {"rules": {"values": [{}] * 5}}, 3)
    with pytest.raises(LimitError) as exc:
        from_data(workflow([trigger(), switch]), "x", limits=Limits(max_outputs=3))
    assert SECRET not in str(exc.value) and f"node #1 ({len(name)} chars)" in str(exc.value)
    conns = {name: {"main": [[{"node": "Start", "type": "main", "index": 0}]] * 5}}
    with pytest.raises(LimitError) as exc:
        from_data(workflow([trigger(), node(name, "noOp")], conns), "x", limits=Limits(max_outputs=3))
    assert SECRET not in str(exc.value) and f"node #1 ({len(name)} chars)" in str(exc.value)
    conns = {name: {"main": [[{"node": "Start", "type": "main", "index": 0}] * 5]}}
    with pytest.raises(LimitError) as exc:
        from_data(workflow([trigger()], conns), "x", limits=Limits(max_targets=3))
    assert SECRET not in str(exc.value) and f"({len(name)} chars)" in str(exc.value)
    big = node(name, "set", {"items": list(range(20))})
    with pytest.raises(LimitError) as exc:
        from_data(workflow([trigger(), big]), "x", limits=Limits(max_list_length=10))
    assert SECRET not in str(exc.value) and f"node #1 ({len(name)} chars)" in str(exc.value)
    deep = node(name, "set", {"a" * 30: {"b" * 30: "x"}})
    with pytest.raises(LimitError) as exc:
        from_data(workflow([trigger(), deep]), "x", limits=Limits(max_path_chars=40))
    assert SECRET not in str(exc.value) and f"node #1 ({len(name)} chars)" in str(exc.value)


def test_api_url_errors_never_echo_the_url() -> None:
    for url in ("ftp://user:pa55word@host/x", "n8n.example.com/?token=abc123secret", "javascript:alert(1)"):
        with pytest.raises(ApiError) as exc:
            normalize_base(url)
        assert "pa55word" not in str(exc.value) and "abc123secret" not in str(exc.value) and "alert" not in str(exc.value)


def test_redirect_errors_strip_user_info() -> None:
    from n8n_doctor.api import _NoRedirect

    with pytest.raises(ApiError) as exc:
        _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://u:pa55word@evil.example/x?token=abc123secret")
    assert "pa55word" not in str(exc.value) and "abc123secret" not in str(exc.value)


# --- truncated files in a folder -----------------------------------------------------------------------


@pytest.mark.parametrize("text", ['{"nodes":[', '{"name": "My flow", "nodes": [{"name": "A", "type": "n8n-nod', '{"connections": {', '{"name":"x"'])
def test_truncated_workflow_files_are_errors(tmp_path: Path, text: str) -> None:
    (tmp_path / "flow.json").write_text(text)
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions": {,}')
    flows, skipped, errors = collect([tmp_path])
    assert not flows and len(errors) == 1 and "flow.json" in errors[0] and len(skipped) == 1 and "tsconfig.json" in skipped[0]


def test_one_skipped_file_is_reported_in_the_singular(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "flow.json").write_text(json.dumps(workflow([trigger()])))
    main(["lint", "--no-config", str(tmp_path)])
    assert "skipped 1 JSON file that is not an n8n workflow" in capsys.readouterr().err


# --- false positives -----------------------------------------------------------------------------------


def _rules_of(data: dict[str, Any], rule_id: str) -> list[Any]:
    from n8n_doctor.lint import run

    return [f for f in run(from_data(data, "x")) if f.rule.id == rule_id]


def test_template_literal_references_are_not_unknown_nodes() -> None:
    code = "for (const nodeName of names) { out.push($(`${nodeName}`).item); out.push($('${nodeName}').first()); }\nreturn $('Gone').all();"
    found = _rules_of(workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code")), "N8D207")
    assert [f.message for f in found] == ['jsCode references node "Gone", which does not exist']


@pytest.mark.parametrize(
    "value", ["Bearer $REPLICATE_API_TOKEN", "$API_TOKEN", "${API_TOKEN}", "process.env.API_TOKEN", "Bearer {{ $env.API_TOKEN }}", "$env.API_TOKEN"]
)
def test_environment_variable_references_are_not_secrets(value: str) -> None:
    headers = {"parameters": [{"name": "Authorization", "value": value}]}
    data = workflow([trigger(), node("Call", "httpRequest", {"url": "https://a", "headerParameters": headers, "password": value}, 4.2)], link("Start", "Call"))
    assert _rules_of(data, "N8D101") == []


def test_real_bearer_token_is_still_a_secret() -> None:
    headers = {"parameters": [{"name": "Authorization", "value": "Bearer r8_AbCdEf0123456789xyzQW"}]}
    data = workflow([trigger(), node("Call", "httpRequest", {"url": "https://a", "headerParameters": headers}, 4.2)], link("Start", "Call"))
    assert len(_rules_of(data, "N8D101")) == 1


def test_reachability_does_not_pass_through_missing_nodes() -> None:
    conns = {"Start": {"main": [[{"node": "Ghost", "type": "main", "index": 0}]]}, "Ghost": {"main": [[{"node": "B", "type": "main", "index": 0}]]}}
    found = _rules_of(workflow([trigger(), node("B", "noOp")], conns), "N8D201")
    assert [f.node for f in found] == ["B"]


# --- MCP --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [["n8n_lint"], {"a": 1}, 7, None])
def test_mcp_tool_name_must_be_a_string(name: Any) -> None:
    import io

    out = io.StringIO()
    mcp.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name}}) + "\n"), out)
    reply = json.loads(out.getvalue())
    assert reply["error"]["code"] == -32602


def test_mcp_fix_unknown_rule_message() -> None:
    reply = mcp.call_tool("n8n_fix", {"workflow": workflow([trigger()]), "rules": ["nope"]})
    assert reply["isError"] and reply["content"][0]["text"] == "Error: unknown rule 'nope'"


# --- action.yml ---------------------------------------------------------------------------------------------


# a wrapper, not a symlink: on Python 3.10 a symlink outside the test's own venv loses that venv and its packages
_FAKE_VENV = f"""mkdir -p "$venv/bin" && printf '#!/bin/sh\\nexec {sys.executable} "$@"\\n' > "$venv/bin/python" && chmod +x "$venv/bin/python\""""


def _install_script() -> str:
    text = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    start = text.index("      run: |\n", text.index("- name: Install n8n-doctor")) + len("      run: |\n")
    end = text.index("\n\n", start)
    return "\n".join(line[8:] for line in text[start:end].splitlines())


def test_action_boolean_inputs_are_read_the_same_way() -> None:
    text = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    assert "fromJSON" not in text and "inputs.annotations)" not in text and "inputs.upload-sarif)" not in text
    assert text.count("$(flag ") == 3


@pytest.mark.parametrize(
    ("value", "on"),
    [("true", True), (" TRUE ", True), ("Yes", True), ("oN", True), ("1", True), ("false", False), ("", False), ("nope", False), ("0", False)],
)
def test_action_booleans_trim_and_ignore_case(tmp_path: Path, value: str, on: bool) -> None:

    if shutil.which("bash") is None:
        pytest.skip("needs bash")
    (tmp_path / "flows").mkdir()
    (tmp_path / "flows" / ".git").mkdir()
    for name in ("a.json", "b.json", "[x].json", ".hidden.json", ".git/config.json"):
        (tmp_path / "flows" / name).write_text("{}")
    script = _install_script().replace('"$n8nd_py" -m pip install', ": pip install")
    script = script.replace('"$py" -m venv "$venv"', _FAKE_VENV)
    env_file = tmp_path / "env"
    env = {
        "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",  # the script's python3 is the test interpreter
        "RUNNER_TEMP": str(tmp_path / "runner"),
        "GITHUB_ENV": str(env_file),
        "ACTION_PATH": str(Path(__file__).resolve().parents[1]),
        "INLINE": value if value else "true",
        "ANNOTATIONS": value,
        "UPLOAD": value,
        "N8ND_ARGS": "",
        "N8ND_PATHS": "flows/*.json 'flows/[x].json' missing/*.json flows/**/*.json",
        "N8ND_SARIF": "reports/out/n8n.sarif",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    done = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    values = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
    assert values["N8ND_ANNOTATE"] == values["N8ND_UPLOAD"] == ("true" if on else "false")
    # every path once (flows/[x].json is matched and given), hidden files included, nothing from .git
    assert json.loads(values["N8ND_PATH_LIST"]) == ["flows/.hidden.json", "flows/[x].json", "flows/a.json", "flows/b.json", "missing/*.json"]
    assert (tmp_path / "reports" / "out").is_dir()
    if value in ("false", "0"):
        assert values["N8ND_FLAGS"] == "--no-inline-suppress"


def _expand_with_action(tmp_path: Path, paths: str, args: str = "") -> subprocess.CompletedProcess[str]:
    """The install step of action.yml, run up to the path expansion, in ``tmp_path``."""
    script = _install_script().replace('"$n8nd_py" -m pip install', ": pip install")
    script = script.replace('"$py" -m venv "$venv"', _FAKE_VENV)
    env = {
        "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path / "runner"),
        "GITHUB_ENV": str(tmp_path / "env"),
        "ACTION_PATH": str(Path(__file__).resolve().parents[1]),
        "INLINE": "true",
        "ANNOTATIONS": "true",
        "UPLOAD": "false",
        "N8ND_ARGS": args,
        "N8ND_PATHS": paths,
        "N8ND_SARIF": "",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    return subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)


def _path_list(tmp_path: Path) -> list[str]:
    values = dict(line.split("=", 1) for line in (tmp_path / "env").read_text().splitlines())
    paths: list[str] = json.loads(values["N8ND_PATH_LIST"])
    return paths


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash and symlinks")
def test_action_globs_do_not_follow_symlink_loops(tmp_path: Path) -> None:
    flows = tmp_path / "flows" / "sub"
    flows.mkdir(parents=True)
    (flows / "a.json").write_text("{}")
    (flows / "loop").symlink_to(tmp_path / "flows")  # flows/sub/loop -> flows: a cycle
    (flows / "up").symlink_to(tmp_path)  # and another one to the top
    started = time.perf_counter()
    done = _expand_with_action(tmp_path, "'flows/**/*.json' '**/a.json'")
    assert time.perf_counter() - started < 1
    assert done.returncode == 0, done.stderr
    assert _path_list(tmp_path) == ["flows/sub/a.json"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_action_globs_semantics_and_match_cap(tmp_path: Path) -> None:
    for name in ("top.json", "a/x.json", "a/b/y.json", "a/b/c/z.json", "a/.hidden/h.json", "node_modules/m.json", "a/b/n.txt"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("{}")
    assert _expand_with_action(tmp_path, "'**/*.json'").returncode == 0
    assert _path_list(tmp_path) == ["a/.hidden/h.json", "a/b/c/z.json", "a/b/y.json", "a/x.json", "top.json"]
    # * stays inside one folder; ** is any number of folders, none included
    assert _expand_with_action(tmp_path, "'a/*/*.json' 'a/b/**/z.json' 'a/**/y.json' a/?.json").returncode == 0
    assert _path_list(tmp_path) == ["a/.hidden/h.json", "a/b/y.json", "a/b/c/z.json", "a/x.json"]
    many = tmp_path / "many"
    many.mkdir()
    for i in range(10_001):
        (many / f"{i}.json").touch()
    done = _expand_with_action(tmp_path, "'many/*.json'")
    assert done.returncode != 0 and "10,000" in done.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_action_checks_it_installed_its_own_version(tmp_path: Path) -> None:
    action = tmp_path / "action"
    action.mkdir()
    (action / "pyproject.toml").write_text('[project]\nname = "n8n-doctor"\nversion = "9.9.9"\n')
    script = _install_script().replace('"$n8nd_py" -m pip install', ": pip install")
    script = script.replace('"$py" -m venv "$venv"', _FAKE_VENV)
    env = {
        "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin",
        "RUNNER_TEMP": str(tmp_path / "runner"),
        "GITHUB_ENV": str(tmp_path / "env"),
        "ACTION_PATH": str(action),
        **dict.fromkeys(("INLINE", "ANNOTATIONS", "UPLOAD", "N8ND_ARGS", "N8ND_PATHS", "N8ND_SARIF"), ""),
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
    }
    done = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode != 0 and "but the action is 9.9.9" in done.stderr


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash and symlinks")
def test_action_globs_skip_symlinks_like_a_folder_scan(tmp_path: Path) -> None:
    (tmp_path / "wf" / "real").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "o.json").write_text("{}")
    (tmp_path / "wf" / "a.json").write_text("{}")
    (tmp_path / "wf" / "real" / "b.json").write_text("{}")
    (tmp_path / "wf" / "link.json").symlink_to(tmp_path / "outside" / "o.json")
    (tmp_path / "wf" / "linked").symlink_to(tmp_path / "outside")
    assert _expand_with_action(tmp_path, "'wf/*' 'wf/**/*.json'").returncode == 0
    assert _path_list(tmp_path) == ["wf/a.json", "wf/real", "wf/real/b.json"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_action_paths_are_normalised_before_dedupe_and_trailing_slash_means_folders(tmp_path: Path) -> None:
    (tmp_path / "wf" / "sub").mkdir(parents=True)
    (tmp_path / "wf" / "a.json").write_text("{}")
    (tmp_path / "wf" / "sub" / "b.json").write_text("{}")
    assert _expand_with_action(tmp_path, "./wf/a.json wf/a.json 'wf//a.json' './wf/*.json'").returncode == 0
    assert _path_list(tmp_path) == ["wf/a.json"]
    assert _expand_with_action(tmp_path, "'wf/**/'").returncode == 0
    assert _path_list(tmp_path) == ["wf/sub"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("args", ["-h", "--help", "--hel", "--version", "--fail-on warning --help"])
def test_action_args_cannot_ask_for_help_or_version(tmp_path: Path, args: str) -> None:
    (tmp_path / "a.json").write_text("{}")
    done = _expand_with_action(tmp_path, "a.json", args)
    assert done.returncode != 0 and "would print help or the version" in done.stderr


@pytest.mark.parametrize("where", ["typeVersion", "parameter"])
def test_a_number_too_large_has_a_clean_message(tmp_path: Path, capsys: pytest.CaptureFixture[str], where: str) -> None:
    big = "9" * 5000
    version, value = (big, "1") if where == "typeVersion" else ("1", big)
    entry = {"name": "A", "type": "n8n-nodes-base.noOp", "typeVersion": "VERSION", "position": [0, 0], "parameters": {"n": "VALUE"}}
    text = json.dumps({"name": "x", "nodes": [entry], "connections": {}}, indent=1).replace('"VERSION"', version).replace('"VALUE"', value)
    path = tmp_path / "big.json"
    path.write_text(text)
    assert main(["lint", str(path)]) == 2
    err = capsys.readouterr().err
    assert "invalid JSON (a number with 5,000 digits on line" in err and "too large" in err
    assert "set_int_max_str_digits" not in err and "4300" not in err


def _sarif_step() -> str:
    text = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
    start = text.index("run: >-\n", text.index("- name: SARIF report")) + len("run: >-\n")
    end = text.index("\n\n", start)
    return " ".join(line.strip() for line in text[start:end].splitlines())


def _run_sarif_step(tmp_path: Path, sarif: Path, input_file: Path) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "N8ND_PY": sys.executable,
        "N8ND_ARGS": "--no-config",
        "N8ND_CONFIG": "none",
        "N8ND_SARIF": str(sarif),
        "N8ND_PATH_LIST": json.dumps([str(input_file)]),
        "GITHUB_OUTPUT": str(tmp_path / "output"),
    }
    return subprocess.run(["bash", "-c", _sarif_step()], env=env, capture_output=True, text=True, check=False, cwd=tmp_path)


def test_action_fails_when_the_sarif_file_cannot_be_written(tmp_path: Path) -> None:
    good = tmp_path / "wf.json"
    good.write_text(json.dumps(workflow([trigger()])))
    assert _run_sarif_step(tmp_path, tmp_path / "missing" / "out.sarif", good).returncode != 0
    assert not (tmp_path / "output").exists() or "path=" not in (tmp_path / "output").read_text()


def test_action_passes_when_the_sarif_file_is_written(tmp_path: Path) -> None:
    good = tmp_path / "wf.json"
    good.write_text(json.dumps(workflow([trigger()])))
    sarif = tmp_path / "out.sarif"
    done = _run_sarif_step(tmp_path, sarif, good)
    assert done.returncode == 0 and sarif.is_file() and "path=" in (tmp_path / "output").read_text()
    broken = tmp_path / "broken.json"
    broken.write_text("{")  # an input error: the report is still written, the lint step afterwards fails the job
    done = _run_sarif_step(tmp_path, sarif, broken)
    assert done.returncode == 0
