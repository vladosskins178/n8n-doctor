"""`executions` fails closed: a message whose workflow secrets cannot be checked is hidden, not pattern-masked."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor import cli, executions
from n8n_doctor.api import ApiError, RunTimeout
from n8n_doctor.report import Style

from .conftest import link, node, trigger, workflow

SECRET = "hunter2-Pa55w0rd-xyz"  # only in the workflow (a header value): no pattern recognises it in a message


def _execution(i: int, version: str, padding: int = 0, with_copy: bool = True) -> dict[str, Any]:
    params: dict[str, Any] = {"url": "https://a.example", "headerParameters": {"parameters": [{"name": "X-Api-Key", "value": SECRET}]}}
    nodes = [trigger(), node("Call", "httpRequest", params, 4.2)]
    if padding:
        nodes.append(node("Note", "stickyNote", {"content": "x" * padding}))
    flow = workflow(nodes, link("Start", "Call"), name="Flow", versionId=version)
    error = {"message": f"Request failed: header was {SECRET}", "name": "NodeApiError", "node": {"name": "Call"}}
    ex: dict[str, Any] = {"id": str(i), "workflowId": "w1", "startedAt": f"2026-11-0{i % 9 + 1}T00:00:00Z", "data": {"resultData": {"error": error}}}
    if with_copy:
        ex["workflowData"] = flow
    return ex


class _Client:
    base = "https://n8n.example.com/api/v1"
    _key = "n8n_api_key_value_123456"

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self.items = items

    def executions(self, *args: Any, **kwargs: Any) -> Any:
        yield from self.items

    def workflow(self, wid: str) -> Any:
        raise ApiError("gone")


def _shown(result: dict[str, Any]) -> str:
    return json.dumps(result) + executions.render_text(result, Style(False))


def test_normal_case_masks_with_the_workflow_and_shows_the_message() -> None:
    result = executions.summarize(_Client([_execution(1, "v1")]), None, 10)  # type: ignore[arg-type]
    (g,) = result["groups"]
    assert SECRET not in _shown(result)
    assert g["example"] == "Request failed: header was ***" and g["message_hidden"] is False
    assert g["error_type"] == "NodeApiError" and g["workflow"] == "Flow" and g["node"] == "Call"


def test_exhausted_budget_hides_messages(capsys: pytest.CaptureFixture[str]) -> None:
    # the first copy fits, the second is over the budget: its messages are hidden, the details stay
    items = [_execution(1, "v1"), _execution(2, "v2", padding=4000), _execution(3, "v2", padding=4000)]
    result = executions.summarize(_Client(items), None, 10, masker_budget=3000)  # type: ignore[arg-type]
    shown = _shown(result)
    assert SECRET not in shown and "header was" in shown  # the first is still shown, masked
    hidden = [g for g in result["groups"] if g["message_hidden"]]
    assert len(hidden) == 1 and hidden[0]["count"] == 2
    assert hidden[0]["example"] == hidden[0]["error"] == executions.HIDDEN_BUDGET
    assert "--max-masker-mb" in hidden[0]["example"] and "header" not in hidden[0]["example"]
    # without the workflow masker, names are hidden too: the workflow by id, the node by position and type
    assert hidden[0]["error_type"] == "NodeApiError" and hidden[0]["node"] == "node #1 (httpRequest)" and hidden[0]["workflow"] == "workflow w1"
    assert hidden[0]["names_hidden"] is True
    assert hidden[0]["first_seen"] and hidden[0]["execution_ids"] == ["2", "3"]
    assert result["hidden_messages"] == 2
    err = capsys.readouterr().err
    assert err.count("--max-masker-mb") == 1 and "hidden" in err


def test_unusable_workflow_hides_messages() -> None:
    # no copy in the execution and the workflow cannot be fetched
    result = executions.summarize(_Client([_execution(1, "v1", with_copy=False)]), None, 10)  # type: ignore[arg-type]
    (g,) = result["groups"]
    assert SECRET not in _shown(result) and g["message_hidden"] is True and g["example"] == executions.HIDDEN_UNREADABLE
    # a copy that is not a usable workflow
    ex = _execution(2, "v1")
    ex["workflowData"] = {"name": "Flow", "nodes": "broken"}
    result = executions.summarize(_Client([ex]), None, 10)  # type: ignore[arg-type]
    assert SECRET not in _shown(result) and result["groups"][0]["message_hidden"] is True


def test_pattern_masking_only_opts_into_pattern_masking(capsys: pytest.CaptureFixture[str]) -> None:
    items = [_execution(1, "v1"), _execution(2, "v2", padding=4000)]
    items[1]["data"]["resultData"]["error"]["message"] = f"password={SECRET}9 and {SECRET}"
    result = executions.summarize(_Client(items), None, 10, masker_budget=3000, pattern_only=True)  # type: ignore[arg-type]
    shown = _shown(result)
    assert f"{SECRET}9" not in shown  # the patterns still mask password=...
    assert SECRET in shown  # the less safe opt-in: the secret known only to the workflow shows
    assert not any(g["message_hidden"] for g in result["groups"]) and result["hidden_messages"] == 0
    assert "pattern" in capsys.readouterr().err


def _cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], items: list[dict[str, Any]], *args: str) -> tuple[int, str]:
    class _Api:
        @staticmethod
        def from_env(*_: Any) -> _Client:
            return _Client(items)

    monkeypatch.setattr(cli, "Client", _Api)
    code = cli.main(["executions", "--no-config", "--color", "never", *args])
    return code, capsys.readouterr().out


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_cli_budget_flag_and_opt_in(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], fmt: str) -> None:
    big = 1024 * 1024 + 10  # over a 1 MB budget on its own
    items = [_execution(1, "v1", padding=big), _execution(2, "v1", padding=big)]
    code, out = _cli(monkeypatch, capsys, items, "-f", fmt, "--max-masker-mb", "1")
    assert code == 0 and SECRET not in out and "message hidden" in out and "NodeApiError" in out and "workflow w1" in out
    code, out = _cli(monkeypatch, capsys, items, "-f", fmt)  # the default 16 MB budget is enough
    assert code == 0 and SECRET not in out and "message hidden" not in out and "header was ***" in out
    code, out = _cli(monkeypatch, capsys, items, "-f", fmt, "--max-masker-mb", "1", "--pattern-masking-only")
    assert code == 0 and SECRET in out and "message hidden" not in out


def test_cli_budget_from_config(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Any) -> None:
    cfg = tmp_path / "n8n-doctor.toml"
    cfg.write_text("[limits]\nmax-masker-mb = 1\n")
    items = [_execution(1, "v1", padding=1024 * 1024 + 10)]

    class _Api:
        @staticmethod
        def from_env(*_: Any) -> _Client:
            return _Client(items)

    monkeypatch.setattr(cli, "Client", _Api)
    assert cli.main(["executions", "--config", str(cfg), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and "message hidden" in out
    assert cli.main(["executions", "--max-masker-mb", "0"]) == 2


NAMED_SECRET = "Zq8vR2mK9xT4pL7wB3nY"  # a workflow and node name that repeats a header value


def _named(i: int, version: str, padding: int = 0, with_copy: bool = True) -> dict[str, Any]:
    ex = _execution(i, version, padding, with_copy)
    ex["data"]["resultData"]["error"]["node"]["name"] = f"Call {NAMED_SECRET}"
    if with_copy:
        flow = ex["workflowData"]
        flow["name"] = f"Flow {NAMED_SECRET}"
        flow["nodes"][1]["name"] = f"Call {NAMED_SECRET}"
        flow["nodes"][1]["parameters"]["headerParameters"]["parameters"][0]["value"] = NAMED_SECRET
    return ex


@pytest.mark.parametrize("with_copy", [True, False])
def test_names_are_hidden_without_a_workflow_masker(with_copy: bool) -> None:
    items = [_named(1, "v1", padding=4000, with_copy=with_copy)]
    result = executions.summarize(_Client(items), None, 10, masker_budget=100)  # type: ignore[arg-type]
    shown = _shown(result)
    (g,) = result["groups"]
    assert NAMED_SECRET not in shown and "Flow" not in shown and g["workflow"] == "workflow w1"
    assert g["node"] == ("node #1 (httpRequest)" if with_copy else "node (name hidden)")
    assert "workflow w1 > node" in executions.render_text(result, Style(False))


def test_names_are_shown_masked_with_a_workflow_masker() -> None:
    result = executions.summarize(_Client([_named(1, "v1")]), None, 10)  # type: ignore[arg-type]
    (g,) = result["groups"]
    assert NAMED_SECRET not in _shown(result) and g["workflow"].startswith("Flow ") and g["node"].startswith("Call ")
    assert g["names_hidden"] is False


@pytest.mark.parametrize(
    "name",
    [
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "ghp_" + "K" * 36,
        _Client._key,
        "NodeApiError: password=hunter2",
        "nodeApiError",
        "Error" + "x" * 70,
        "SecretTokenError",  # fine as a class name, but not if the workflow knows it (see below)
    ],
)
def test_error_type_shows_only_class_names(name: str) -> None:
    ex = _execution(1, "v1")
    ex["data"]["resultData"]["error"]["name"] = name
    if name == "SecretTokenError":
        ex["workflowData"]["nodes"][1]["parameters"]["headerParameters"]["parameters"][0]["value"] = name
    result = executions.summarize(_Client([ex]), None, 10)  # type: ignore[arg-type]
    (g,) = result["groups"]
    assert g["error_type"] == "Error" and name not in _shown(result)


@pytest.mark.parametrize("name", ["NodeApiError", "NodeOperationError", "TypeError", "WorkflowActivationException"])
def test_error_type_keeps_class_names(name: str) -> None:
    ex = _execution(1, "v1", with_copy=False)
    ex["data"]["resultData"]["error"]["name"] = name
    result = executions.summarize(_Client([ex]), None, 10)  # type: ignore[arg-type]
    assert result["groups"][0]["error_type"] == name and name in executions.render_text(result, Style(False))


def test_long_messages_are_masked_within_the_shown_part() -> None:
    ex = _execution(1, "v1")
    ex["data"]["resultData"]["error"]["message"] = f"password={SECRET} " + "y" * 300_000 + " api_key=TAILSECRET99"
    result = executions.summarize(_Client([ex]), None, 10)  # type: ignore[arg-type]
    shown = _shown(result)
    assert SECRET not in shown and "TAILSECRET99" not in shown
    assert len(result["groups"][0]["example"]) <= 500 and executions.MESSAGE_SHOWN <= executions.MESSAGE_MASKED


def test_text_without_start_times_has_no_dangling_separator() -> None:
    ex = _execution(1, "v1")
    del ex["startedAt"]
    out = executions.render_text(executions.summarize(_Client([ex]), None, 10), Style(False))  # type: ignore[arg-type]
    assert "executions 1\n" in out and "; " not in out.split("executions 1")[1].splitlines()[0]


def test_copies_of_the_api_key_are_masked() -> None:
    import base64
    import urllib.parse

    key = _Client._key
    variants = [
        key,
        key.upper(),
        base64.b64encode(key.encode()).decode(),
        base64.urlsafe_b64encode(key.encode()).decode().rstrip("="),
        urllib.parse.quote(key + "/", safe=""),
        base64.b64encode(f"user:{key}".encode()).decode(),  # Basic auth with the key as the password
    ]
    items = [_execution(i, "v1") for i in range(1, len(variants) + 1)]
    for item, variant in zip(items, variants, strict=True):
        item["data"]["resultData"]["error"]["message"] = f"call failed with {variant} sent"
        item["data"]["resultData"]["error"]["node"]["name"] = f"Node {variant}"
    shown = _shown(executions.summarize(_Client(items), None, 10))  # type: ignore[arg-type]
    for variant in variants:
        assert variant not in shown and variant.rstrip("=") not in shown, variant


class _SlowClient(_Client):
    """Two executions, then the run's --timeout runs out."""

    def executions(self, *args: Any, **kwargs: Any) -> Any:
        yield from self.items
        raise RunTimeout("GET executions: the n8n API calls took longer than 300s in all (raise it with --timeout)")


def test_timeout_keeps_partial_results(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    items = [_execution(1, "v1"), _execution(2, "v1")]
    result = executions.summarize(_SlowClient(items), None, 10)  # type: ignore[arg-type]
    assert result["executions"] == 2 and "took longer than 300s" in result["incomplete"]

    class _Api:
        @staticmethod
        def from_env(*_: Any) -> _Client:
            return _SlowClient(items)

    monkeypatch.setattr(cli, "Client", _Api)
    for fmt in ("text", "json"):
        assert cli.main(["executions", "--no-config", "--color", "never", "-f", fmt]) == cli.EXIT_INCOMPLETE == 3
        captured = capsys.readouterr()
        assert "2 error executions" in captured.out or '"executions": 2' in captured.out
        assert "warning: results are incomplete" in captured.err and SECRET not in captured.out


def test_timeout_before_any_execution_is_an_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class _Api:
        @staticmethod
        def from_env(*_: Any) -> _Client:
            return _SlowClient([])

    monkeypatch.setattr(cli, "Client", _Api)
    assert cli.main(["executions", "--no-config"]) == 2
    assert "took longer than 300s" in capsys.readouterr().err
