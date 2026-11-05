"""One budget of nodes plus embedded workflows per file: past it the file is refused, or embedded text is only scanned."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.cli import main
from n8n_doctor.explain import outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.limits import DEFAULT, Limits
from n8n_doctor.lint import run
from n8n_doctor.rules import known_secrets
from n8n_doctor.workflow import LimitError, from_data

from .conftest import node, trigger, workflow

SECRET = "Qz7vK2mPx9Lw4Tb"


def _embedding(text: Any, name: str = "Sub") -> dict[str, Any]:
    return node(name, "executeWorkflow", {"source": "parameter", "workflowJson": text}, 1.2)


def _header(value: str = SECRET) -> dict[str, Any]:
    entry = {"name": "Authorization", "value": value}
    return node("Call", "httpRequest", {"url": "https://x.example.com", "headerParameters": {"parameters": [entry]}}, 4.2)


def test_the_default_is_documented() -> None:
    assert DEFAULT.max_file_nodes == 50_000
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    assert "`--max-file-nodes` / `max-file-nodes`" in readme and "50,000" in readme


def test_a_file_over_the_budget_is_refused() -> None:
    data: list[dict[str, Any]] = [{"nodes": [{}] * 60} for _ in range(3)]
    with pytest.raises(LimitError, match="max-file-nodes"):
        from_data(data, "x.json", limits=Limits(max_file_nodes=100))
    assert len(from_data(data, "x.json", limits=Limits(max_file_nodes=183))) == 3
    with pytest.raises(LimitError, match="183 nodes and workflows"):
        from_data(data, "x.json", limits=Limits(max_file_nodes=182))


def test_a_file_over_the_budget_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "many.json"
    path.write_text(json.dumps([{"nodes": [{}] * 60} for _ in range(3)]), encoding="utf-8")
    for command in (["lint"], ["explain"], ["fix"]):
        assert main([*command, "--no-config", "--max-file-nodes", "100", str(path)]) == 2
        assert "max-file-nodes" in capsys.readouterr().err
    assert main(["lint", "--no-config", "--max-file-nodes", "1000", str(path)]) != 2


def test_the_workflow_limit_is_named_first() -> None:
    with pytest.raises(LimitError, match="max-nodes"):
        from_data(workflow([{}] * 60), "x.json", limits=Limits(max_file_nodes=10, max_nodes=50))


def _over_budget(secret_in_text: str) -> Any:
    big = json.dumps([workflow([trigger(f"T{i}")]) for i in range(40)])
    second = workflow([trigger("In"), _header(secret_in_text)])
    return workflow([trigger(), _embedding(big, "Big"), _embedding(json.dumps(second), "Late")])


LOW = Limits(max_file_nodes=20)


def test_embedded_text_past_the_budget_is_scanned_with_an_info_finding() -> None:
    flow = from_data(_over_budget(SECRET), "x.json", limits=LOW)[0]
    found = [f for f in run([flow]) if f.rule.id == "N8D101"]
    info = [f for f in found if f.severity.label == "info"]
    assert {f.node for f in info} == {"Big", "Late"} and all("--max-file-nodes" in (f.fix_hint or "") for f in info)
    assert [f.node for f in found if f.severity.label == "error"] == ["Late"]  # read from the text
    assert SECRET in known_secrets(flow) and SECRET not in outline(flow)


def test_the_budget_counts_what_was_read_before_it_in_document_order() -> None:
    fits = workflow([trigger(), _embedding(json.dumps(workflow([trigger("A")])), "First"), _embedding(json.dumps([workflow([])] * 40), "Big")])
    flow = from_data(fits, "x.json", limits=LOW)[0]
    assert [f.node for f in run([flow]) if f.rule.id == "N8D101"] == ["Big"]


def test_commands_read_the_same_embedded_workflows_whatever_comes_first() -> None:
    data = _over_budget(SECRET)
    first = from_data(data, "x.json", limits=LOW)[0]
    second = from_data(data, "x.json", limits=LOW)[0]
    known = known_secrets(first)  # masking walks workflows in another order than the rule
    run([second])
    assert known == known_secrets(second)


def test_the_budget_spans_the_workflows_of_a_file() -> None:
    inner = json.dumps(workflow([trigger("In")]))
    flows = from_data([workflow([trigger(), _embedding(inner)]) for _ in range(6)], "x.json", limits=Limits(max_file_nodes=20))
    over = [f for f in run(flows) if f.rule.id == "N8D101" and f.severity.label == "info"]
    assert len(over) == 5  # 18 charged up front, one embedded workflow fits in the other 2


def test_an_object_past_the_budget_is_still_walked() -> None:
    inner = workflow([trigger("In"), _header()])
    flow = from_data(workflow([trigger(), _embedding(inner)]), "x.json", limits=Limits(max_file_nodes=4))[0]
    assert SECRET in known_secrets(flow)
    assert any(f.rule.id == "N8D101" and f.severity.label == "error" for f in run([flow]))


def test_fix_still_works_past_the_budget() -> None:
    plain = node("Set", "set", {"value": "{{ $json.a }}"})
    data = _over_budget(SECRET)
    data["nodes"].append(plain)
    result = fix_workflow(from_data(data, "x.json", limits=LOW)[0])
    assert any("N8D212" in change for change in result.changes) and SECRET not in result.diff


def _timed(data: Any, tmp_path: Path, *command: str) -> int:
    path = tmp_path / "repro.json"
    path.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
    started = time.perf_counter()
    code = main([*command, "--no-config", "--fail-on", "never", str(path)] if command[0] == "lint" else [*command, "--no-config", str(path)])
    assert time.perf_counter() - started < 60
    return code


def test_thousand_workflows_of_4990_nodes_are_refused_quickly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _timed([{"nodes": [{}] * 4990} for _ in range(1000)], tmp_path, "lint") == 2
    assert "max-file-nodes" in capsys.readouterr().err


def test_one_embedded_text_of_five_million_nodes_is_only_scanned(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    text = json.dumps([{"nodes": [{}] * 4990}] * 1000, separators=(",", ":"))
    assert _timed(workflow([_embedding(text)]), tmp_path, "lint") == 0
    assert "--max-file-nodes" in capsys.readouterr().out


def test_a_thousand_texts_of_a_thousand_workflows_are_only_scanned(tmp_path: Path) -> None:
    text = json.dumps([{"nodes": [{}]}] * 1000, separators=(",", ":"))
    assert _timed(workflow([_embedding(text, f"N{i}") for i in range(1000)]), tmp_path, "lint") == 0
