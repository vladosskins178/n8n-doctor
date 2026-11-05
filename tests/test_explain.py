from __future__ import annotations

import json
from pathlib import Path

import pytest

from n8n_doctor.cli import main
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.workflow import from_data

from .conftest import link, merge, node, trigger, workflow


def _wf(data: dict) -> object:  # type: ignore[type-arg]
    return from_data(data, "x")[0]


def test_outline_branches_loops_and_merges() -> None:
    ifn = node("Check", "if", {"conditions": {"conditions": [{"leftValue": "={{ $json.a }}", "rightValue": 1}]}}, 2)
    data = workflow(
        [trigger(), ifn, node("Yes", "noOp"), node("No", "noOp"), node("Join", "noOp"), node("Lost", "noOp")],
        merge(
            link("Start", "Check"),
            link("Check", "Yes", output=0),
            link("Check", "No", output=1),
            link("Yes", "Join"),
            link("No", "Join"),
            link("Join", "Check"),
        ),
    )
    text = outline(_wf(data), unicode=False)  # type: ignore[arg-type]
    assert "[true] Yes (noOp)" in text and "[false] No (noOp)" in text
    assert "-> Join (continues above)" in text and "(loop) back to Check" in text
    assert "Never runs (not reachable from a trigger): Lost" in text


def test_outline_without_trigger_and_sticky_notes() -> None:
    data = workflow([node("A", "noOp"), node("Note", "stickyNote", {"content": "# Title\nDoes things"})])
    text = outline(_wf(data))  # type: ignore[arg-type]
    assert "cannot start on its own" in text and "Title Does things" in text


def test_mermaid_escapes_and_json() -> None:
    data = workflow([trigger('Say "hi" <now>'), node("B", "noOp", disabled=True)], link('Say "hi" <now>', "B"))
    chart = mermaid(_wf(data))  # type: ignore[arg-type]
    assert '"hi"' not in chart and "#quot;hi#quot;" in chart and "stroke-dasharray" in chart
    d = as_dict(_wf(data))  # type: ignore[arg-type]
    assert d["nodes"][0]["outputs"] == [{"label": "", "to": ["B"]}]


def test_a_filter_output_with_nothing_on_it_is_not_shown() -> None:
    data = workflow([trigger(), node("F", "filter", {}, 2), node("Next", "noOp")], merge(link("Start", "F"), link("F", "Next")))
    wf = _wf(data)
    text = outline(wf, unicode=False)  # type: ignore[arg-type]
    assert "discarded" not in text
    filter_node = next(n for n in as_dict(wf)["nodes"] if n["name"] == "F")  # type: ignore[arg-type]
    assert [o["label"] for o in filter_node["outputs"]] == ["kept"]


def test_a_connected_discarded_output_is_shown() -> None:
    data = workflow(
        [trigger(), node("F", "filter", {}, 2), node("Next", "noOp"), node("Rest", "noOp")],
        merge(link("Start", "F"), link("F", "Next"), link("F", "Rest", output=1)),
    )
    wf = _wf(data)
    assert "[discarded] Rest" in outline(wf, unicode=False)  # type: ignore[arg-type]
    filter_node = next(n for n in as_dict(wf)["nodes"] if n["name"] == "F")  # type: ignore[arg-type]
    assert [o["label"] for o in filter_node["outputs"]] == ["kept", "discarded"]


def test_explain_and_fix_read_past_log_lines(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = workflow([trigger(), node("Next", "code", {"jsCode": "$('start').all();"}, 2)], link("Start", "Next"))
    path = tmp_path / "wf.json"
    path.write_text("Warning: something\nPermissions 0644 are too wide\n" + json.dumps(data), encoding="utf-8")
    assert main(["explain", "--no-config", str(path)]) == 0
    assert "Next" in capsys.readouterr().out
    assert main(["fix", "--no-config", str(path)]) == 0
    capsys.readouterr()
    out = tmp_path / "out.json"
    assert main(["fix", "--no-config", "--write", "-o", str(out), str(path)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["nodes"][1]["name"] == "Next"
