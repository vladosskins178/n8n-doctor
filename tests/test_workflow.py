from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.expressions import find_refs, replace_ref, strip_js_comments
from n8n_doctor.lint import collect, run
from n8n_doctor.workflow import WorkflowError, from_data, load_file, node_offsets, parse_text

from .conftest import EXAMPLES, link, node, trigger, workflow


def test_accepts_single_array_and_api_shapes() -> None:
    wf = workflow([trigger()])
    assert len(from_data(wf, "a")) == 1
    many = from_data([wf, {**wf, "name": "Two"}], "b")
    assert [w.name for w in many] == ["Test", "Two"] and [w.position for w in many] == [1, 2]
    assert len(from_data({"data": [wf]}, "c")) == 1
    assert from_data([wf], "d")[0].position == 0


@pytest.mark.parametrize("data", [{}, [], {"nodes": "x"}, [1, 2], "text", {"data": [{"a": 1}]}])
def test_rejects_non_workflows(data: Any) -> None:
    with pytest.raises(WorkflowError):
        from_data(data, "x")


def test_invalid_json_and_tolerant_shapes() -> None:
    with pytest.raises(WorkflowError, match="invalid JSON"):
        parse_text("{nope", "x")
    odd = {
        "nodes": [None, {"name": "A", "type": "n8n-nodes-base.noOp", "parameters": "bad", "typeVersion": "2"}],
        "connections": {"A": {"main": [None, "x", [{"bad": 1}]]}, "B": 3},
    }
    wf = from_data(odd, "x")[0]
    assert [n.name for n in wf.nodes] == ["A"] and wf.nodes[0].parameters == {} and wf.edges == []


def test_node_lines_follow_the_file() -> None:
    wf = load_file(EXAMPLES / "lead-intake.json")[0]
    text = (EXAMPLES / "lead-intake.json").read_text()
    for n in wf.nodes:
        assert f'"name": "{n.name}"' in "\n".join(text.splitlines()[n.line - 1 : n.line + 40])
    assert node_offsets("[]") == [] and node_offsets('{"nodes": []}') == []
    minified = json.dumps(workflow([trigger(), node("A", "noOp")]))
    assert len(node_offsets(minified)) == 2


def test_offsets_ignore_tricky_strings() -> None:
    text = '{"name": "x \\" [ {", "nodes": [ {"name": "a"}, {"name": "b ] }"} ], "connections": {}}'
    offs = node_offsets(text)
    assert len(offs) == 2 and text[offs[1]] == "{"


def test_collect_folders_skips_non_workflows(tmp_path: Path) -> None:
    (tmp_path / "flows").mkdir()
    (tmp_path / "flows" / "a.json").write_text(json.dumps(workflow([trigger()])))
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.json").write_text(json.dumps(workflow([trigger()])))
    (tmp_path / "broken.json").write_text("{")
    flows, skipped, errors = collect([tmp_path])
    assert len(flows) == 1 and len(skipped) == 2 and errors == []
    _, _, errors = collect([tmp_path / "package.json", tmp_path / "missing.json"])
    assert len(errors) == 2


def test_collect_does_not_follow_symlinked_folders(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.json").write_text(json.dumps(workflow([trigger()])))
    project = tmp_path / "project"
    project.mkdir()
    (project / "link").symlink_to(outside)
    flows, _, _ = collect([project])
    assert flows == []


def test_reachability_and_downstream() -> None:
    wf = from_data(workflow([trigger(), node("A", "noOp"), node("B", "noOp")], link("Start", "A", "B")), "x")[0]
    assert wf.downstream(["Start"]) == {"A", "B"}
    assert wf.reachable_from_triggers() == {"Start", "A", "B"}


def test_find_refs_all_syntaxes() -> None:
    text = """$('A') $("B b") $(`C`) $node["D"] $node['E\\'s'] $items("F", 0) $node.G $node.context"""
    assert [r.name for r in find_refs(text)] == ["A", "B b", "C", "D", "E's", "F", "G"]


def test_strip_comments_keeps_strings_and_offsets() -> None:
    code = "const a = '// not a comment'; // gone\n/* block\n gone */ b"
    out = strip_js_comments(code)
    assert len(out) == len(code) and "'// not a comment'" in out and "gone" not in out and out.count("\n") == 2


@pytest.mark.parametrize(
    ("text", "new", "expected"),
    [
        ("$('Old').item", "New", "$('New').item"),
        ('$node["Old"].json', "It's", '$node["It\'s"].json'),
        ("$node.Old.json", "New_1", "$node.New_1.json"),
        ("$node.Old.json", "New one", "$node['New one'].json"),
        ("$items('Old', 0)", "New", "$items('New', 0)"),
    ],
)
def test_replace_ref(text: str, new: str, expected: str) -> None:
    ref = find_refs(text)[0]
    assert replace_ref(text, ref, new) == expected


def test_deeply_nested_json_is_rejected_cleanly() -> None:
    deep = '{"nodes": [], "connections": {}, "x": ' + "[" * 5000 + "]" * 5000 + "}"
    with pytest.raises(WorkflowError):
        parse_text(deep, "deep.json")
    medium = '{"nodes": [], "connections": {}, "x": ' + "[" * 300 + "]" * 300 + "}"
    with pytest.raises(WorkflowError, match="nested"):
        parse_text(medium, "medium.json")


def test_long_chain_explains_without_recursion() -> None:
    from n8n_doctor.explain import outline

    names = ["Start"] + [f"N{i}" for i in range(3000)]
    data = workflow([trigger()] + [node(n, "noOp") for n in names[1:]], link(*names))
    text = outline(from_data(data, "x")[0])
    assert "N2999" in text and max(len(line) for line in text.splitlines()) < 100


def test_lines_in_arrays_and_with_null_nodes() -> None:
    one = workflow([trigger(), node("A", "noOp")], link("Start", "A"))
    two = workflow([node("X", "noOp"), node("Y", "noOp"), node("Z", "noOp")])
    text = json.dumps([one, {"not": "a workflow"}, two], indent=2)
    flows = parse_text(text, "all.json")
    lines = text.splitlines()
    for wf in flows:
        for n in wf.nodes:
            assert any(f'"name": "{n.name}"' in line for line in lines[n.line - 1 : n.line + 12]), (wf.name, n.name)
    with_null = json.dumps({"nodes": [None, node("B", "noOp")], "connections": {}}, indent=2)
    b = parse_text(with_null, "x")[0].nodes[0]
    assert '"name": "B"' in "\n".join(with_null.splitlines()[b.line - 1 : b.line + 12])
    single = json.dumps([one], indent=2)
    assert parse_text(single, "x")[0].nodes[1].line > 1


def test_bom_on_any_input() -> None:
    assert parse_text("﻿" + json.dumps(workflow([trigger()])), "<stdin>")


def test_lines_ignore_nodes_arrays_elsewhere() -> None:
    data = {"name": "x", "staticData": {"nodes": [1, 2]}, "nodes": [trigger(), node("A", "noOp")], "connections": {}}
    text = json.dumps(data, indent=2)
    wf = parse_text(text, "x")[0]
    assert '"name": "A"' in "\n".join(text.splitlines()[wf.nodes[1].line - 1 : wf.nodes[1].line + 12])
    two = [data, {**data, "name": "y"}]
    text2 = json.dumps({"data": two}, indent=2)
    flows = parse_text(text2, "x")
    assert flows[1].nodes[0].line > flows[0].nodes[1].line


def test_parameter_paths_are_built_as_needed() -> None:
    from n8n_doctor.expressions import format_path, iter_leaves

    params = {"a": {"b": [{"c": "x"}, "y"]}, "d": "z", "": {"e": "w"}}
    leaves = list(iter_leaves(params))
    assert [(p.keys(), v) for p, v in leaves] == [(("a", "b", 0, "c"), "x"), (("a", "b", 1), "y"), (("d",), "z"), (("", "e"), "w")]
    assert [p.text() for p, _ in leaves] == [format_path(p.keys()) for p, _ in leaves] == ["a.b[0].c", "a.b[1]", "d", "e"]
    assert [(p.first, p.last, p.depth) for p, _ in leaves] == [("a", "c", 4), ("a", 1, 3), ("d", "d", 1), ("", "e", 2)]


@pytest.mark.parametrize("wrap", [lambda w: {"id": 123, "workflow": w}, lambda w: {"workflow": {"id": 123, "name": "T", "workflow": w}}])
def test_n8n_io_template_wrappers_are_unwrapped(wrap: Any) -> None:
    data = json.loads((EXAMPLES / "lead-intake.json").read_text())
    text = json.dumps(wrap(data), indent=2)
    (wf,) = parse_text(text, "template.json")
    assert wf.name == data["name"] and len(wf.nodes) == len(data["nodes"])
    plain = parse_text(json.dumps(data, indent=2), "x")[0]
    offset = text.count("\n", 0, text.index('"nodes"')) - json.dumps(data, indent=2).count("\n", 0, json.dumps(data, indent=2).index('"nodes"'))
    assert [n.line for n in wf.nodes] == [n.line + offset for n in plain.nodes]


def _template(real: dict[str, Any]) -> dict[str, Any]:
    """What api.n8n.io/api/templates/workflows/<id> returns: a summary with its own short "nodes", and the workflow inside."""
    summary = [{"id": 19, "name": "n8n-nodes-base.httpRequest", "displayName": "HTTP Request"}]
    return {"workflow": {"id": 123, "name": "T", "views": 5, "nodes": summary, "workflow": real, "user": {"name": "a"}}}


def test_an_n8n_io_template_response_gives_the_workflow_not_the_summary() -> None:
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL2xQw"
    real = {
        "name": "Real",
        "nodes": [{"name": "H", "type": "n8n-nodes-base.httpRequest", "parameters": {"url": f"https://a.example.com/?t={token}"}}],
        "connections": {},
    }
    text = json.dumps(_template(real), indent=2)
    (wf,) = parse_text(text, "t.json")
    assert wf.name == "Real" and [n.name for n in wf.nodes] == ["H"]
    assert wf.nodes[0].line == text.count("\n", 0, text.index('"name": "H"'))  # the line of the node's opening brace
    assert any(f.rule.id == "N8D101" for f in run([wf]))


def test_a_summary_after_the_inner_workflow_does_not_win_either() -> None:
    real = {"nodes": [{"name": "H", "type": "n8n-nodes-base.set", "parameters": {}}], "connections": {}}
    data = {"workflow": {"workflow": real, "nodes": [{"id": 1}, {"id": 2}]}}
    assert [n.name for n in parse_text(json.dumps(data), "t.json")[0].nodes] == ["H"]


def test_a_real_workflow_with_a_stray_workflow_field_stays_itself() -> None:
    outer = {
        "name": "Outer",
        "nodes": [{"name": "A", "type": "n8n-nodes-base.set", "parameters": {}}],
        "connections": {},
        "workflow": {"nodes": [], "connections": {}},
    }
    assert parse_text(json.dumps(outer), "t.json")[0].name == "Outer"


def test_a_summary_without_a_workflow_inside_is_still_read() -> None:
    data = {"workflow": {"id": 1, "nodes": [{"name": "A", "type": "n8n-nodes-base.set", "parameters": {}}], "workflow": {"name": "not one"}}}
    assert [n.name for n in parse_text(json.dumps(data), "t.json")[0].nodes] == ["A"]


def test_an_object_with_a_workflow_field_that_is_not_one_is_not_a_workflow() -> None:
    with pytest.raises(WorkflowError):
        from_data({"id": 1, "workflow": {"name": "x"}}, "x")
