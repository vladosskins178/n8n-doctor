from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.cli import main
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.workflow import from_data

from .conftest import EXAMPLES, link, load, merge, node, of, trigger, workflow


def _fix(data: dict[str, Any], rules: set[str] | None = None) -> Any:
    return fix_workflow(from_data(data, "x.json")[0], rules)


def _apply_patch(doc: Any, patch: list[dict[str, Any]]) -> Any:
    """A minimal RFC 6902 applier (add/replace/remove) to check the emitted patch."""
    for op in patch:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["path"].split("/")[1:]]
        target = doc
        for p in parts[:-1]:
            target = target[int(p)] if isinstance(target, list) else target[p]
        last: Any = int(parts[-1]) if isinstance(target, list) else parts[-1]
        if op["op"] == "remove":
            del target[last]
        else:
            target[last] = op["value"]
    return doc


def test_fixes_example_and_patch_matches() -> None:
    wf = from_data(json.loads((EXAMPLES / "lead-intake.json").read_text()), "lead-intake.json")[0]
    result = fix_workflow(wf)
    assert result.changes and result.diff.startswith("lead-intake.json:\n")
    assert _apply_patch(json.loads(json.dumps(wf.data)), result.patch) == result.fixed
    after = {f.rule.id for f in run(from_data(result.fixed, "fixed.json"))}
    assert not after & {"N8D211", "N8D207"}
    assert "N8D302" in after  # a timeout is only set when asked
    assert "N8D101" in after  # secrets are never auto-fixed


def test_http_fixes_respect_methods() -> None:
    get = node("Get", "httpRequest", {"url": "https://x.example.com"}, 4.2)
    post = node("Post", "httpRequest", {"url": "https://x.example.com", "method": "POST", "options": {"timeout": 1}}, 4.2)
    fixed = _fix(workflow([trigger(), get, post], link("Start", "Get", "Post"))).fixed
    by_name = {n["name"]: n for n in fixed["nodes"]}
    assert by_name["Get"]["retryOnFail"] is True
    assert "retryOnFail" not in by_name["Post"]


def test_dangling_connections_removed() -> None:
    data = workflow([trigger(), node("A", "noOp")], merge(link("Start", "A"), link("A", "Gone"), link("Ghost", "A")))
    result = _fix(data)
    assert "Ghost" not in result.fixed["connections"] and result.fixed["connections"]["A"]["main"] == [[]]
    assert not [f for f in run(from_data(result.fixed, "x")) if f.rule.id == "N8D205"]


def test_reference_fix_only_with_clear_match() -> None:
    a = node("Set", "set", {"x": "={{ $('fetch lead').item.json.a }} {{ $('Unknown thing').item }}"}, 3.4)
    result = _fix(workflow([trigger(), node("Fetch lead", "noOp"), a], link("Start", "Fetch lead", "Set")))
    value = next(n for n in result.fixed["nodes"] if n["name"] == "Set")["parameters"]["x"]
    assert "$('Fetch lead')" in value and "$('Unknown thing')" in value


def test_rule_selection_and_settings() -> None:
    data = workflow([trigger()], settings={"saveDataErrorExecution": "none"}, pinData={"Start": [{"json": {}}]})
    only = _fix(data, {"N8D310"})
    assert "saveDataErrorExecution" not in only.fixed["settings"] and only.fixed["pinData"]
    nothing = _fix(workflow([trigger()]))
    assert nothing.changes == [] and nothing.diff == ""


def test_cli_dry_run_never_writes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = tmp_path / "wf.json"
    original = (EXAMPLES / "lead-intake.json").read_text()
    src.write_text(original)
    assert main(["fix", "--dry-run", str(src)]) == 0
    out, err = capsys.readouterr()
    assert '"Enrich lead" retryOnFail: added true' in out and "dry run" in err
    assert sorted(p.name for p in tmp_path.iterdir()) == ["wf.json"] and src.read_text() == original


def test_cli_write_creates_new_file_only(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = tmp_path / "wf.json"
    original = (EXAMPLES / "lead-intake.json").read_text()
    src.write_text(original)
    assert main(["fix", "--write", str(src)]) == 0
    fixed = tmp_path / "wf.fixed.json"
    assert fixed.exists() and src.read_text() == original
    assert json.loads(fixed.read_text())["pinData"] == {}
    assert main(["fix", "--write", str(src)]) == 2  # exists, no --force
    assert main(["fix", "--write", "--force", str(src)]) == 0
    assert main(["fix", "--write", "-o", str(src), str(src)]) == 2  # never the input
    assert src.read_text() == original
    capsys.readouterr()
    assert main(["fix", "-f", "json", "--include-patch", str(src)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["changes"] and payload["patch"]
    assert main(["fix", "--include-patch", str(src)]) == 2  # with --format json only


def test_cli_fix_rejects_multi_workflow_files(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    src = tmp_path / "all.json"
    src.write_text(json.dumps([workflow([trigger()]), workflow([trigger()])]))
    assert main(["fix", str(src)]) == 2


def test_fix_handles_keys_with_dots_and_brackets() -> None:
    s = node("Sheet", "googleSheets", {"columns": {"value": {"user.email": "={{ $('fetch lead').item.json.e }}", "a[0]": "x"}}}, 4)
    result = _fix(workflow([trigger(), node("Fetch lead", "noOp"), s], link("Start", "Fetch lead", "Sheet")))
    fixed = next(n for n in result.fixed["nodes"] if n["name"] == "Sheet")
    assert fixed["parameters"]["columns"]["value"]["user.email"] == "={{ $('Fetch lead').item.json.e }}"
    wf_data = workflow([trigger(), node("Fetch lead", "noOp"), s], link("Start", "Fetch lead", "Sheet"))
    assert _apply_patch(json.loads(json.dumps(wf_data)), result.patch) == result.fixed


def test_duplicate_names_are_not_fixed() -> None:
    a = node("HTTP", "httpRequest", {"url": "https://a.example.com"}, 4.2)
    b = node("HTTP", "httpRequest", {"url": "https://b.example.com", "options": {"timeout": 5}}, 4.2)
    data = workflow([trigger(), a, b], link("Start", "HTTP"))
    result = _fix(data)
    assert result.fixed["nodes"][2]["parameters"]["options"]["timeout"] == 5
    assert _apply_patch(json.loads(json.dumps(data)), result.patch) == result.fixed


def test_fix_respects_config() -> None:
    from n8n_doctor.config import Config

    get = node("Get", "httpRequest", {"url": "https://x.example.com", "options": {"timeout": 1}}, 4.2)
    data = workflow([trigger(), get], link("Start", "Get"))
    assert _fix(data).changes
    from n8n_doctor.workflow import from_data as fd

    assert fix_workflow(fd(data, "x")[0], None, Config(disabled={"N8D303"})).changes == []


def test_crashes_exit_2_not_1(capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "wf.json"
    src.write_text(json.dumps(workflow([trigger()])))

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr("n8n_doctor.lint.run", boom)
    assert main(["lint", "--no-config", str(src)]) == 2
    assert "internal error" in capsys.readouterr().err


def test_fix_adds_expression_prefix() -> None:
    s = node("Set", "set", {"a": "{{ $json.x }}", "b": "Hi {{ $json.name }}!"}, 3.4)
    data = workflow([trigger(), s], link("Start", "Set"))
    result = _fix(data, {"N8D212"})
    params = result.fixed["nodes"][1]["parameters"]
    assert params == {"a": "={{ $json.x }}", "b": "=Hi {{ $json.name }}!"}
    assert _apply_patch(json.loads(json.dumps(data)), result.patch) == result.fixed


def test_rename_and_prefix_fixes_combine() -> None:
    s = node("Set", "set", {"a": "{{ $('fetch lead').item.json.x }}"}, 3.4)
    data = workflow([trigger(), node("Fetch lead", "noOp"), s], link("Start", "Fetch lead", "Set"))
    result = _fix(data)
    assert result.fixed["nodes"][2]["parameters"]["a"] == "={{ $('Fetch lead').item.json.x }}"
    assert _apply_patch(json.loads(json.dumps(data)), result.patch) == result.fixed


def test_fix_skips_suppressed_nodes_and_odd_options() -> None:
    quiet = node("Quiet", "set", {"a": "={{ $('fetch lead').item.json }}"}, 3.4, notes="n8n-doctor-disable N8D207")
    loud = node("Loud", "set", {"a": "={{ $('fetch lead').item.json }}"}, 3.4)
    odd = node("Odd", "httpRequest", {"url": "https://x.example.com", "options": "={{ $('fetch lead').item.json.o }}"}, 4.2)
    data = workflow([trigger(), node("Fetch lead", "noOp"), quiet, loud, odd], link("Start", "Fetch lead", "Quiet", "Loud", "Odd"))
    result = _fix(data)
    by_name = {n["name"]: n for n in result.fixed["nodes"]}
    assert "fetch lead" in by_name["Quiet"]["parameters"]["a"] and "Fetch lead" in by_name["Loud"]["parameters"]["a"]
    assert by_name["Odd"]["parameters"]["options"] == "={{ $('Fetch lead').item.json.o }}"
    assert _apply_patch(json.loads(json.dumps(data)), result.patch) == result.fixed


def test_review_starts_with_the_file_name() -> None:
    from n8n_doctor.files import json_dumps
    from n8n_doctor.workflow import parse_text

    data = workflow([trigger(), node("A", "noOp")], link("Start", "A"), pinData={"A": [{"json": {}}]})
    for text in (json_dumps(data), json_dumps(data) + "\n", json.dumps(data)):
        review = fix_workflow(parse_text(text, "wf.json")[0]).diff
        assert review == "wf.json:\n  pinData: removed 1 pinned record of 1 node\n"


def test_folder_lint_skips_fixed_copies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = workflow([node("A", "noOp")])
    (tmp_path / "wf.json").write_text(json.dumps(workflow([trigger()])))
    (tmp_path / "wf.fixed.json").write_text(json.dumps(broken))
    assert main(["lint", "--no-config", "-f", "json", "--fail-on", "warning", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["lint", "--no-config", "-f", "json", "--fail-on", "warning", str(tmp_path / "wf.fixed.json")]) == 1


def test_fixable_count_and_fix_skip_nodes_that_share_a_name(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    http = node("HTTP", "httpRequest", {"url": "https://a.example"}, 4.2)
    data = workflow([trigger(), http, dict(http), node("Other", "httpRequest", {"url": "https://b.example"}, 4.2)], link("Start", "HTTP", "Other"))
    found = run(from_data(data, "x.json"))
    assert {f.node for f in found if f.rule.id == "N8D303" and f.fixable} == {"Other"}
    assert all(not f.fixable for f in found if f.node == "HTTP")
    result = _fix(data, {"N8D303"})
    assert result.changes == ['N8D303 "Other": retry on fail, 3 tries, 1000 ms apart (GET)']
    assert result.skipped == ['N8D303 "HTTP": not fixed, 2 nodes are named "HTTP" (rename them first, see N8D206)']
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    assert main(["lint", "--no-config", "--select", "N8D303", str(path)]) == 0
    assert "1 can be fixed automatically" in capsys.readouterr().out
    main(["fix", "--no-config", "--rule", "N8D303", str(path)])
    out = capsys.readouterr().out
    assert "Skipped:" in out and "2 nodes are named" in out


def test_change_lines_count_their_connections() -> None:
    one = workflow(
        [trigger(), node("A", "noOp")], {"Start": {"main": [[{"node": "A", "type": "main", "index": 0}, {"node": "Gone", "type": "main", "index": 0}]]}}
    )
    assert fix_workflow(load(one), {"N8D205"}).changes == ['N8D205 "Start": removed a connection to missing node "Gone"']
    two = workflow([trigger()], {"Start": {"main": [[{"node": "G1", "type": "main", "index": 0}, {"node": "G2", "type": "main", "index": 0}]]}})
    assert fix_workflow(load(two), {"N8D205"}).changes == ['N8D205 "Start": removed connections to missing nodes "G1", "G2"']


@pytest.mark.parametrize(
    ("ref", "fixed"),
    [
        ('$("Fetch custmer")', '$("Fetch customer")'),
        ("$('Fetch custmer')", "$('Fetch customer')"),
        ("$(`Fetch custmer`)", "$(`Fetch customer`)"),
        ('$node["Fetch custmer"]', '$node["Fetch customer"]'),
        ("$items('Fetch custmer', 0)", "$items('Fetch customer', 0)"),
    ],
)
def test_reference_fix_keeps_the_quote_style(ref: str, fixed: str) -> None:
    from n8n_doctor.expressions import find_refs, replace_ref

    text = f"x = {ref}.first();"
    assert replace_ref(text, find_refs(text)[0], "Fetch customer") == f"x = {fixed}.first();"


_T = {"type": "main", "index": 0}


def _by_id(connections: dict[str, Any]) -> dict[str, Any]:
    return workflow([node("Start", "manualTrigger", id="id-a"), node("B", "noOp", id="id-b"), node("C", "noOp", id="id-c")], connections)


def test_connections_keyed_by_node_id_get_the_names() -> None:
    data = _by_id({"id-a": {"main": [[{"node": "id-b", **_T}]]}, "id-b": {"main": [[{"node": "C", **_T}]]}})
    messages = [f.message for f in of(data, "N8D205")]
    assert any('"id-a"' in m and '"Start"' in m and "id" in m for m in messages) and any('"id-b"' in m and '"B"' in m for m in messages)
    result = fix_workflow(load(data), {"N8D205"})
    assert result.fixed["connections"] == {"Start": {"main": [[{"node": "B", **_T}]]}, "B": {"main": [[{"node": "C", **_T}]]}}
    assert _apply_patch(data, result.patch)["connections"] == result.fixed["connections"]
    assert all("node id" in c for c in result.changes) and not result.skipped
    assert of(result.fixed, "N8D205") == []


def test_a_target_given_by_node_id_gets_the_name() -> None:
    data = _by_id({"Start": {"main": [[{"node": "id-b", **_T}, {"node": "Gone", **_T}]]}})
    assert any('"id-b"' in f.message and '"B"' in f.message for f in of(data, "N8D205"))
    result = fix_workflow(load(data), {"N8D205"})
    assert result.fixed["connections"] == {"Start": {"main": [[{"node": "B", **_T}]]}}
    assert _apply_patch(data, result.patch)["connections"] == result.fixed["connections"]
    assert any('"Gone"' in c and "removed" in c for c in result.changes)


def test_an_id_of_several_nodes_keeps_its_wiring() -> None:
    data = workflow(
        [trigger(), node("A", "noOp", id="same"), node("B", "noOp", id="same")],
        {"same": {"main": [[{"node": "Start", **_T}]]}, "Start": {"main": [[{"node": "same", **_T}]]}},
    )
    messages = [f.message for f in of(data, "N8D205")]
    assert len(messages) == 2 and all('"same"' in m and '"A"' in m and '"B"' in m for m in messages)
    assert all(f.fixable is False for f in of(data, "N8D205"))
    result = fix_workflow(load(data), {"N8D205"})
    assert result.fixed["connections"] == data["connections"] and result.changes == []
    assert result.skipped and all('"same"' in note for note in result.skipped)


def test_an_id_key_next_to_the_name_key_keeps_its_wiring() -> None:
    data = _by_id({"id-a": {"main": [[{"node": "B", **_T}]]}, "Start": {"main": [[{"node": "C", **_T}]]}})
    assert [f.fixable for f in of(data, "N8D205")] == [False]
    result = fix_workflow(load(data), {"N8D205"})
    assert result.fixed["connections"] == data["connections"] and result.skipped


def test_an_unknown_key_is_still_removed_and_said() -> None:
    data = _by_id({"Gone": {"main": [[{"node": "B", **_T}]]}})
    assert fix_workflow(load(data), {"N8D205"}).changes == ['N8D205 removed connections from missing node "Gone"']
