"""The shape limits checked when a workflow is loaded, and the inputs at the largest size they let through."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import workflow as workflow_module
from n8n_doctor.cli import main
from n8n_doctor.config import ConfigError
from n8n_doctor.config import load as load_config
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.limits import DEFAULT, Limits
from n8n_doctor.lint import run
from n8n_doctor.model import Severity
from n8n_doctor.report import Style, counts, render_json, render_text
from n8n_doctor.rules import resolve
from n8n_doctor.workflow import LimitError, from_data, parse_text

from .conftest import link, node, trigger, workflow


def _cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def _timed(func: Any, limit: float) -> Any:
    started = time.perf_counter()
    result = func()
    assert time.perf_counter() - started < limit
    return result


def _edge(name: str) -> dict[str, Any]:
    return {"node": name, "type": "main", "index": 0}


# --- hard shape limits -------------------------------------------------------------------------------


def test_nesting_depth_is_limited(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    deep: Any = "x"
    for _ in range(70):
        deep = {"a": deep}
    data = workflow([trigger(), node("S", "set", {"v": deep})])
    with pytest.raises(LimitError, match=r"nested more than 64 levels deep.*--max-depth"):
        from_data(data, "x")
    assert from_data(data, "x", limits=Limits(max_depth=100))[0].nodes[1].name == "S"
    path = tmp_path / "deep.json"
    path.write_text(json.dumps(data))
    for command in ("lint", "explain", "fix"):
        code, _, err = _cli(capsys, command, "--no-config", str(path))
        assert code == 2 and "--max-depth" in err
    assert _cli(capsys, "lint", "--no-config", "--max-depth", "100", str(path))[0] in (0, 1)


def test_parameter_values_list_length_and_path_length_are_limited() -> None:
    many = workflow([trigger(), *(node(f"S{i}", "set", {"values": ["a"] * 1000}) for i in range(5))])
    with pytest.raises(LimitError, match=r"more than 4,000 values in node parameters.*--max-parameter-values"):
        from_data(many, "x", limits=Limits(max_parameter_values=4000))
    assert from_data(many, "x", limits=Limits(max_parameter_values=5005))
    long_list = workflow([trigger(), node("S", "set", {"values": ["a"] * 10_001})])
    with pytest.raises(LimitError, match=r"node #1 \(1 chars\) has an array of 10,001 entries.*--max-list-length"):
        from_data(long_list, "x")
    deep_key = workflow([trigger(), node("S", "set", {"k" * 600: {"k" * 600: "x"}})])
    with pytest.raises(LimitError, match=r"parameter path 1,201 characters long.*--max-path-length"):
        from_data(deep_key, "x")
    index = workflow([trigger(), node("S", "set", {"k" * 1020: ["x"] * 100})])  # "k...k[99]" is 1,024 characters
    assert from_data(index, "x")
    with pytest.raises(LimitError, match="--max-path-length"):
        from_data(workflow([trigger(), node("S", "set", {"k" * 1020: ["x"] * 1000})]), "x")


@pytest.mark.parametrize(
    ("data", "flag"),
    [
        (workflow([trigger("N" * 1025)]), "--max-name-length"),
        (workflow([trigger()], name="W" * 1025), "--max-name-length"),
        (workflow([trigger()], id="7" * 1025), "--max-name-length"),
        (workflow([node("Start", "x" * 1025)]), "--max-name-length"),
        (workflow([trigger()], {"G" * 1025: {"main": [[_edge("Start")]]}}), "--max-name-length"),
        (workflow([trigger()], {"Start": {"main": [[_edge("G" * 1025)]]}}), "--max-name-length"),
        (workflow([trigger()], pinData={"P" * 1025: []}), "--max-name-length"),
        (workflow([trigger()], {"Start": {"main": [[] for _ in range(1001)]}}), "--max-outputs"),
        (workflow([trigger()], {"Start": {"main": [[_edge("Start")] * 1001]}}), "--max-targets-per-output"),
        (workflow([trigger(), node("Sw", "switch", {"rules": {"values": [{}] * 1001}}, 3)]), "--max-outputs"),
        (workflow([trigger(), node("Sw", "switch", {"rules": {"rules": [{}] * 1001}}, 2)]), "--max-outputs"),
    ],
)
def test_names_outputs_and_connections_are_limited(data: dict[str, Any], flag: str) -> None:
    with pytest.raises(LimitError, match=flag):
        from_data(data, "x")


def test_connection_output_lists_count_against_the_connection_limit() -> None:
    names = [f"N{i}" for i in range(60)]
    conns: dict[str, Any] = {n: {"main": [[] for _ in range(1000)]} for n in names}  # 60,000 output lists, no connection
    with pytest.raises(LimitError, match="more than 50,000 connection outputs"):
        from_data(workflow([trigger(), *(node(n, "noOp") for n in names)], conns), "x")


def test_workflows_per_file_are_limited(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    flows = [workflow([trigger()], name=f"W{i}") for i in range(1001)]
    with pytest.raises(LimitError, match=r"1,001 workflows.*--max-workflows-per-file"):
        from_data(flows, "x")
    assert len(from_data(flows[:1000], "x")) == 1000
    path = tmp_path / "all.json"
    path.write_text(json.dumps(flows))
    assert _cli(capsys, "lint", "--no-config", str(path))[0] == 2
    assert _cli(capsys, "lint", "--no-config", "--max-workflows-per-file", "1001", str(path))[0] in (0, 1)


def test_secret_count_and_length_are_limited(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    many = workflow([trigger(), node("S", "set", {"options": {f"p{i}password": f"Pw{i:06d}xyzxyz" for i in range(300)}})])
    with pytest.raises(LimitError, match=r"more than 200 distinct secrets.*--max-secrets"):
        run(from_data(many, "x", limits=Limits(max_secrets=200)))
    assert len(run(from_data(many, "x", limits=Limits(max_secrets=300)))) > 0
    long = workflow([trigger(), node("S", "set", {"options": {"password": "Q1" * 1500}})])
    with pytest.raises(LimitError, match=r"3 KB of distinct secrets.*more than 2 KB.*--max-secret-kb"):
        outline(from_data(long, "x", limits=Limits(max_secret_chars=2048))[0])
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(many))
    for command in ("lint", "explain", "fix"):
        code, _, err = _cli(capsys, command, "--no-config", "--max-secrets", "10", str(path))
        assert code == 2 and "--max-secrets" in err


def test_new_limits_in_the_config_file_and_on_the_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = tmp_path / ".n8n-doctor.toml"
    cfg_path.write_text(
        "[limits]\nmax-depth = 100\nmax-workflows-per-file = 5\nmax-outputs = 10\nmax-targets-per-output = 10\nmax-name-length = 50\n"
        "max-path-length = 60\nmax-parameter-values = 99\nmax-list-length = 9\nmax-secrets = 8\nmax-secret-kb = 4\nmax-code-kb = 3\n"
        "max-findings = 7\n"
    )
    limits = load_config(cfg_path, lambda r: resolve(r).id).limits
    assert (limits.max_depth, limits.max_workflows, limits.max_outputs, limits.max_targets, limits.max_name_chars) == (100, 5, 10, 10, 50)
    assert (limits.max_path_chars, limits.max_parameter_values, limits.max_list_length, limits.max_secrets) == (60, 99, 9, 8)
    assert (limits.max_secret_chars, limits.max_code_chars, limits.max_findings) == (4096, 3072, 7)
    for bad in ("[limits]\nmax-depth = 513\n", "[limits]\nmax-depth = 7\n", "[limits]\nmax-findings = 0\n"):
        cfg_path.write_text(bad)
        with pytest.raises(ConfigError):
            load_config(cfg_path, lambda r: resolve(r).id)
    # each command offers the flags it uses
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(workflow([trigger()])))
    for command, flag in (
        ("lint", "--max-explain-depth"),
        ("lint", "--max-output-kb"),
        ("fix", "--max-output-kb"),
        ("fix", "--max-findings"),
        ("explain", "--max-findings"),
    ):
        with pytest.raises(SystemExit) as exc:
            main([command, "--no-config", flag, "5", str(path)])
        assert exc.value.code == 2, (command, flag)
    capsys.readouterr()
    assert _cli(capsys, "explain", "--no-config", "--max-output-kb", "5", "--max-depth", "20", str(path))[0] == 0
    assert _cli(capsys, "lint", "--no-config", "--max-findings", "5", "--max-secrets", "3", str(path))[0] == 0


# --- soft limits: checked in part, with a finding ---------------------------------------------------


def test_long_code_is_analysed_up_to_the_limit() -> None:
    code = '$("Gone early").item;\n' + "x/" * 600_000 + '\n$("Gone late").item;'
    wf = from_data(workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code")), "x")[0]
    found = _timed(lambda: run([wf]), 10)
    refs = [f.message for f in found if f.rule.id == "N8D207"]
    assert len(refs) == 1 and "Gone early" in refs[0]
    partial = [f for f in found if f.rule.id == "N8D001"]
    assert len(partial) == 1 and partial[0].node == "Code" and partial[0].severity == Severity.INFO
    assert "jsCode is 1,200,043 characters long: only its first 1,024 KB were checked" in partial[0].message
    # 10 million "x/" (each / a division the comment stripper looks at) in a 20 MB file
    big = "x/" * 9_900_000
    wf = from_data(workflow([trigger(), node("Code", "code", {"jsCode": big}, 2)], link("Start", "Code")), "x")[0]
    _timed(lambda: run([wf]), 15)
    assert "x/x/" in fix_workflow(wf).fixed_text


def test_findings_per_workflow_are_capped_with_a_summary_listed_last(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    hosts = [node(f"H{i}", "httpRequest", {"url": "https://a.example"}, 4.2) for i in range(150)]
    data = workflow([trigger(), *hosts], link("Start", *[h["name"] for h in hosts]))
    wf = from_data(data, "x", limits=Limits(max_findings=100))[0]
    found = run([wf])
    assert len(found) == 101 and found[-1].rule.id == "N8D001" and found[-1].extra["summary"]
    assert found[-1].message.startswith("200 more findings in this workflow not listed (limit: 100 per workflow, --max-findings)")
    assert counts(found)["info"] == 300 and found[-1].severity == Severity.INFO  # timeouts and retries, all info
    text = render_text(found, [("x", "Test", 151)], Style(False))
    assert "300 problems (0 errors, 0 warnings, 300 info)" in text and text.index("N8D001") > text.rindex("N8D302")
    assert json.loads(render_json(found, [("x", "Test", 151)]))["summary"]["fixable"] == 150  # the retries: timeouts are only fixed when asked
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    code, out, _ = _cli(capsys, "lint", "--no-config", "-f", "json", "--max-findings", "10", "--fail-on", "info", str(path))
    assert code == 1 and json.loads(out)["summary"]["info"] == 300 and len(json.loads(out)["findings"]) == 11


def test_rule_summaries_are_listed_after_the_findings_of_their_workflow() -> None:
    keys = " ".join(f"AKIAQ{i:05d}WERTYZXCVB" for i in range(5))
    data = workflow([trigger(), node("S", "set", {"value": keys}), *(node(f"H{i}", "httpRequest", {"url": "https://a"}, 4.2) for i in range(3))])
    found = run(from_data(data, "x", limits=Limits(max_findings_per_rule=2)))
    summaries = [i for i, f in enumerate(found) if f.extra.get("summary")]
    assert summaries and min(summaries) > max(i for i, f in enumerate(found) if not f.extra.get("summary"))
    one = next(f for f in found if f.rule.id == "N8D101" and f.extra.get("summary"))
    assert one.message.startswith("3 more findings of N8D101")
    single = run(from_data(workflow([trigger(), node("S", "set", {"value": keys})]), "x", limits=Limits(max_findings_per_rule=4)))
    assert any(f.message.startswith("1 more finding of N8D101 in this workflow") for f in single)


def test_min_severity_applies_before_the_limits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    hosts = [node(f"H{i}", "httpRequest", {"url": "https://a.example"}, 4.2) for i in range(250)]
    keys = " ".join(f"AKIAQ{i:05d}WERTYZXCVB" for i in range(3))
    data = workflow([trigger(), node("S", "set", {"value": keys}), *hosts], link("Start", "S"))
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    code, out, _ = _cli(capsys, "lint", "--no-config", "-f", "json", "--min-severity", "warning", str(path))
    summary = json.loads(out)["summary"]
    assert code == 1 and summary["info"] == 0 and summary["error"] == 3  # 500 info findings past the per-rule limit are not counted
    assert all(f["severity"] != "info" for f in json.loads(out)["findings"])
    code, out, _ = _cli(capsys, "lint", "--no-config", "-f", "json", str(path))
    assert json.loads(out)["summary"]["info"] == 500


# --- stdin ----------------------------------------------------------------------------------------------


def test_stdin_with_warnings_before_the_json_is_parsed_once_more_at_most(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    good = json.dumps(workflow([trigger()]), indent=2)
    monkeypatch.setattr("sys.stdin", io.StringIO("Permissions 0644 are too wide\n[WARN] old config\n" + good))
    assert _cli(capsys, "lint", "--no-config", "-")[0] == 0
    calls: list[int] = []
    real = parse_text

    def counting(text: str, source: str, limits: Limits = DEFAULT) -> Any:
        calls.append(len(text))
        return real(text, source, limits)

    monkeypatch.setattr(workflow_module, "parse_text", counting)
    junk = "warning\n" + "{}x\n" * 40  # every line starts like a JSON object: only the first one is tried
    monkeypatch.setattr("sys.stdin", io.StringIO(junk))
    code, _, err = _cli(capsys, "lint", "--no-config", "-")
    assert code == 2 and "invalid JSON" in err and len(calls) == 2


# --- the shapes that each needed a fix, at the largest size the limits let through ------------------------


def _duplicate_names(kinds: list[tuple[str, dict[str, Any], float]]) -> dict[str, Any]:
    """4,899 nodes all named X with 999 outputs of 50 connections each to Y0..Y49 (49,950 connections)."""
    nodes = [node("X", *kinds[i % len(kinds)][:2], kinds[i % len(kinds)][2]) for i in range(4899)] + [node(f"Y{j}", "noOp") for j in range(50)]
    conns: dict[str, Any] = {"X": {"main": [[_edge(f"Y{j}") for j in range(50)] for _ in range(999)]}}
    for j in range(50):
        conns[f"Y{j}"] = {"main": [[_edge("X")]]}
    return workflow(nodes, conns)


@pytest.mark.parametrize(
    "kinds",
    [
        [("manualTrigger", {}, 1), ("noOp", {}, 1)],
        [
            ("webhook", {"path": "p", "responseMode": "responseNode"}, 2),
            ("scheduleTrigger", {"rule": {"interval": [{"field": "seconds", "secondsInterval": 10}]}}, 1.2),
            ("splitInBatches", {}, 3),
            ("wait", {"amount": 10, "unit": "seconds"}, 1.1),
        ],
    ],
)
def test_many_nodes_sharing_a_name_are_walked_once(kinds: list[tuple[str, dict[str, Any], float]]) -> None:
    wf = from_data(_duplicate_names(kinds), "x")[0]
    found = _timed(lambda: run([wf]), 15)  # the shared connections are walked once, not once per copy
    assert any(f.rule.id == "N8D206" and '4,899 nodes are named "X"' in f.message for f in found)
    shown = _timed(lambda: as_dict(wf), 15)
    outputs = [n["outputs"] for n in shown["nodes"] if n["name"] == "X"]
    assert sum(len(o["to"]) for o in outputs[0]) == 999 * 50 and all(not o["to"] for out in outputs[1:] for o in out)
    _timed(lambda: (outline(wf), mermaid(wf), fix_workflow(wf)), 15)


def test_duplicate_names_keep_their_graph_meaning() -> None:
    # a connection from a shared name leaves every node of that name; one to it reaches the first
    hook = node("N", "webhook", {"path": "p", "responseMode": "responseNode"}, 2)
    data = workflow([node("N", "set", {}, 3.4), hook, node("R", "respondToWebhook", {}, 1.1)], link("N", "R"))
    assert not [f for f in run(from_data(data, "x")) if f.rule.id == "N8D209"]
    loop = workflow(
        [trigger(), node("A", "set", {}, 3.4), node("A", "set", {}, 3.4), node("B", "set", {}, 3.4)], {**link("Start", "A", "B"), "B": {"main": [[_edge("A")]]}}
    )
    assert [f.message for f in run(from_data(loop, "x")) if f.rule.id == "N8D305"] == ['loop through "A" -> "B" has no exit condition']


def test_long_node_names_and_references_stay_fast() -> None:
    names = [f"A{i:04d}" + "abcdefghij " * 92 + "Z" for i in range(3000)]  # 1,018 characters each
    refs = "".join(f'$("{n[:500]}q{n[501:]}").item\n' for n in names[:900])  # 900 typos of 1 KB names (1 MB of code)
    nodes = [trigger(), *(node(n, "noOp") for n in names), node("Code", "code", {"jsCode": refs}, 2)]
    wf = from_data(workflow(nodes, link("Start", "Code")), "x")[0]
    found = _timed(lambda: run([wf]), 15)  # no difflib comparison of 1 KB names
    assert counts([f for f in found if f.rule.id == "N8D207"])["error"] == 900
    assert not any(f.fix_hint and "Did you mean" in f.fix_hint for f in found)  # no typo suggestions for names over 128 characters
    _timed(lambda: fix_workflow(wf), 15)
    short = from_data(workflow([trigger(), node("Fetch customer", "noOp"), node("C", "code", {"jsCode": '$("Fetch custmer").item'}, 2)]), "x")[0]
    assert any(f.fix_hint and '"Fetch customer"' in f.fix_hint for f in run([short]))


def test_many_workflows_in_one_file_count_lines_once() -> None:
    flows = [workflow([trigger(), *(node(f"N{i}", "noOp", {"note": "x" * 300}) for i in range(40))], name=f"W{w}") for w in range(1000)]
    text = json.dumps(flows, indent=1)
    loaded = _timed(lambda: parse_text(text, "x"), 10)
    lines = text.splitlines()
    last = loaded[-1]
    assert '"name": "W999"' in "\n".join(lines[last.nodes[0].line - 40 : last.nodes[0].line])
    assert '"name": "N39"' in "\n".join(lines[last.nodes[-1].line - 1 : last.nodes[-1].line + 6])


def test_deep_paths_with_many_values_lint_and_fix_quickly() -> None:
    value: Any = {f"k{j}": ["{{ $json.a }}"] * 9_950 for j in range(20)}
    for i in range(57):
        value = {f"key{i:02d}xxxxxxxxxx": value}
    data = workflow([trigger(), node("S", "set", {"v": value})], link("Start", "S"))
    wf = from_data(data, "x")[0]
    found = _timed(lambda: run([wf]), 15)
    assert counts([f for f in found if f.rule.id == "N8D212"])["warning"] == 199_000
    result = _timed(lambda: fix_workflow(wf), 25)
    assert len(result.patch) == 1 and result.patch[0]["path"] == "/nodes/1/parameters"
    assert len(result.changes) == 1 and "added the leading = to 199,000 values" in result.changes[0]
    inner = result.fixed["nodes"][1]["parameters"]["v"]
    for i in reversed(range(57)):
        inner = inner[f"key{i:02d}xxxxxxxxxx"]
    assert inner["k7"][9949] == "={{ $json.a }}"
    assert len(result.edits) == 51 and result.edits[-1].text == '"S": and 198,950 more changed values'  # counted, not listed


def test_many_long_secrets_mask_quickly() -> None:
    import random

    rnd = random.Random(5)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    secrets = ["".join(rnd.choice(alphabet) for _ in range(245_000)) for _ in range(8)]  # 1.96 MB of secrets
    nodes = [trigger(), *(node(f"H{k}", "httpRequest", {"url": "https://a.example", "options": {}, "password": secrets[k % 8]}, 4.2) for k in range(78))]
    wf = from_data(workflow(nodes, link("Start", "H0")), "x")[0]
    result = _timed(lambda: fix_workflow(wf), 15)
    assert len(result.changes) == 78 and not any(s[:40] in result.diff for s in secrets)
