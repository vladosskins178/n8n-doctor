"""Resource limits and the inputs they bound: deep explain trees, many distinct secrets, floods of
findings, and node arrays with entries that are not nodes."""

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main
from n8n_doctor.config import Config, ConfigError
from n8n_doctor.config import load as load_config
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.fix import fix_workflow
from n8n_doctor.limits import DEFAULT, Limits
from n8n_doctor.lint import run
from n8n_doctor.report import Style, counts, render_json, render_sarif, render_text
from n8n_doctor.rules import RULES, resolve
from n8n_doctor.workflow import LimitError, from_data, parse_text

from .conftest import link, merge, node, trigger, workflow


def _cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def _if_chain(count: int) -> dict[str, Any]:
    """Start -> IF0 -(true)-> IF1 -(true)-> ...: every IF opens a tree level."""
    names = [f"IF{i}" for i in range(count)]
    return workflow([trigger(), *(node(n, "if", {}, 2) for n in names)], merge(link("Start", names[0]), link(*names)))


# --- hard limits: file size, nodes, connections -------------------------------------------------


def test_node_and_connection_limits_are_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    names = [f"N{i}" for i in range(10)]
    data = workflow([trigger(), *(node(n, "noOp") for n in names)], link("Start", *names))
    with pytest.raises(LimitError, match="11 nodes, more than the limit of 5"):
        from_data(data, "x", limits=Limits(max_nodes=5))
    with pytest.raises(LimitError, match="more than 3 connections"):
        from_data(data, "x", limits=Limits(max_connections=3))
    assert from_data(data, "x")[0].limits == DEFAULT
    path = tmp_path / "big.json"
    path.write_text(json.dumps(data))
    code, _, err = _cli(capsys, "lint", "--no-config", "--max-nodes", "5", str(path))
    assert code == 2 and "--max-nodes" in err
    # inside a folder too: a workflow over a limit fails the run instead of being skipped
    code, _, err = _cli(capsys, "lint", "--no-config", "--max-connections", "3", str(tmp_path))
    assert code == 2 and "connections" in err
    for command in (["explain"], ["fix"]):
        code, _, err = _cli(capsys, *command, "--no-config", "--max-nodes", "5", str(path))
        assert code == 2 and "limit" in err
    assert _cli(capsys, "lint", "--no-config", "--max-nodes", "11", str(path))[0] == 0


def test_file_size_limit(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    data = workflow([trigger(), node("S", "set", {"value": "x" * (1024 * 1024)})], link("Start", "S"))
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    code, _, err = _cli(capsys, "lint", "--no-config", "--max-file-mb", "1", str(path))
    assert code == 2 and "larger than the limit of 1 MB" in err
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(data)))
    code, _, err = _cli(capsys, "lint", "--no-config", "--max-file-mb", "1", "-")
    assert code == 2 and "<stdin>" in err
    with pytest.raises(LimitError):
        parse_text(json.dumps(data), "x", Limits(max_file_bytes=1024 * 1024))
    code, _, err = _cli(capsys, "lint", "--no-config", "--max-file-mb", "65", str(path))
    assert code == 2 and "at most 64" in err
    assert _cli(capsys, "lint", "--no-config", "--max-nodes", "0", str(path))[0] == 2


def test_limits_in_the_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg_path = tmp_path / ".n8n-doctor.toml"
    cfg_path.write_text("[limits]\nmax-nodes = 2\nmax-findings-per-rule = 7\n")
    cfg = load_config(cfg_path, lambda r: resolve(r).id)
    assert cfg.limits.max_nodes == 2 and cfg.limits.max_findings_per_rule == 7 and cfg.limits.max_connections == DEFAULT.max_connections
    (tmp_path / "wf.json").write_text(json.dumps(workflow([trigger(), node("A", "noOp"), node("B", "noOp")])))
    code, _, err = _cli(capsys, "lint", "--config", str(cfg_path), str(tmp_path / "wf.json"))
    assert code == 2 and "limit of 2" in err
    assert _cli(capsys, "lint", "--config", str(cfg_path), "--max-nodes", "3", str(tmp_path / "wf.json"))[0] in (0, 1)  # the flag wins
    for bad in ("[limits]\nmax-node = 2\n", "[limits]\nmax-nodes = -1\n", '[limits]\nmax-nodes = "2"\n', "[limits]\nmax-file-mb = 100\n", "limits = 3\n"):
        cfg_path.write_text(bad)
        with pytest.raises(ConfigError):
            load_config(cfg_path, lambda r: resolve(r).id)


# --- values too long to scan in full ------------------------------------------------------------


def test_long_values_are_scanned_at_both_ends() -> None:
    limits = Limits(max_value_chars=4096, max_name_chars=10_000)
    head, middle, tail = "ghp_" + "A" * 36, "ghp_" + "B" * 36, "ghp_" + "C" * 36
    value = head + " " + "x" * 3000 + middle + "x" * 3000 + " " + tail
    pw = "hunter2hunter2xyz"
    s = node("S", "set", {"value": value, "options": {"password": pw}})
    wf = from_data(workflow([trigger(), s, node(f"Repeats {pw}", "noOp")], link("Start", "S", f"Repeats {pw}")), "x", limits=limits)[0]
    found = [f for f in run([wf]) if f.rule.id == "N8D101"]
    partial = [f for f in found if "too large to check in full" in f.message]
    assert len(partial) == 1 and partial[0].severity.label == "info" and partial[0].parameter == "value"
    shown = " ".join(f.message for f in found)
    assert "ghp_..." in shown and sum("GitHub token" in f.message for f in found) == 2  # head and tail; the middle was not read
    text = outline(wf) + mermaid(wf) + json.dumps(as_dict(wf))
    assert middle not in text and pw not in text
    fixed = fix_workflow(
        from_data(workflow([trigger(), s, node("H", "httpRequest", {"url": "https://a.example"}, 4.2)], link("Start", "S", "H")), "x", limits=limits)[0]
    )
    assert fixed.changes and middle not in fixed.diff and "too large to check for secrets" not in fixed.fixed_text
    assert middle in fixed.fixed_text  # the fixed workflow itself keeps the value
    # names: checked at both ends too
    long_name = "ghp_" + "D" * 36 + "n" * 5000
    wf = from_data(workflow([trigger(long_name)]), "x", limits=limits)[0]
    assert any("node name is 5,040 characters" in f.message for f in run([wf]))


# --- findings per rule ---------------------------------------------------------------------------


def test_findings_per_rule_are_capped_and_counted(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    keys = " ".join(f"AKIAQ{i:05d}WERTYZXCVB" for i in range(250))
    data = workflow([trigger(), node("S", "set", {"value": keys})], link("Start", "S"))
    found = [f for f in run(from_data(data, "x")) if f.rule.id == "N8D101"]
    assert len(found) == 201 and found[-1].extra["omitted"] == {"error": 50} and "50 more findings of N8D101" in found[-1].message
    assert counts(found)["error"] == 250
    text = render_text(found, [("x", "Test", 2)], Style(False))
    assert "250 problems (250 errors" in text
    payload = json.loads(render_json(found, [("x", "Test", 2)]))
    assert payload["summary"]["error"] == 250 and sum(1 for f in payload["findings"] if "omitted" in f) == 1
    assert len(json.loads(render_sarif(found, [r.meta for r in RULES]))["runs"][0]["results"]) == 201
    cfg = Config(limits=Limits(max_findings_per_rule=10))
    found = [f for f in run(from_data(data, "x", limits=cfg.limits)) if f.rule.id == "N8D101"]
    assert len(found) == 11
    timeouts = workflow([trigger(), *(node(f"H{i}", "httpRequest", {"url": "https://a.example"}, 4.2) for i in range(230))], link("Start", "H0"))
    found = [f for f in run(from_data(timeouts, "x")) if f.rule.id == "N8D303"]
    assert len(found) == 201 and json.loads(render_json(found, [("x", "Test", 231)]))["summary"]["fixable"] == 230
    assert "230 can be fixed automatically" in render_text(found, [("x", "Test", 231)], Style(False))
    assert len(fix_workflow(from_data(timeouts, "x")[0], {"N8D303"}).changes) == 230  # fix is not limited to the listed ones
    # suppressed findings are capped the same way, and still counted
    sticky = node("Note", "stickyNote", {"content": "n8n-doctor-disable N8D101"})
    suppressed: list[Any] = []
    assert not [f for f in run(from_data(workflow([*data["nodes"], sticky], data["connections"]), "x"), suppressed=suppressed) if f.rule.id == "N8D101"]
    assert len(suppressed) == 201 and counts(suppressed)["error"] == 250
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(data))
    code, out, _ = _cli(capsys, "lint", "--no-config", "-f", "json", "--max-findings-per-rule", "5", str(path))
    assert code == 1 and json.loads(out)["summary"]["error"] == 250 and len(json.loads(out)["findings"]) <= 20
    head = mcp.call_tool("n8n_lint", {"workflow": data})["content"][0]["text"].split("\n", 1)[0]
    assert head.startswith("250 findings: 250 errors")


def test_dangling_connections_are_grouped_per_source() -> None:
    targets = [[{"node": f"Gone {i}-{j}", "type": "main", "index": 0} for j in range(1000)] for i in range(30)]
    data = workflow([trigger(), node("A", "noOp")], {"Start": {"main": targets}, "Ghost": {"main": [[{"node": "A", "type": "main", "index": 0}]]}})
    started = time.perf_counter()
    found = [f for f in run(from_data(data, "x")) if f.rule.id == "N8D205"]
    results = json.loads(render_sarif(found, [r.meta for r in RULES]))["runs"][0]["results"]
    assert time.perf_counter() - started < 10 and len(json.dumps(results)) < 5_000
    assert len(found) == 2 and found[1].node == "Start" and "connections to 30,000 missing nodes" in found[1].message
    assert 'connection from missing node "Ghost" (linked with "A")' in found[0].message
    fixed = fix_workflow(from_data(data, "x")[0], {"N8D205"})
    assert fixed.fixed["connections"] == {"Start": {"main": [[]] * 30}}
    flood = {"Start": {"main": [[{"node": f"G{i}", "type": "main", "index": 0} for i in range(DEFAULT.max_connections + 1)]]}}
    with pytest.raises(LimitError):
        from_data(workflow([trigger()], flood), "x")


# --- explain depth and output size ----------------------------------------------------------------


def test_explain_flattens_deep_branches_and_stops_at_the_output_limit() -> None:
    wf = from_data(_if_chain(80), "x")[0]
    text = outline(wf)
    widest = max(len(line) - len(line.lstrip(" │├└─↓")) for line in text.splitlines())
    assert text.count("(depth limit") == 1 and widest <= 2 + 3 * (DEFAULT.max_explain_depth + 1)
    assert "IF79 (if)" in text and "truncated" not in text
    ascii_text = outline(from_data(_if_chain(80), "x", limits=Limits(max_explain_depth=3))[0], unicode=False)
    assert "-> (depth limit" in ascii_text and max(len(line) - len(line.lstrip(" |`-v")) for line in ascii_text.splitlines()) <= 2 + 3 * 4
    small = outline(from_data(_if_chain(300), "x", limits=Limits(max_output_bytes=4096))[0])
    assert len(small) < 4096 + 200 and small.rstrip().endswith("(--max-output-kb, max-output-kb in [limits]; one limit per run)")
    chart = mermaid(from_data(_if_chain(300), "x", limits=Limits(max_output_bytes=4096))[0])
    assert len(chart) < 4096 + 200 and "%% ... truncated" in chart
    # the MCP tool applies the same limits
    reply = mcp.call_tool("n8n_explain", {"workflow": _if_chain(80)})["content"][0]["text"]
    assert reply.count("(depth limit") == 1


def test_explain_of_large_branching_workflows_is_bounded() -> None:
    wf = from_data(_if_chain(4999), "x")[0]  # every IF opens a tree level: the output stays linear in the depth
    started = time.perf_counter()
    text = outline(wf)
    assert time.perf_counter() - started < 20 and len(text) <= DEFAULT.max_output_bytes + 200
    # every IF and Wait connected to many others: one line per connection, cut at the output limit
    names = [f"N{i}" for i in range(1500)]
    nodes = [trigger(), *(node(n, "if" if i % 2 else "wait", {}, 2) for i, n in enumerate(names))]
    conns: dict[str, Any] = {"Start": {"main": [[{"node": "N0", "type": "main", "index": 0}]]}}
    for i, n in enumerate(names):
        conns[n] = {"main": [[{"node": names[(i + k) % len(names)], "type": "main", "index": 0} for k in range(1, 16)]] * 2}
    wf = from_data(workflow(nodes, conns), "x")[0]
    started = time.perf_counter()
    text = outline(wf)
    assert time.perf_counter() - started < 20 and len(text) <= DEFAULT.max_output_bytes + 200 and "truncated" in text


# --- masking with many distinct first characters --------------------------------------------------


def test_masker_with_many_distinct_first_characters_is_fast() -> None:
    count = 4999  # one first character per password: the candidate search does not grow with their number
    nodes = [trigger()] + [node(f"S{i}", "set", {"options": {"password": chr(0x4E00 + i) + f"bcdefgh1{i:05d}"}}) for i in range(count)]
    wf = from_data(workflow(nodes, link("Start", *[f"S{i}" for i in range(count)])), "x")[0]
    started = time.perf_counter()
    text = outline(wf)
    found = run([wf])
    assert time.perf_counter() - started < 20
    assert chr(0x4E00 + 77) + "bcdefgh100077" not in text and sum(f.rule.id == "N8D101" for f in found) == 201


def test_masker_matches_naive_masking_with_many_first_characters() -> None:
    from n8n_doctor.rules import _MultiMasker

    def naive(forms: set[str], text: str) -> str:
        covered = [False] * len(text)
        for f in forms:
            if len(f) >= 4:
                start = text.find(f)
                while start >= 0:
                    covered[start : start + len(f)] = [True] * len(f)
                    start = text.find(f, start + 1)
        out, k = [], 0
        while k < len(text):
            if covered[k]:
                while k < len(text) and covered[k]:
                    k += 1
                out.append("***")
            else:
                out.append(text[k])
                k += 1
        return "".join(out)

    rng = random.Random(23)
    for _ in range(600):
        alphabet = [chr(c) for c in rng.sample(range(0x20, 0x3000), rng.randint(2, 300))] + list("]\\^-[")
        text = "".join(rng.choice(alphabet[:8]) if rng.random() < 0.5 else rng.choice(alphabet) for _ in range(rng.randint(0, 500)))
        forms = {text[i : i + rng.randint(4, 30)] for i in (rng.randrange(len(text) or 1) for _ in range(rng.randint(0, 30)))}
        forms |= {"".join(rng.choice(alphabet) for _ in range(rng.randint(4, 9))) for _ in range(rng.randint(0, 60))}
        assert _MultiMasker(forms)(text) == naive(forms, text)


# --- entries of the nodes array that are not nodes --------------------------------------------------


def test_null_first_node_does_not_crash() -> None:
    http = node("HTTP", "httpRequest", {"url": "https://a.example"}, 4.2)
    wf = from_data(workflow([None, trigger(), http], link("Start", "HTTP")), "x")[0]  # type: ignore[list-item]
    found = run([wf])
    assert {f.node for f in found if f.rule.id == "N8D302"} == {"HTTP"}
    assert [f.message for f in found if f.rule.id == "N8D213"] == ["nodes[0] is null, not a node object"]
    assert next(f for f in found if f.rule.id == "N8D213").severity.label == "error"


def test_fix_patches_the_node_at_its_real_position() -> None:
    http = node("HTTP", "httpRequest", {"url": "https://a.example"}, 4.2)
    data = workflow([trigger(), None, http, node("Set", "set")], link("Start", "HTTP", "Set"))  # type: ignore[list-item]
    result = fix_workflow(from_data(data, "x")[0], {"N8D302"}, set_timeout=30000)
    assert result.changes == ['N8D302 "HTTP": timeout 30000 ms']
    assert result.patch == [
        {"op": "add", "path": "/nodes/2/parameters/options", "value": {}},
        {"op": "add", "path": "/nodes/2/parameters/options/timeout", "value": 30000},
    ]
    assert result.fixed["nodes"][1] is None and "options" not in result.fixed["nodes"][3]["parameters"]


@pytest.mark.parametrize("junk", [None, "node", 3, 2.5, True, [], [{"name": "X"}], {}])
def test_junk_in_nodes_and_connections_is_handled(junk: Any) -> None:
    rng = random.Random(repr(junk))
    for _ in range(20):
        nodes: list[Any] = [trigger(), node("HTTP", "httpRequest", {"url": "https://a.example"}, 4.2), node("Code", "code", {"jsCode": "return items"}, 2)]
        for _ in range(rng.randint(1, 3)):
            nodes.insert(rng.randint(0, len(nodes)), junk)
        conns: dict[str, Any] = link("Start", "HTTP", "Code")
        conns[rng.choice(["HTTP", "Start", "Gone"])] = rng.choice([junk, {"main": junk}, {"main": [junk]}, {"main": [[junk]]}, {"main": [[{"node": junk}]]}])
        wf = from_data(workflow(nodes, conns, pinData={"HTTP": junk}, settings={"errorWorkflow": junk}), "x")[0]
        found = run([wf])
        positions = {i for i, n in enumerate(nodes) if not isinstance(n, dict) or not n}
        assert {f.parameter for f in found if f.rule.id == "N8D213"} == {f"nodes[{i}]" for i in positions}
        assert all(f.node in (None, "Start", "HTTP", "Code") or f.node.startswith("(node ") for f in found)  # {} is a node without a name
        result = fix_workflow(wf)
        for op in result.patch:
            if op["path"].startswith("/nodes/"):
                assert isinstance(nodes[int(op["path"].split("/")[2])], dict)
        outline(wf), mermaid(wf), as_dict(wf)


@pytest.mark.parametrize("fmt", ["text", "mermaid"])
def test_explain_output_limit_is_per_run(tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: str) -> None:
    flows = [{**_if_chain(60), "name": f"Flow {i}"} for i in range(50)]
    path = tmp_path / "all.json"
    path.write_text(json.dumps(flows), encoding="utf-8")
    (tmp_path / "n8n-doctor.toml").write_text("[limits]\nmax-output-kb = 8\n", encoding="utf-8")
    assert main(["explain", "--config", str(tmp_path / "n8n-doctor.toml"), "-f", fmt, str(path)]) == 0
    out = capsys.readouterr().out
    assert len(out.encode()) < 8 * 1024 + 400  # for all 50 workflows together
    assert out.count("... truncated") == 1 and "more workflows not shown" in out


def test_explain_of_several_small_workflows_is_whole() -> None:
    from n8n_doctor.explain import mermaids, outlines

    flows = [from_data({**_if_chain(3), "name": f"Flow {i}"}, "x")[0] for i in range(3)]
    assert outlines(flows) == "\n".join(outline(w) for w in flows)
    assert mermaids(flows) == "\n".join(mermaid(w) for w in flows)
