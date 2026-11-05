"""The fix review (CLI text, ``fix --format json`` changes/edits/diff, MCP n8n_fix by default) never shows whole
parameter values: one line per changed value with node, path and only the changed token, never the text around it."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main
from n8n_doctor.expressions import iter_leaves
from n8n_doctor.fix import describe_change, fix_workflow
from n8n_doctor.workflow import from_data

from .conftest import EXAMPLES, REGRESSION_FIXTURES, link, node, trigger, workflow

FILES = sorted(EXAMPLES.glob("*.json")) + sorted(REGRESSION_FIXTURES.glob("*.json"))

T7_SECRETS = [
    "Enter-The-Dragon-99",
    "aHVudGVyOmh1bnRlcjI=",
    "Blue-Sky-Rain-77",
    "Tr0ub4dor&3",
    "k9-Lm-22-Qx",
    "Moon-River-2024",
    "Winter-Is-Coming-1",
    "Purple-Monkey-Dishwasher",
]


def _load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _shown(path: Path, capsys: pytest.CaptureFixture[str]) -> str:
    """Everything the default fix outputs show for ``path``: CLI text, CLI JSON without the raw patch, MCP n8n_fix."""
    data = _load(path)
    result = fix_workflow(from_data(data, path.name)[0])
    out = [result.diff, "\n".join(result.changes), "\n".join(result.skipped), json.dumps([e.as_dict() for e in result.edits])]
    capsys.readouterr()
    main(["fix", "--no-config", str(path)])
    out.append(capsys.readouterr().out)
    main(["fix", "--no-config", "-f", "json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert "patch" not in payload  # the raw JSON Patch only comes with --include-patch
    out.append(json.dumps(payload, ensure_ascii=False))
    out.append(mcp.call_tool("n8n_fix", {"workflow": data})["content"][0]["text"])
    return "\n".join(out)


@pytest.mark.parametrize("path", FILES, ids=[p.name for p in FILES])
def test_no_parameter_value_is_shown_whole(path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = _load(path)
    shown = _shown(path, capsys)
    names = [n["name"] for n in data.get("nodes", []) if isinstance(n, dict) and isinstance(n.get("name"), str)]
    result = fix_workflow(from_data(data, path.name)[0])
    tokens = [t for e in result.edits for t in (e.before, e.after) if t]
    values = {v for n in data.get("nodes", []) if isinstance(n, dict) for _, v in iter_leaves(n.get("parameters", {})) if len(v) >= 8}
    # node names are shown by design; the changed token itself is what the review is for
    leaked = [v for v in values if v in shown and not any(v in name for name in names) and not any(v in t for t in tokens)]
    assert leaked == []


def test_code_fix_shows_only_the_renamed_reference(capsys: pytest.CaptureFixture[str]) -> None:
    shown = _shown(REGRESSION_FIXTURES / "t7.json", capsys)
    assert "$('Get Ordr')" in shown and "$('Get Order')" in shown
    assert not [s for s in T7_SECRETS if s in shown]
    assert "api.acme.io" not in shown and ".first().json" not in shown  # no context around a change in code
    assert "@@" not in shown and "+++" not in shown  # no unified diff anywhere


def test_sensitive_fields_show_the_inserted_prefix_only(capsys: pytest.CaptureFixture[str]) -> None:
    shown = _shown(REGRESSION_FIXTURES / "t8.json", capsys)
    assert not [s for s in ("Enter-The-Dragon-99", "Blue-Sky-Rain-77", "Moon-River-2024", "Purple-Monkey-Dishwasher", "Winter-Is-Coming-1") if s in shown]
    assert '"GQL" url: inserted "=" at the start' in shown
    assert '"Raw" options.timeout' not in shown
    assert "api.x.io" not in shown and "{{ $json.q }}" not in shown


def test_plain_fields_show_no_context() -> None:
    s = node("Set", "set", {"text": "=Dear customer, {{ $('fetch lead').item.json.name }}, thanks for your order number 1234"}, 3.4)
    result = fix_workflow(from_data(workflow([trigger(), node("Fetch lead", "noOp"), s], link("Start", "Fetch lead", "Set")), "x")[0])
    line = next(e.note for e in result.edits if e.path == "text")
    assert "$('fetch lead')" in line and "$('Fetch lead')" in line
    assert "customer" not in line and "item.json" not in line and "thanks" not in line  # the token only
    assert "Dear customer, {{ $('fetch lead').item.json.name }}, thanks" not in result.diff


def test_pinned_data_removal_is_a_count() -> None:
    data = workflow([trigger()], pinData={"Start": [{"json": {"email": "jane.doe@example.com"}}, {"json": {"t": "pinnedTok3n"}}]})
    result = fix_workflow(from_data(data, "x")[0])
    assert "pinData: removed 2 pinned records of 1 node" in result.diff
    assert "jane.doe" not in result.diff and "pinnedTok3n" not in result.diff


def test_describe_change_forms() -> None:
    code = "const a = 'Enter-The-Dragon-99';\nreturn $('Prepare emial').all();"
    assert describe_change(code, code.replace("emial", "email"), True) == "\"$('Prepare emial')\" -> \"$('Prepare email')\""
    assert describe_change("{{ $json.x }}", "={{ $json.x }}", True) == 'inserted "=" at the start'
    assert describe_change("abcdefgh-old-value", "completely different", True) == "<value changed, 20 chars>"
    assert describe_change("x" * 9, "y" * 9, False) == '"xxxxxxxxx" -> "yyyyyyyyy"'  # short, plain: shown
    assert describe_change("x" * 41, "y" * 41, False) == "<value changed, 41 chars>"
    assert describe_change("x" * 9, "y" * 9, True) == "<value changed, 9 chars>"
    assert describe_change("Dear Jane, order 12 shipped", "Dear Jane, order 13 shipped", False) == '"12" -> "13"'
    prose = "note: password=Zq8vLm2Pq7Rt in a Slack text field {{ $('fetch lead').item.json.x }}"
    two = describe_change(prose, "=" + prose.replace("fetch lead", "Fetch lead"), False)
    assert two == 'inserted "=" at the start; "$(\'fetch lead\')" -> "$(\'Fetch lead\')"'  # separate changes, nothing between
    long_token = "$('" + "N" * 200 + "')"
    assert describe_change(long_token, long_token.replace("N')", "M')"), True).startswith("<")


def test_mcp_default_output_is_the_change_list() -> None:
    data = _load(REGRESSION_FIXTURES / "t7.json")
    text = mcp.call_tool("n8n_fix", {"workflow": data})["content"][0]["text"]
    assert '"Call API" jsCode: "$(\'Get Ordr\')" -> "$(\'Get Order\')"' in text
    assert "JSON Patch" not in text and "Enter-The-Dragon-99" not in text
    raw = mcp.call_tool("n8n_fix", {"workflow": data, "output": "patch"})["content"][0]["text"]
    assert "JSON Patch" in raw  # the raw forms stay available on request


def test_cli_json_has_structured_edits(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["fix", "--no-config", "-f", "json", str(REGRESSION_FIXTURES / "t8.json")]) == 0
    payload = json.loads(capsys.readouterr().out)
    edit = next(e for e in payload["edits"] if e["node"] == "GQL" and e["path"] == "url")
    assert edit == {"node": "GQL", "path": "url", "before": "", "after": "=", "note": 'inserted "=" at the start'}
    assert "patch" not in payload  # the raw JSON Patch is not log-safe: only on request
    assert main(["fix", "--no-config", "-f", "json", "--include-patch", str(REGRESSION_FIXTURES / "t8.json")]) == 0
    assert json.loads(capsys.readouterr().out)["patch"]


_WORDS = ["Dear", "customer", "order", "SELECT", "FROM", "users", "WHERE", "id", "<p>", "</p>", "const", "return", "https://api.acme.io/v1", "x"]
_SECRETS = ["Enter-The-Dragon-99", "Blue-Sky-Rain-77", "Moon-River-2024", "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", "hunter22", "Zq8!vR2#kL9@"]
_FIELDS = [
    ("set", 3.4, ("text",)),
    ("set", 3.4, ("jsonOutput",)),
    ("httpRequest", 4.2, ("url",)),
    ("httpRequest", 4.2, ("body",)),
    ("httpRequest", 4.2, ("headerParameters", "parameters", 0, "value")),
    ("httpRequest", 4.2, ("queryParameters", "parameters", 0, "value")),
    ("code", 2, ("jsCode",)),
    ("postgres", 2.5, ("query",)),
    ("slack", 2.2, ("text",)),
]


def _generated(rng: Any) -> dict[str, Any]:
    """A workflow with one value that mixes words, a secret and a stale node reference (with or without the =)."""
    type_, version, keys = rng.choice(_FIELDS)
    parts = [rng.choice(_WORDS) for _ in range(rng.randint(0, 8))]
    # a secret in a form detection cannot know (prose in a plain field): only the changed token keeps it out
    parts.insert(rng.randint(0, len(parts)), f"note: password={rng.choice(_SECRETS)} in a Slack text field")
    ref = "$('fetch lead').first().json.x" if type_ == "code" else "{{ $('fetch lead').item.json.x }}"
    parts.insert(rng.randint(0, len(parts)), ref)
    value = " ".join(parts)
    if type_ != "code" and rng.random() < 0.5:
        value = "=" + value
    if len(keys) == 1:
        params: dict[str, Any] = {keys[0]: value}
    else:  # an entry of a name/value list: a header, a query parameter
        params = {keys[0]: {"parameters": [{"name": rng.choice(["Authorization", "q", "X-Api-Key"]), "value": value}]}}
    lead = node("Fetch lead", "noOp")
    return workflow([trigger(), lead, node("N", type_, params, version)], link("Start", "Fetch lead", "N"))


def test_generated_values_are_never_shown_whole() -> None:
    import random

    rng = random.Random(11)
    checked = 0
    for _ in range(300):
        data = _generated(rng)
        result = fix_workflow(from_data(data, "x.json")[0])
        shown = result.diff + "\n".join(result.changes) + json.dumps([e.as_dict() for e in result.edits], ensure_ascii=False)
        shown += mcp.call_tool("n8n_fix", {"workflow": data})["content"][0]["text"]
        tokens = [t for e in result.edits for t in (e.before, e.after) if t]
        for n in data["nodes"]:
            for _, v in iter_leaves(n["parameters"]):
                if len(v) >= 8 and not any(v in t for t in tokens):
                    assert v not in shown
                    checked += 1
        assert not [s for s in _SECRETS if s in shown]
    assert checked >= 250


def test_many_renames_in_code_are_reviewed_quickly() -> None:
    # 290 copies of $('ab') in each of 8 Code nodes (perf repros rv1/rv8): once 6 s per node of difflib
    data = _load(REGRESSION_FIXTURES / "many_renames_in_one_code_node.json")
    code = data["nodes"][2]
    data["nodes"] += [{**code, "name": f"Code{i}"} for i in range(1, 8)]
    data["connections"]["T"]["main"][0] += [{"node": f"Code{i}", "type": "main", "index": 0} for i in range(1, 8)]
    started = time.perf_counter()
    result = fix_workflow(from_data(data, "x")[0])
    assert time.perf_counter() - started < 2
    assert len(result.edits) == 8
    assert all(e.note == "\"$('ab')\" -> \"$('AB')\" (290 times)" for e in result.edits)
    # the change list says each rename once, with a count
    assert result.changes[0] == 'N8D207 "Code0" jsCode: "ab" -> "AB" (290 times)'


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("ab" * 1024, "ba" * 1024),
        ("a" * 2048, "ab" * 1024),
        ("".join(chr(97 + i % 7) for i in range(2048)), "".join(chr(97 + (i * 3) % 7) for i in range(2048))),
        ("x" * 5000 + "ab" * 1024, "x" * 5000 + "ba" * 1024),
    ],
)
def test_describing_a_long_changed_region_is_quick(old: str, new: str) -> None:
    started = time.perf_counter()
    assert describe_change(old, new, False).startswith("<value changed")
    assert time.perf_counter() - started < 0.5
