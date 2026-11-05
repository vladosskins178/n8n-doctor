"""The per-run findings limit, and JSON and SARIF reports written as a stream."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.cli import main
from n8n_doctor.config import Config
from n8n_doctor.files import json_dumps
from n8n_doctor.limits import Limits
from n8n_doctor.lint import run
from n8n_doctor.model import Severity
from n8n_doctor.report import Style, counts, fixable, render_github, render_json, render_sarif, render_text, write_json, write_sarif
from n8n_doctor.rules import RULES
from n8n_doctor.workflow import from_data

from .conftest import link, node, trigger, workflow


def _http_flows(count: int, per: int) -> list[dict[str, Any]]:
    """``count`` workflows of ``per`` HTTP nodes: one N8D103 error and three more findings each."""
    flows = []
    for w in range(count):
        hosts = [
            node(f"H{i}", "httpRequest", {"method": "POST", "url": f"https://x.app.n8n.cloud/webhook-test/{w}-{i}"}, 4.2, onError="continueErrorOutput")
            for i in range(per)
        ]
        flows.append(workflow([trigger(), *hosts], link("Start", *[h["name"] for h in hosts]), name=f"W{w}"))
    return flows


def _cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_findings_of_a_run_are_capped_with_one_summary() -> None:
    full = run([w for d in _http_flows(4, 30) for w in from_data(d, "x")])
    capped = run([w for d in _http_flows(4, 30) for w in from_data(d, "x", limits=Limits(max_findings_total=50))])
    assert counts(capped) == counts(full) and fixable(capped) == fixable(full)
    listed = [f for f in capped if not f.extra.get("summary")]
    assert len(listed) == 50
    last = capped[-1]
    assert last.extra.get("run_summary") and last.rule.id == "N8D001" and last.severity == Severity.ERROR
    by_rule = last.extra["omitted_by_rule"]
    assert sum(by_rule.values()) == sum(last.extra["omitted"].values()) == len(full) - 50
    assert last.message.startswith(f"{len(full) - 50:,} more findings not listed (limit: 50 per run, --max-findings-total)")
    assert "N8D103" in last.message
    text = render_text(capped, [("x", f"W{i}", 31) for i in range(4)], Style(False))
    assert last.message in text and f"{sum(counts(full).values()):,} problems" in text
    sarif = json.loads(render_sarif(capped, [r.meta for r in RULES]))
    assert len(sarif["runs"][0]["results"]) == 50
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("more findings not listed" in n["message"]["text"] and n["level"] == "warning" for n in notes)
    assert sarif["runs"][0]["properties"]["omittedFindings"]["byRule"] == by_rule
    payload = json.loads(render_json(capped, []))
    assert payload["summary"]["not_listed"] == len(full) - 50 and payload["findings"][-1]["omitted_by_rule"] == by_rule
    assert "more findings not listed" in render_github(capped)


def test_suppressed_findings_of_a_run_are_capped_too() -> None:
    data = _http_flows(3, 20)
    for d in data:
        d["nodes"].append(node("Note", "stickyNote", {"content": "n8n-doctor-disable"}))
    flows = [w for d in data for w in from_data(d, "x", limits=Limits(max_findings_total=10))]
    silenced: list[Any] = []
    run(flows, Config(), silenced)
    assert len([f for f in silenced if not f.extra.get("summary")]) == 10
    assert silenced[-1].extra.get("run_summary") and silenced[-1].suppressed


def test_run_limit_on_the_command_line_and_in_the_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "flows.json"
    path.write_text(json.dumps(_http_flows(3, 10)))
    code, out, _ = _cli(capsys, "lint", "--no-config", "-f", "json", "--max-findings-total", "7", str(path))
    data = json.loads(out)
    assert code == 1 and len([f for f in data["findings"] if "omitted" not in f]) == 7 and data["summary"]["not_listed"] > 0
    (tmp_path / ".n8n-doctor.toml").write_text("[limits]\nmax-findings-total = 5\n")
    code, out, _ = _cli(capsys, "lint", "-f", "json", str(path))
    assert len([f for f in json.loads(out)["findings"] if "omitted" not in f]) == 5
    assert _cli(capsys, "lint", "--no-config", "--max-findings-total", "0", str(path))[0] == 2
    with pytest.raises(SystemExit):  # a lint flag only
        main(["fix", "--max-findings-total", "5", str(path)])


class _Chunks(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.largest = 0

    def write(self, text: str) -> int:
        self.largest = max(self.largest, len(text))
        return super().write(text)


def test_json_and_sarif_are_written_as_a_stream_in_the_usual_layout() -> None:
    flows = [w for d in _http_flows(2, 400) for w in from_data(d, "x\u0085y")]
    found = run(flows, Config())
    labels = [("x", "W", 401)] * 2
    out = _Chunks()
    write_json(out.write, found, labels, ["skip.json"], [], ["bad.json: broken"])
    text = out.getvalue()
    assert out.largest < 4096 and len(text) > 100 * 4096  # no write holds the whole report
    assert text == render_json(found, labels, ["skip.json"], [], ["bad.json: broken"])
    assert text == json_dumps(json.loads(text)) + "\n"  # the layout json.dumps(indent=2) gives, C1 characters escaped
    assert "\\u0085" in text and "\u0085" not in text
    out = _Chunks()
    write_sarif(out.write, found, [r.meta for r in RULES], Path.cwd(), [], ["bad.json: broken"])
    text = out.getvalue()
    assert out.largest < 64 * 1024 and len(text) > 64 * 1024 * 4
    assert text == json_dumps(json.loads(text)) + "\n"
    sarif = json.loads(text)
    assert len(sarif["runs"][0]["results"]) == len(found) and not sarif["runs"][0]["invocations"][0]["executionSuccessful"]
    empty = json.loads(render_json([], []))
    assert empty["findings"] == [] and render_json([], []) == json_dumps(empty) + "\n"
