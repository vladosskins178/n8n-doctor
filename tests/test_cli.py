from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import __version__
from n8n_doctor.cli import main

from .conftest import EXAMPLES, link, node, trigger, workflow


def run_cli(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_lint_examples_text(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run_cli(capsys, "lint", "--no-config", "--color", "never", str(EXAMPLES))
    assert code == 1
    assert "N8D101 hardcoded-secret" in out and "fix:" in out
    assert "healthy.json" not in out  # clean workflows are only listed with --verbose
    assert "problems (" in out and "\033[" not in out
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-v", str(EXAMPLES / "healthy.json"))
    assert code == 0 and "ok" in out and "No problems found in 1 workflow." in out


def test_lint_json_is_one_document(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "json", str(EXAMPLES))
    payload = json.loads(out)
    assert code == 1 and payload["summary"]["workflows"] == 3
    f = payload["findings"][0]
    assert {"rule", "name", "severity", "message", "fix", "file", "line", "node", "docs", "fixable"} <= set(f)
    assert payload["summary"]["error"] == sum(1 for x in payload["findings"] if x["severity"] == "error")


def test_lint_sarif(capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(EXAMPLES.parent)
    out_file = tmp_path / "n8n.sarif"
    code, _, err = run_cli(capsys, "lint", "--no-config", "-f", "sarif", "-o", str(out_file), "examples")
    sarif = json.loads(out_file.read_text())
    assert code == 1 and "wrote" in err
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "n8n-doctor"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].startswith("examples/") and loc["region"]["startLine"] >= 1
        assert result["level"] in ("error", "warning", "note")
    fingerprints = [r["partialFingerprints"]["n8nDoctor/v1"] for r in run["results"]]
    assert len(fingerprints) == len(set(fingerprints))


def test_fail_on_and_min_severity(capsys: pytest.CaptureFixture[str], write_json: Any) -> None:
    http = node("H", "httpRequest", {"url": "https://x.example.com", "options": {"timeout": 1}}, 4.2)
    path = write_json(workflow([trigger(), http], link("Start", "H")))  # only an info finding (no retry)
    assert run_cli(capsys, "lint", "--no-config", str(path))[0] == 0
    assert run_cli(capsys, "lint", "--no-config", "--fail-on", "info", str(path))[0] == 1
    assert run_cli(capsys, "lint", "--no-config", "--fail-on", "never", str(EXAMPLES))[0] == 0
    code, out, _ = run_cli(capsys, "lint", "--no-config", "--min-severity", "warning", "-f", "json", str(path))
    assert code == 0 and json.loads(out)["findings"] == []


def test_select_and_ignore(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "json", "--select", "N8D101,webhook-without-auth", str(EXAMPLES))
    assert {f["rule"] for f in json.loads(out)["findings"]} == {"N8D101", "N8D102"}
    _, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "json", "--ignore", "N8D101", str(EXAMPLES))
    assert "N8D101" not in {f["rule"] for f in json.loads(out)["findings"]}
    code, _, err = run_cli(capsys, "lint", "--select", "N8D999", str(EXAMPLES))
    assert code == 2 and "unknown rule" in err


def test_config_file_is_used(capsys: pytest.CaptureFixture[str], tmp_path: Path, write_json: Any) -> None:
    path = write_json(workflow([trigger(), node("H", "httpRequest", {"url": "https://x.example.com"}, 4.2)], link("Start", "H")))
    (tmp_path / ".n8n-doctor.toml").write_text('fail-on = "info"\n')
    assert run_cli(capsys, "lint", str(path))[0] == 1
    assert run_cli(capsys, "lint", "--no-config", str(path))[0] == 0
    (tmp_path / ".n8n-doctor.toml").write_text("fail-on = 3\n")
    code, _, err = run_cli(capsys, "lint", str(path))
    assert code == 2 and "fail-on" in err
    assert run_cli(capsys, "lint", "--config", str(tmp_path / "missing.toml"), str(path))[0] == 2


def test_stdin(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(workflow([trigger()]))))
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-")
    assert code == 0 and "No problems" in out


def test_usage_errors(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert run_cli(capsys, "lint", str(tmp_path / "missing.json"))[0] == 2
    (tmp_path / "x.json").write_text('{"not": "a workflow"}')
    code, _, err = run_cli(capsys, "lint", "--no-config", str(tmp_path / "x.json"))
    assert code == 2 and "not an n8n workflow" in err
    code, _, err = run_cli(capsys, "lint", "--no-config", str(tmp_path))
    assert code == 2 and "no n8n workflows found" in err
    assert run_cli(capsys)[0] == 2
    with pytest.raises(SystemExit):
        main(["--version"])
    assert __version__ in capsys.readouterr().out


def test_terminal_escapes_in_workflow_text_are_neutralised(capsys: pytest.CaptureFixture[str], write_json: Any) -> None:
    evil = node("Hook\x1b[2J", "webhook", {"path": "x\x1b]0;pwn\x07"}, 2)
    path = write_json(workflow([evil], name="Name\x1b[31m"))
    _, out, _ = run_cli(capsys, "lint", "--no-config", "--color", "never", str(path))
    assert "\x1b" not in out and "\x07" not in out


def test_rules_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run_cli(capsys, "rules", "-f", "json")
    rules = json.loads(out)
    assert code == 0 and len(rules) >= 20 and all(r["docs"].endswith(f"#{r['id'].lower()}-{r['name']}") for r in rules)
    assert "N8D101" in run_cli(capsys, "rules", "--color", "never")[1]


def test_explain_command(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run_cli(capsys, "explain", "--ascii", str(EXAMPLES / "order-sync.json"))
    assert code == 0 and "[loop] Shape order" in out and "[done] (nothing connected)" in out
    code, out, _ = run_cli(capsys, "explain", "-f", "mermaid", str(EXAMPLES / "order-sync.json"))
    assert out.startswith("flowchart LR") and "-->|loop|" in out
    code, out, _ = run_cli(capsys, "explain", "-f", "json", str(EXAMPLES / "healthy.json"))
    assert json.loads(out)[0]["triggers"][0]["name"] == "Every morning"
    assert run_cli(capsys, "explain", str(EXAMPLES))[0] == 2
    assert run_cli(capsys, "explain")[0] == 2


def test_skill_print_and_install(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, out, _ = run_cli(capsys, "skill", "print")
    assert code == 0 and out.startswith("# n8n-doctor") and "name: n8n-doctor" not in out
    assert "name: n8n-doctor" in run_cli(capsys, "skill", "print", "--frontmatter")[1]
    assert run_cli(capsys, "skill", "install", "--dest", str(tmp_path / "s"))[0] == 0
    assert (tmp_path / "s" / "SKILL.md").read_text().startswith("---")


def test_api_mode_needs_env(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("N8N_API_URL", raising=False)
    monkeypatch.delenv("N8N_API_KEY", raising=False)
    code, _, err = run_cli(capsys, "executions")
    assert code == 2 and "N8N_API_URL" in err
    monkeypatch.setenv("N8N_API_URL", "https://n8n.example.com")
    code, _, err = run_cli(capsys, "lint", "--api")
    assert code == 2 and "N8N_API_KEY" in err
    assert run_cli(capsys, "executions", "--limit", "0")[0] == 2
    assert run_cli(capsys, "lint", "--api", "x.json")[0] == 2


def test_github_annotations(capsys: pytest.CaptureFixture[str], write_json: Any) -> None:
    evil = node("A,b:c\nd", "webhook", {"path": "x"}, 2)
    path = write_json(workflow([evil]))
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "github", str(path))
    lines = out.splitlines()
    assert code == 0 and lines and all(line.startswith(("::warning ", "::error ", "::notice ")) for line in lines)
    assert "title=N8D102 webhook-without-auth" in out and "%0AFix: " in out and "\nd" not in out


def _broken_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "flows"
    folder.mkdir()
    (folder / "a_good.json").write_text(json.dumps(workflow([trigger(), node("H", "httpRequest", {"url": "https://x.example.com"}, 4.2)], link("Start", "H"))))
    (folder / "b_broken.json").write_text('{"nodes": [}, "connections": {}')  # a bad merge
    (folder / "c_good.json").write_text(json.dumps(workflow([trigger("Other")])))
    return folder


def test_a_broken_file_in_a_folder_does_not_stop_the_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    folder = _broken_folder(tmp_path)
    code, out, err = run_cli(capsys, "lint", "--no-config", "--verbose", str(folder))
    assert code == 2
    assert "a_good.json" in out and "c_good.json" in out and "N8D302" in out
    assert "1 file could not be checked:" in out and "b_broken.json: invalid JSON" in out
    assert "1 file could not be checked" in err
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "json", str(folder))
    payload = json.loads(out)
    assert code == 2 and payload["summary"]["workflows"] == 2 and payload["summary"]["file_errors"] == 1
    assert payload["errors"][0].startswith(str(folder / "b_broken.json"))
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "sarif", str(folder))
    run = json.loads(out)["runs"][0]
    assert code == 2 and run["results"] and run["invocations"][0]["executionSuccessful"] is False
    (note,) = run["invocations"][0]["toolExecutionNotifications"]
    assert note["level"] == "error" and "b_broken.json" in note["message"]["text"]
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "github", str(folder))
    assert code == 2 and "::error title=n8n-doctor (file not checked)::" in out and "N8D302" in out


def test_clean_runs_report_a_successful_sarif_invocation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "wf.json"
    path.write_text(json.dumps(workflow([trigger()])))
    code, out, _ = run_cli(capsys, "lint", "--no-config", "-f", "sarif", str(path))
    assert code == 0 and json.loads(out)["runs"][0]["invocations"] == [{"executionSuccessful": True, "toolExecutionNotifications": []}]


def test_only_broken_files_is_still_an_input_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "broken.json"
    path.write_text('{"nodes": [}, "connections": {}')
    code, out, err = run_cli(capsys, "lint", "--no-config", str(path))
    assert code == 2 and out == "" and "invalid JSON" in err


@pytest.mark.parametrize("fmt", ["text", "json", "sarif", "github"])
def test_lint_output_that_cannot_be_written(capsys: pytest.CaptureFixture[str], tmp_path: Path, fmt: str) -> None:
    lead = str(EXAMPLES / "lead-intake.json")
    code, out, err = run_cli(capsys, "lint", "--no-config", "-f", fmt, "-o", str(tmp_path / "missing" / "r.out"), lead)
    assert code == 2 and "cannot write" in err and "does not exist" in err and "internal error" not in err
    assert not (tmp_path / "missing").exists()  # the folder is not created
    code, out, err = run_cli(capsys, "lint", "--no-config", "-f", fmt, "-o", str(tmp_path), lead)
    assert code == 2 and "cannot write" in err and "not a regular file" in err and out == ""


def test_fix_write_checks_the_output_before_showing_the_diff(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    lead = str(EXAMPLES / "lead-intake.json")
    (tmp_path / "out").mkdir()
    code, out, err = run_cli(capsys, "fix", "--no-config", "--write", "--force", "-o", str(tmp_path / "out"), lead)
    assert code == 2 and out == "" and "cannot write" in err and "not a regular file" in err
    code, out, err = run_cli(capsys, "fix", "--no-config", "--write", "-o", str(tmp_path / "no" / "x.json"), lead)
    assert code == 2 and out == "" and "does not exist" in err and not (tmp_path / "no").exists()


def test_write_errors_after_the_check_are_reported(capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from n8n_doctor import cli

    def full(*_: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "write_text", full)
    code, _, err = run_cli(capsys, "lint", "--no-config", "-o", str(tmp_path / "r.txt"), str(EXAMPLES / "healthy.json"))
    assert code == 2 and f"cannot write {tmp_path / 'r.txt'}: No space left on device" in err
