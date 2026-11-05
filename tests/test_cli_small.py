"""lint of an excluded file, of a file with log lines before its JSON, and the upper bound of --set-timeout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from n8n_doctor import mcp
from n8n_doctor.cli import main

from .conftest import link, node, trigger, workflow

FLOW = workflow([trigger(), node("A", "noOp")], link("Start", "A"))


def test_mcp_timeout_upper_bound() -> None:
    tool = next(t for t in mcp.TOOLS if t["name"] == "n8n_fix")
    assert tool["inputSchema"]["properties"]["set_timeout_ms"]["maximum"] == 2147483647


def _config(tmp_path: Path) -> Path:
    config = tmp_path / ".n8n-doctor.toml"
    config.write_text('exclude = ["drafts/**"]\n')
    (tmp_path / "drafts").mkdir()
    (tmp_path / "drafts" / "a.json").write_text(json.dumps(FLOW))
    return config


def test_lint_of_an_excluded_file_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _config(tmp_path)
    code = main(["lint", "--config", str(config), str(tmp_path / "drafts" / "a.json")])
    err = capsys.readouterr().err
    assert code == 2
    assert "exclude" in err
    assert "a.json" in err
    assert "no n8n workflows found" not in err


def test_excluded_file_next_to_a_checked_one_is_mentioned(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _config(tmp_path)
    (tmp_path / "live.json").write_text(json.dumps(FLOW))
    main(["lint", "--config", str(config), str(tmp_path / "live.json"), str(tmp_path / "drafts" / "a.json")])
    captured = capsys.readouterr()
    assert "exclude" in captured.err
    assert "not an n8n workflow" not in captured.err


def test_folder_stays_silent_about_excluded_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _config(tmp_path)
    (tmp_path / "live.json").write_text(json.dumps(FLOW))
    main(["lint", "--config", str(config), str(tmp_path)])
    assert "exclude" not in capsys.readouterr().err


def test_log_lines_before_the_json_of_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "export.json"
    path.write_text("Permissions 0644 for n8n settings file are too wide.\nUser settings loaded\n" + json.dumps(FLOW, indent=2))
    assert main(["lint", "--no-config", "--format", "json", str(path)]) in (0, 1)
    assert json.loads(capsys.readouterr().out)["summary"]["workflows"] == 1


def test_a_file_of_only_log_lines_is_still_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "export.json"
    path.write_text("nothing here\nat all\n")
    assert main(["lint", "--no-config", str(path)]) == 2
    assert "export.json" in capsys.readouterr().err


@pytest.mark.parametrize(("value", "code"), [("2147483647", 0), ("2147483648", 2), ("99999999999999", 2)])
def test_set_timeout_upper_bound(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str, code: int) -> None:
    path = tmp_path / "w.json"
    path.write_text(json.dumps(workflow([trigger(), node("H", "httpRequest", {"url": "https://x.io"}, 4)], link("Start", "H"))))
    assert main(["fix", "--no-config", "--set-timeout", value, str(path)]) == code
    if code:
        assert "2147483647" in capsys.readouterr().err
