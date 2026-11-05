"""Docs, skill and manifests stay in sync with the code."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from n8n_doctor import __version__
from n8n_doctor.cli import main
from n8n_doctor.rules import RULES

from .conftest import ROOT


def test_every_rule_is_documented() -> None:
    text = (ROOT / "docs" / "rules.md").read_text()
    for r in RULES:
        assert f"### {r.id} {r.meta.name}\n" in text, r.id
        row = re.search(rf"\| \[{r.id}\]\(#{r.id.lower()}-{r.meta.name}\) \| {r.meta.name} \| (\w+) \| ([^|]*)\|", text)
        assert row, r.id
        assert row.group(1) == r.meta.severity.label, r.id
        assert bool(row.group(2).strip()) == r.meta.fixable, r.id


def test_versions_match() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in pyproject
    assert json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"] == __version__
    assert f"## [{__version__}]" in (ROOT / "CHANGELOG.md").read_text()


def test_skill_mentions_every_rule_it_relies_on() -> None:
    skill = (ROOT / "skills" / "n8n-doctor" / "SKILL.md").read_text()
    assert skill.startswith("---\nname: n8n-doctor\n")
    known = {r.id for r in RULES}
    assert set(re.findall(r"N8D\d{3}", skill)) <= known


def test_action_pins_the_sarif_upload_and_checks_its_inputs(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    text = (ROOT / "action.yml").read_text()
    assert re.search(r"uses: github/codeql-action/upload-sarif@[0-9a-f]{40} # v4\.\d+\.\d+\n", text)
    assert "false|no|off|0)" in text
    # the install step refuses paths in `args`: they belong in `path`, which is passed after `--`
    check = re.search(r"\"\$n8nd_py\" -c '(import os, shlex, sys; from n8n_doctor\.cli import build_parser;.*?)'\n", text, re.DOTALL)
    assert check
    code = "\n".join(line.strip() for line in check.group(1).splitlines())
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    ok = subprocess.run([sys.executable, "-c", code], env={**env, "N8ND_ARGS": "--fail-on warning --ignore N8D303"}, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    bad = subprocess.run([sys.executable, "-c", code], env={**env, "N8ND_ARGS": "--fail-on warning workflows/"}, capture_output=True, text=True)
    assert bad.returncode == 1 and "pass workflow paths with the path input" in bad.stderr
    refused_args = ("--format json", "--format=json", "--form json", "-f json", "-fjson", "--output x", "--output=x", "--out x", "-o x", "-ox", "-v -vf json")
    for args in refused_args:
        refused = subprocess.run([sys.executable, "-c", code], env={**env, "N8ND_ARGS": args}, capture_output=True, text=True)
        assert refused.returncode == 1 and "--format or --output" in refused.stderr, args
    for args in ("--fail-on warning", "--fail-on=warning", "--force", "-v", "--select N8D101", "--ignore --format-thing"):
        allowed = subprocess.run([sys.executable, "-c", code], env={**env, "N8ND_ARGS": args}, capture_output=True, text=True)
        assert "--format or --output" not in allowed.stderr, args


def test_readme_fix_sample_is_the_real_output(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    sample = re.search(r"```text\n\$ (n8n-doctor fix examples/lead-intake\.json)\n(.*?)```", (ROOT / "README.md").read_text(encoding="utf-8"), re.DOTALL)
    assert sample
    monkeypatch.chdir(ROOT)
    assert main([*sample.group(1).split()[1:], "--no-config"]) in (0, 1)
    assert capsys.readouterr().out == sample.group(2)


def test_release_docs_state_facts_in_the_present() -> None:
    for name in ("SECURITY.md", "CHANGELOG.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for phrase in ("Unreleased", "Previously", "before this change", "reported case", "code before these limits", "it took", "no longer"):
            assert phrase not in text, (name, phrase)
