from __future__ import annotations

from pathlib import Path

import pytest

from n8n_doctor.config import Config, ConfigError, find_config, load
from n8n_doctor.lint import run
from n8n_doctor.model import Severity
from n8n_doctor.rules import resolve
from n8n_doctor.workflow import from_data

from .conftest import link, node, trigger, workflow


def _resolve(ref: str) -> str:
    return resolve(ref).id


def _write(tmp_path: Path, text: str, name: str = ".n8n-doctor.toml") -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def test_load_full_config(tmp_path: Path) -> None:
    cfg = load(
        _write(
            tmp_path,
            'disable = ["N8D303", "pinned-data"]\nfail-on = "warning"\nexclude = ["drafts/**"]\n'
            '[severity]\nhttp-without-timeout = "error"\n[rules.hardcoded-secret]\nallow = ["^pk_test_"]\n',
        ),
        _resolve,
    )
    assert cfg.disabled == {"N8D303", "N8D211"} and cfg.fail_on == "warning"
    assert cfg.severity == {"N8D302": Severity.ERROR}
    assert cfg.options["N8D101"]["allow"] == ["^pk_test_"]
    assert cfg.is_excluded(tmp_path / "drafts" / "x.json") and not cfg.is_excluded(tmp_path / "live" / "x.json")


@pytest.mark.parametrize(
    "text",
    [
        'disable = ["nope"]',
        "disable = 3",
        'fail-on = "sometimes"',
        "[severity]\nN8D101 = 'fatal'",
        "unknown = 1",
        "[rules.N8D101]\nallow = ['(']",
        "not toml ===",
        "[severity]\nN8D101 = 3",
    ],
)
def test_bad_configs_are_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load(_write(tmp_path, text), _resolve)


def test_pyproject_section_and_discovery(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    _write(tmp_path, '[tool.n8n-doctor]\ndisable = ["N8D302"]\n', "pyproject.toml")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    found = find_config(sub)
    assert found == tmp_path / "pyproject.toml"
    assert load(found, _resolve).disabled == {"N8D302"}
    _write(sub, 'disable = ["N8D303"]')
    assert find_config(sub) == sub / ".n8n-doctor.toml"


def test_discovery_stops_at_repository_root(tmp_path: Path) -> None:
    _write(tmp_path, 'disable = ["N8D303"]')
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    assert find_config(repo) is None


def test_disable_and_severity_apply() -> None:
    wf = from_data(workflow([trigger(), node("H", "httpRequest", {"url": "https://x.example.com"}, 4.2)], link("Start", "H")), "x")
    base = {f.rule.id for f in run(wf)}
    assert {"N8D302", "N8D303"} <= base
    cfg = Config(disabled={"N8D303"}, severity={"N8D302": Severity.ERROR})
    out = run(wf, cfg)
    assert "N8D303" not in {f.rule.id for f in out}
    assert next(f for f in out if f.rule.id == "N8D302").severity == Severity.ERROR
    only = run(wf, Config(enabled_only={"N8D302"}))
    assert {f.rule.id for f in only} == {"N8D302"}


def test_suppression_in_node_notes_and_sticky_notes() -> None:
    hook = node("Hook", "webhook", {"path": "x"}, 2, notes="Signed by Stripe. n8n-doctor-disable webhook-without-auth")
    wf = workflow([hook])
    assert "N8D102" not in {f.rule.id for f in run(from_data(wf, "x"))}
    all_off = node("Hook", "webhook", {"path": "x", "authentication": "basicAuth"}, 2, notes="n8n-doctor-disable")
    assert not [f for f in run(from_data(workflow([all_off]), "x")) if f.node == "Hook"]  # N8D208 silenced
    sticky = node("Note", "stickyNote", {"content": "## Notes\nn8n-doctor-disable N8D102, N8D301"})
    ids = {f.rule.id for f in run(from_data(workflow([node("Hook", "webhook", {"path": "x"}, 2), sticky], active=True), "x"))}
    assert "N8D102" not in ids and "N8D301" not in ids
    other = node("Hook", "webhook", {"path": "x"}, 2, notes="n8n-doctor-disable N8D301")
    assert "N8D102" in {f.rule.id for f in run(from_data(workflow([other]), "x"))}


def test_blanket_disable_cannot_hide_secrets_or_open_webhooks() -> None:
    token = "gh" + "p_" + "B" * 36
    hook = node("Hook", "webhook", {"path": "x", "note": f"https://x.example.com/?t={token}"}, 2, notes="n8n-doctor-disable")
    sticky = node("Note", "stickyNote", {"content": "n8n-doctor-disable"})
    wf = from_data(workflow([hook, sticky], active=True), "x")
    suppressed: list = []  # type: ignore[type-arg]
    ids = {f.rule.id for f in run(wf, suppressed=suppressed)}
    assert {"N8D101", "N8D102"} <= ids and "N8D301" not in ids
    assert {f.rule.id for f in suppressed} >= {"N8D301"} and all(f.suppressed for f in suppressed)
    assert "N8D301" in {f.rule.id for f in run(wf, inline_suppressions=False)}


def test_suppressed_findings_are_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from n8n_doctor.cli import main

    path = tmp_path / "wf.json"
    path.write_text(json.dumps(workflow([node("Hook", "webhook", {"path": "x"}, 2, notes="n8n-doctor-disable N8D102")])))
    assert main(["lint", "--no-config", "--color", "never", str(path)]) == 0
    assert "1 finding suppressed" in capsys.readouterr().out
    main(["lint", "--no-config", "-f", "json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["suppressed"] == 1 and payload["suppressed"][0]["suppressed"] == "node notes"
    main(["lint", "--no-config", "-f", "sarif", str(path)])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    result = next(r for r in results if r["ruleId"] == "N8D102")
    assert result["suppressions"][0]["kind"] == "inSource"
    assert main(["lint", "--no-config", "--no-inline-suppress", "--fail-on", "warning", str(path)]) == 1


@pytest.mark.parametrize(
    ("notes", "silenced"),
    [
        ("n8n-doctor-disable webhok-without-auth", False),  # typo: nothing is suppressed
        ("Add n8n-doctor-disable in a node's notes to accept a finding.", False),
        ("n8n-doctor-disable: N8D208", True),
        ("n8n-doctor-disable N8D208; N8D302", True),
        ("first line\nn8n-doctor-disable\nmore text", True),
    ],
)
def test_suppression_parsing(notes: str, silenced: bool) -> None:
    hook = node("Hook", "webhook", {"path": "x", "authentication": "basicAuth"}, 2, notes=notes)
    ids = {f.rule.id for f in run(from_data(workflow([hook]), "x"))}
    assert ("N8D208" not in ids) == silenced
