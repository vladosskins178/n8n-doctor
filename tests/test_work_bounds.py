"""Hard bounds on crafted input: what the masker, the sticky-note labels, the raw scan and the percent spellings may cost."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import Any

import pytest

from n8n_doctor import rules
from n8n_doctor.explain import outline
from n8n_doctor.limits import DEFAULT, MB
from n8n_doctor.lint import labels, run
from n8n_doctor.rules import _raw_levels, _url_spellings, known_secrets, masked_workflow, secret_masker, shown_value
from n8n_doctor.workflow import Workflow, from_data, parse_text

from .conftest import node, workflow

TOKEN = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL2xQw"


def _raw_flow(payload: str, count: int, **settings: int) -> Workflow:
    data = workflow([node(f"E{i}", "executeWorkflow", {"workflowJson": payload}) for i in range(count)])
    return from_data(data, "x.json", limits=replace(DEFAULT, **settings))[0]


# --- the masker -------------------------------------------------------------------------------------------------------


def test_many_lengths_of_a_weak_secret_inside_a_long_word_stay_bounded() -> None:
    nodes = [node(f"S{i}", "set", {"password": "a" * (i + 4)}) for i in range(400)]
    wf = from_data(workflow([*nodes, node("N", "stickyNote", {"content": "b" + "a" * 60_000 + "b"})]), "x")[0]
    started = time.perf_counter()
    text = outline(wf)
    assert time.perf_counter() - started < 5
    assert "a" * 40 not in text  # when the budget runs out the word is masked, never shown


def test_long_weak_secret_inside_a_long_word_is_not_copied_per_position() -> None:
    wf = from_data(workflow([node("S", "set", {"password": "a" * 100_000}), node("N", "set", {"note": "b" + "a" * 200_000 + "b"})]), "x")[0]
    started = time.perf_counter()
    secret_masker(wf)("b" + "a" * 200_000 + "b")
    assert time.perf_counter() - started < 5


def test_the_masker_budget_leaves_ordinary_words_alone() -> None:
    wf = from_data(workflow([node("S", "set", {"password": "Pa55"}), node("T", "set", {"password": "hunter22"})]), "x")[0]
    mask = secret_masker(wf)
    assert mask("use Pa55word and Pa55") == "use Pa55word and ***"
    assert mask("xhunter22 hunter22") == "xhunter22 ***"


# --- sticky-note labels ------------------------------------------------------------------------------------------------


def test_repeated_labels_in_sticky_notes_are_linear() -> None:
    nodes = [
        node(f"S{i}", "stickyNote", {"content": fill})
        for i, fill in enumerate(["pass=" * 52_428] * 6 + ["x-a-key: " + "a" * 30 + " "] * 2 + ["| password | " * 20_000] * 2)
    ]
    wf = from_data(workflow(nodes), "x")[0]
    started = time.perf_counter()
    run([wf])
    outline(wf)
    assert time.perf_counter() - started < 6


def test_many_short_labelled_values_are_read_once_each() -> None:
    wf = from_data(workflow([node("S", "stickyNote", {"content": "password: abcd1234, " * 13_000})]), "x")[0]
    started = time.perf_counter()
    assert len([f for f in run([wf]) if f.rule.id == "N8D101"]) == 1
    assert time.perf_counter() - started < 3


# --- the raw scan ------------------------------------------------------------------------------------------------------

_LEVELS_TEXT = '{bad name:"Authorization",value:"Bearer abcdefgh1234" ' + "\\" * 255 + '"'


def test_a_large_text_is_unescaped_fewer_times() -> None:
    small = list(_raw_levels(_LEVELS_TEXT))
    large = list(_raw_levels(_LEVELS_TEXT + " " * 100_000))
    assert len(small) > 4 >= len(large)


def test_the_raw_scan_stops_at_the_file_budget_and_says_so() -> None:
    payload = '{bad name:"Authorization",value:"Bearer abcdefgh1234abcd" ' + " " * 200_000
    wf = _raw_flow(payload, 12, max_raw_scan_bytes=1 * MB)
    started = time.perf_counter()
    found = [f for f in run([wf]) if f.rule.id == "N8D101"]
    assert time.perf_counter() - started < 10
    cut = [f for f in found if "scanned" in f.message and "--max-raw-scan-mb" in (f.fix_hint or "")]
    assert cut and all(f.severity.label == "info" for f in cut)


def test_a_large_text_cut_short_by_its_levels_is_reported() -> None:
    deep = json.dumps(json.dumps(json.dumps('{bad name:"Authorization",value:"abcdefgh1234abcd"')))
    wf = _raw_flow("{bad " + deep + " " * 100_000, 1)
    assert any("scanned" in f.message and f.severity.label == "info" for f in run([wf]) if f.rule.id == "N8D101")


def test_text_past_the_budget_is_not_shown() -> None:
    late = "{bad name:'x', " + json.dumps(f'const password = "{TOKEN[4:]}z"') + " " * 200_000
    data = workflow([node(f"E{i}", "executeWorkflow", {"workflowJson": late}) for i in range(12)])
    wf = from_data(data, "x.json", limits=replace(DEFAULT, max_raw_scan_bytes=1024))[0]
    show = shown_value(wf)
    assert "not shown" in show(late) and TOKEN[4:] not in show(late) and show("plain") == "plain"
    assert TOKEN[4:] not in json.dumps(masked_workflow(wf).data)


def test_an_ordinary_raw_text_is_scanned_at_every_level() -> None:
    inner = '{bad "parameters":{"name":"Authorization","value":"' + TOKEN[4:] + '"}'
    wf = _raw_flow(json.dumps(json.dumps(inner))[1:-1], 1)
    assert TOKEN[4:] in known_secrets(wf)
    assert not any("scanned" in f.message for f in run([wf]))


# --- percent spellings and masker memory -------------------------------------------------------------------------------


def _symbols(seed: int, size: int) -> str:
    return f"{seed}" + (":;<=>?@[]^!~ " * (size // 13 + 1))[:size]


def test_a_long_secret_has_no_url_spellings_in_the_masker() -> None:
    long_secret = _symbols(1, 95_000)
    wf = from_data(workflow([node("S", "set", {"password": long_secret})]), "x")[0]
    mask = secret_masker(wf)
    assert mask(f"say {long_secret} now") == "say *** now"
    short = "p@ss w:rd/1!"
    wf = from_data(workflow([node("S", "set", {"password": short})]), "x")[0]
    assert secret_masker(wf)("https://a/?p=p%40ss%20w%3Ard%2F1%21") == "https://a/?p=***"


def test_at_most_a_few_automatons_stay_alive_and_none_is_built_for_short_names(monkeypatch: pytest.MonkeyPatch) -> None:
    flows = from_data([workflow([node("S", "set", {"password": _symbols(k, 20_000)})], name=f"w{k}") for k in range(30)], "x")
    built: list[int] = []
    original = rules._MultiMasker

    def counting(*args: Any) -> Any:
        built.append(1)
        return original(*args)

    monkeypatch.setattr(rules, "_MultiMasker", counting)
    assert [name for _, name, _ in labels(flows)][:2] == ["w0", "w1"]
    assert not built  # no name is long enough to hold a secret
    for wf in flows:
        secret_masker(wf)("x" * 30_000)
    assert len(built) == 30
    assert sum(wf.masker is not None for wf in flows) <= 8


def test_the_masker_of_a_workflow_masks_the_same_after_it_was_dropped() -> None:
    flows = from_data([workflow([node("S", "set", {"password": f"Zx9!{k}-secret-value"})], name=f"w{k}") for k in range(30)], "x")
    first = secret_masker(flows[0])
    for wf in flows[1:]:
        secret_masker(wf)("x" * 100)
    assert flows[0].masker is None or flows[0].masker is first
    assert secret_masker(flows[0])("Zx9!0-secret-value") == "***"


def test_url_spellings_are_those_of_a_short_secret() -> None:
    forms = _url_spellings("p@ss w:rd/1!")
    for form in [
        "p%40ss%20w%3Ard%2F1%21",
        "p%40ss+w%3Ard%2F1%21",
        "p@ss%20w:rd/1!",
        "p@ss+w:rd/1!",
        "p%40ss%20w%3Ard/1%21",
        "p%40ss%20w%3ard%2f1!",
        "p@ss%20w:rd%2F1%21",
    ]:
        assert form in forms, form


# --- many non-workflow entries --------------------------------------------------------------------------------------------


def test_many_entries_before_the_workflow_are_paired_quickly() -> None:
    real = workflow([node("S", "set", {})])
    text = json.dumps([{"nodes": [], "connections": 1}] * 300_000 + [real], indent=None)
    started = time.perf_counter()
    (wf,) = parse_text(text, "x.json")
    assert wf.nodes[0].name == "S"
    assert time.perf_counter() - started < 6
