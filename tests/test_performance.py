"""Running time on crafted large inputs (limits are generous: shared CI machines are slow), and fast paths checked against simple references."""

from __future__ import annotations

import itertools
import json
import string
import time
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor import mcp
from n8n_doctor.config import Config
from n8n_doctor.explain import as_dict, mermaid, outline
from n8n_doctor.expressions import find_python_refs, find_refs, replace_ref, replace_refs, strip_js_comments
from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.workflow import from_data, node_offsets

from .conftest import BIG, link, merge, node, trigger, workflow


def test_regex_literal_scan_is_linear() -> None:
    code = "[/" * 500_000  # each / may start a regex literal: a line without a closing / is scanned once
    started = time.perf_counter()
    assert len(strip_js_comments(code)) == len(code)
    assert time.perf_counter() - started < 3
    # a line without a closing / does not stop regex literals on the next line from being recognised
    assert strip_js_comments("a = [/\nb = /items/g", blank_strings=True).endswith("b = /     /g")


def test_many_secrets_in_one_parameter() -> None:
    keys = " ".join(f"AKIAQ{i:05d}WERTYZXCVB" for i in range(50_000))  # 1 MB: deduplication and masking are linear in it
    wf = from_data(workflow([trigger(), node("S", "set", {"value": keys})], link("Start", "S")), "x", limits=BIG)[0]
    started = time.perf_counter()
    found = [f for f in run([wf]) if f.rule.id == "N8D101"]
    text = outline(wf)
    assert len(found) == 50_000 and "AKIA0000000000012345" not in text
    assert time.perf_counter() - started < 30


def test_many_nodes_with_passwords_explain_quickly() -> None:
    count = 10_000
    nodes = [trigger()] + [node(f"S{i}", "set", {"options": {"password": f"pw{i:08d}xyz"}}) for i in range(count)]
    wf = from_data(workflow(nodes, link("Start", *[f"S{i}" for i in range(count)])), "x", limits=BIG)[0]
    started = time.perf_counter()
    text = outline(wf) + json.dumps(as_dict(wf))
    assert "pw00004321xyz" not in text and "S9999" in text
    assert time.perf_counter() - started < 30


def test_many_unknown_references_lint_and_fix_quickly() -> None:
    names = [f"Node name {i} abc" for i in range(800)]
    # fuzzy matching has a per-workflow budget: the typo comes first, the 8000 unknown names exhaust the budget
    code = '$("Fetch custmer data").item\n' + "\n".join(f'$("Missing ref {i} abc").item' for i in range(8000))
    nodes = [trigger(), node("Fetch customer data", "noOp"), *(node(n, "noOp") for n in names), node("Code", "code", {"jsCode": code}, 2)]
    wf = from_data(workflow(nodes, link("Start", "Code")), "x", limits=BIG)[0]
    started = time.perf_counter()
    found = [f for f in run([wf]) if f.rule.id == "N8D207"]
    result = fix_workflow(wf, {"N8D207"})
    assert len(found) == 8001 and any('"Fetch custmer data" -> "Fetch customer data"' in c for c in result.changes)  # typo still fixed in a big workflow
    assert time.perf_counter() - started < 20


def test_line_numbers_of_many_nodes_are_counted_once() -> None:
    count = 20_000
    nodes = [trigger()] + [node(f"S{i}", "noOp") for i in range(count)]
    text = json.dumps(workflow(nodes, link("Start", *[f"S{i}" for i in range(count)])), indent=2)
    started = time.perf_counter()
    wf = from_data(json.loads(text), "x", text, limits=BIG)[0]
    assert time.perf_counter() - started < 8
    offsets = node_offsets(text)
    assert all(wf.nodes[i].line == text.count("\n", 0, offsets[i]) + 1 for i in (0, 1, 5, count))
    assert wf.nodes[1].line > wf.nodes[0].line > 1


def test_execution_masking_is_linear() -> None:
    from n8n_doctor.executions import mask_message

    started = time.perf_counter()
    for text in (
        "\\" * 200_000,
        '"password":"' * 15_000,
        '"a":"' * 40_000,
        "password%3D" * 20_000,
        "password:" * 20_000,
        "a@b.c" * 40_000,
        "key provided " * 15_000,
        "x@y.zz:" * 30_000,
        "key '" * 50_000,
    ):
        mask_message(text)
    assert time.perf_counter() - started < 10


def _timed(func: Any, limit: float) -> Any:
    started = time.perf_counter()
    result = func()
    assert time.perf_counter() - started < limit
    return result


def _only(rule: str) -> Any:

    return Config(enabled_only={rule})


def test_webhook_responses_are_checked_in_one_pass() -> None:
    names = [f"Hook {i}" for i in range(6000)]  # one pass for all webhooks, not one walk each
    hooks = [node(n, "webhook", {"path": n, "responseMode": "responseNode"}, 2) for n in names]
    wf = from_data(workflow([*hooks, node("A", "noOp")], link(*names, "A")), "x", limits=BIG)[0]
    found = _timed(lambda: run([wf], _only("N8D209")), 15)
    assert len(found) == 6000 and "no Respond to Webhook node follows" in found[0].message


def test_respond_to_webhook_lists_are_capped_and_ordered() -> None:
    hook = node("Hook", "webhook", {"path": "x", "responseMode": "responseNode"}, 2)
    sw = node("Route", "switch", {"rules": {"values": [{"outputKey": f"k{i}"} for i in range(8)]}}, 3)
    reply = node("Reply", "respondToWebhook")
    data = workflow([hook, sw, reply], merge(link("Hook", "Route"), {"Route": {"main": [[{"node": "Reply", "type": "main", "index": 0}]]}}))
    found = [f for f in run(from_data(data, "x")) if f.rule.id == "N8D209"]
    assert len(found) == 1 and found[0].message.endswith('"Route" [5] ...') and '"Route" [1], "Route" [2]' in found[0].message
    replies = [node(f"Reply {i}", "respondToWebhook") for i in range(7)]
    early = node("Hook", "webhook", {"path": "x"}, 2)
    conns = {"Hook": {"main": [[{"node": r["name"], "type": "main", "index": 0} for r in replies]]}}
    found = [f for f in run(from_data(workflow([early, *replies], conns), "x")) if f.rule.id == "N8D209"]
    assert '"Reply 0", "Reply 1", "Reply 2", "Reply 3", "Reply 4" ...' in found[0].message


def test_loops_and_schedules_scale() -> None:
    loops = [f"Loop {i}" for i in range(6000)]  # one pass over the components, not one walk per loop
    data = workflow([trigger(), *(node(n, "splitInBatches", {}, 3) for n in loops)], link("Start", *loops, output=1))
    found = _timed(lambda: run(from_data(data, "x", limits=BIG), _only("N8D304")), 15)
    assert len(found) == 5999  # the last one has no loop output at all
    scheds = [f"Sched {i}" for i in range(6000)]
    rule = {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}}
    wait = node("Wait", "wait", {"amount": 1, "unit": "hours"}, 1.1)
    data = workflow([*(node(n, "scheduleTrigger", rule, 1.2) for n in scheds), wait], link(*scheds, "Wait"))
    found = _timed(lambda: run(from_data(data, "x", limits=BIG), _only("N8D306")), 15)
    assert len(found) == 6000 and '"Wait" alone waits 1 h' in found[0].message


def test_switch_with_many_outputs_explains_quickly() -> None:
    rules = [{"outputKey": f"k{i}", "renameOutput": True} for i in range(15000)]  # each node's connections are grouped once
    sw = node("Sw", "switch", {"rules": {"values": rules}}, 3.2)
    conns = {"Start": {"main": [[{"node": "Sw", "type": "main", "index": 0}]]}, "Sw": {"main": [[{"node": "T", "type": "main", "index": 0}]] * 15000}}
    wf = from_data(workflow([trigger(), sw, node("T", "noOp")], conns), "x", limits=BIG)[0]
    as_json = _timed(lambda: as_dict(wf), 15)
    assert as_json["nodes"][1]["outputs"][14999] == {"label": "k14999", "to": ["T"]}
    assert _timed(lambda: mermaid(wf), 15).count("-->") == 15001


def test_big_code_parameter_fixes_quickly() -> None:
    line = "const value = items.map(x => x.json.id); // comment here\n"
    code = '$("Old Name").all();\n' + line * 70_000  # 4 MB of code: the fix rewrites one reference
    nodes = [trigger(), node("Code", "code", {"jsCode": code}, 2), node("Old-Name", "noOp")]
    wf = from_data(workflow(nodes, link("Start", "Code", "Old-Name")), "x")[0]
    result = _timed(lambda: fix_workflow(wf), 20)
    assert any('"Old Name" -> "Old-Name"' in c for c in result.changes)


def test_c1_escaping_is_fast() -> None:
    from n8n_doctor.files import json_dumps

    text = _timed(lambda: json_dumps({"v": "\u0085" * 2_000_000 + " ok"}), 5)
    assert text.count("\\u0085") == 2_000_000 and "\\u2028ok" in text


def test_long_and_periodic_secrets_mask_quickly() -> None:
    pem = '$("Old Name");' + '"-----BEGIN PRIVATE KEY-----xyz" ' * 100_000  # each header is found once, without slicing the rest
    nodes = [trigger(), node("Code", "code", {"jsCode": pem}, 2), node("Old-Name", "noOp")]
    wf = from_data(workflow(nodes, link("Start", "Code", "Old-Name")), "x")[0]
    result = _timed(lambda: fix_workflow(wf), 20)
    assert "xyz" not in result.diff


def test_masker_matches_naive_union() -> None:
    import random

    from n8n_doctor.rules import _MultiMasker

    def naive(forms: set[str], text: str) -> str:
        spans = sorted((k, k + len(f)) for f in forms if len(f) >= 4 for k in range(len(text)) if text.startswith(f, k))
        out, last, start, end = [], 0, -1, -1
        for s, e in [*spans, (len(text) + 1, len(text) + 1)]:
            if s > end:
                if end > start:
                    out += [text[last:start], "***"]
                    last = end
                start = s
            end = max(end, e)
        return "".join([*out, text[last:]])

    rng = random.Random(5)
    for _ in range(400):
        base = "".join(rng.choice("ab") for _ in range(rng.randint(1, 5)))
        text = "".join(c if rng.random() > 0.01 else "c" for c in (base * 400)[: rng.randint(0, 1200)])
        forms = {text[i : i + rng.choice([4, 10, 257, 600])] for i in (rng.randrange(len(text) or 1) for _ in range(3))} | {base * 100}
        assert _MultiMasker(forms)(text) == naive(forms, text)


def test_many_http_nodes_fix_quickly() -> None:
    names = [f"Fetch {i}" for i in range(10_000)]
    nodes = [trigger(), *(node(n, "httpRequest", {"url": "https://x.example.com", "options": {}}, 4.2) for n in names)]
    wf = from_data(workflow(nodes, link("Start", *names)), "x", limits=BIG)[0]
    result = _timed(lambda: fix_workflow(wf, {"N8D302"}, set_timeout=30000), 20)
    assert sum(1 for line in result.diff.splitlines() if line.endswith("options.timeout: added 30000")) == 10_000


def _many_lengths_one_prefix(size: int, values: list[str]) -> Any:
    """Many secrets sharing their first characters, and big texts made of that prefix: what made the masker slow."""
    headers = {"parameters": [{"name": "Authorization", "value": v} for v in values]}
    params = {"url": "https://x.example.com/" + "a" * size, "sendHeaders": True, "headerParameters": headers, "options": {}}
    http = node("HTTP", "httpRequest", params, 4.2, notes="a" * size)
    sticky = node("Note", "stickyNote", {"content": "a" * size})
    return from_data(workflow([trigger(), http, sticky], link("Start", "HTTP")), "x")[0]


@pytest.mark.parametrize(
    "values",
    [["aaaa" + "1" * k for k in range(4, 254)], ["a" * 300 + "b" * k for k in range(1, 250)]],
    ids=["short", "long"],
)
def test_secrets_of_many_lengths_mask_in_linear_time(values: list[str]) -> None:
    wf = _many_lengths_one_prefix(1_000_000, values)  # 3 MB of text made of overlapping secrets
    _timed(lambda: (outline(wf), mermaid(wf), as_dict(wf)), 20)
    result = _timed(lambda: fix_workflow(wf), 20)
    assert values[-1] not in result.diff and "retryOnFail: added true" in result.diff


def test_masker_matches_naive_union_on_many_overlapping_strings() -> None:
    import random

    from n8n_doctor.rules import _MultiMasker

    def naive(forms: set[str], text: str) -> str:
        covered = [False] * len(text)
        for f in forms:
            if len(f) >= 4:
                for k in range(len(text) - len(f) + 1):
                    if text.startswith(f, k):
                        covered[k : k + len(f)] = [True] * len(f)
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

    rng = random.Random(11)
    for _ in range(1500):
        alphabet = rng.choice(["ab", "abc", "aé ", "abcdefgh", "a1", "\U0001f511k"])
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        forms: set[str] = set()
        for _ in range(rng.randint(0, 40)):
            if text and rng.random() < 0.7:
                i = rng.randrange(len(text))
                forms.add(text[i : i + rng.randint(1, 60)])
            else:
                forms.add("".join(rng.choice(alphabet) for _ in range(rng.randint(1, 12))))
        assert _MultiMasker(forms)(text) == naive(forms, text)  # one *** per run of covered characters


@pytest.mark.parametrize("unit", ["http://a", "http://a@", "https://a/b#", "Basic+", "Basic%20+", "token: Bearer ", "Authorization: ", 'password = "', "ab:"])
def test_execution_messages_with_repeated_prefixes_mask_quickly(unit: str) -> None:
    from n8n_doctor.executions import mask_message

    text = (unit * 40_000)[:200_000]  # 200 KB of URL starts or Basic schemes: each run is measured once
    _timed(lambda: mask_message(text), 3)


def test_linear_scans_match_the_regexes_they_replace() -> None:
    import base64
    import random
    import re

    from n8n_doctor.executions import _mask_basic, _mask_basic_all, _mask_query_strings
    from n8n_doctor.rules import _without_number

    basic = re.compile(r"\b(Basic)([ \t]+|%20|\+)([A-Za-z0-9+/_%-]{4,4096}(?:={0,2}|(?:%3D){0,2}))(?![A-Za-z0-9+/=_%-])", re.IGNORECASE)
    query = re.compile(r"(https?://[^\s?#'\"]+)\?[^\s'\"]*")
    cred = base64.b64encode(b"user:pw").decode()
    parts = ["Basic", "basic", " ", "\t", "%20", "+", "=", "==", "%3D", cred, "abc", "x", "-", "#", "?", "http://", "https://a", "'", '"', "/", ":"]
    rng = random.Random(4)
    for _ in range(5000):
        t = "".join(rng.choice(parts) for _ in range(rng.randint(0, 14)))
        assert _mask_basic_all(t) == basic.sub(lambda m: _mask_basic(m.group(1), m.group(2), m.group(3), m.group(0)), t), t
        assert _mask_query_strings(t, "...") == query.sub(r"\1?...", t), t
    for n in (4095, 4096, 4097):  # the 4096-character limit on a Basic token
        for tail in ("", "=", "===", "=x", " x"):
            t = "Basic " + ("dTpw" * 1100)[:n] + tail
            assert _mask_basic_all(t) == basic.sub(lambda m: _mask_basic(m.group(1), m.group(2), m.group(3), m.group(0)), t)
    for _ in range(5000):
        t = "".join(rng.choice("a1\n٣ 9") for _ in range(rng.randint(0, 8)))
        assert _without_number(t) == re.sub(r"\d+$", "", t), repr(t)


def test_long_digit_runs_in_names_are_quick() -> None:
    digits = "1" * 200_000 + "a"  # a long digit run not at the end: the trailing-number strip is linear
    nodes = [trigger(), node(digits, "noOp"), node("Code", "code", {"jsCode": f'return $("{digits}b").all();'}, 2)]
    wf = from_data(workflow(nodes, link("Start", digits, "Code")), "x", limits=BIG)[0]
    _timed(lambda: run([wf]), 10)
    _timed(lambda: fix_workflow(wf), 10)


def test_executions_mask_only_the_start_of_long_messages() -> None:
    from n8n_doctor import executions

    message = '"password": "x", ' * 12_000  # 200 KB: only the first MESSAGE_MASKED characters are masked
    flow = workflow([trigger(), node("Call", "httpRequest", {"url": "https://a"}, 4.2)], link("Start", "Call"), name="F", versionId="v1")

    class _Client:
        base = "x"
        _key = "n8n_api_key_value_123456"

        def executions(self, *args: object, **kwargs: object) -> Any:
            for i in range(200):
                error = {"message": message + str(i), "name": "NodeApiError", "node": {"name": "Call"}}
                yield {"id": str(i), "workflowId": "w1", "workflowData": flow, "data": {"resultData": {"error": error}}}

        def workflow(self, wid: str) -> object:
            raise AssertionError

    start = time.perf_counter()
    result = executions.summarize(_Client(), None, 200)  # type: ignore[arg-type]
    assert time.perf_counter() - start < 6  # about 2.5 s on a laptop
    assert result["executions"] == 200 and '"password": "***"' in result["groups"][0]["example"]


def test_email_token_after_a_long_local_part_is_masked_quickly() -> None:
    from n8n_doctor.executions import mask_message

    assert mask_message("x" * 300 + "@example.com:abcd12345678") == "x" * 300 + "@example.com:***"
    start = time.perf_counter()
    mask_message("a-" * 100_000)
    assert time.perf_counter() - start < 1


def test_many_references_inside_string_literals_are_quick() -> None:
    for quote in "'`":
        code = "const s = " + quote + "$('Gone') " * 90_000 + quote + ";\nreturn [];"  # 900 KB of references in one literal
        wf = workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"))
        found = _timed(lambda wf=wf: run(from_data(wf, "x")), 10)
        assert not [f for f in found if f.rule.id == "N8D207"]


def _two_letter_names(count: int, size: int, seed: int) -> list[str]:
    """Names of ``size`` letters a and b: the worst case for difflib (every character matches many others)."""
    import random

    rng = random.Random(seed)
    return list(dict.fromkeys("a" + "".join(rng.choices("ab", k=size - 2)) + "b" for _ in range(count)))


def _fuzzy_workflow(names: int, refs: int, size: int, seed: int) -> dict[str, Any]:
    targets = _two_letter_names(names, size, seed)
    missing = _two_letter_names(refs, size, seed + 1000)
    code = "\n".join(f"$('{r}').item.json.x;" for r in missing)
    nodes = [trigger(), *(node(n, "noOp") for n in targets), node("Code", "code", {"jsCode": code}, 2)]
    return workflow(nodes, link("Start", "Code"), name=f"W{seed}")


def test_typo_suggestions_for_long_names_are_bounded() -> None:
    # 300 names and 400 references of 128 letters a/b (tests/fixtures perf repro fz1): once 80 s of difflib
    wf = from_data(_fuzzy_workflow(300, 400, 128, 1), "x", limits=BIG)[0]
    found = _timed(lambda: [f for f in run([wf]) if f.rule.id == "N8D207"], 5)
    assert len(found) == 400


def test_typo_suggestion_budget_is_shared_by_the_workflows_of_a_run() -> None:
    # 64 letters (the longest name still compared) in 6 workflows: the budget is for the run, not each workflow
    flows = [from_data(_fuzzy_workflow(300, 300, 64, seed), "x", limits=BIG)[0] for seed in range(6)]
    found = _timed(lambda: [f for f in run(flows) if f.rule.id == "N8D207"], 5)
    assert len(found) == 6 * 300
    assert len({id(wf.fuzzy_budget) for wf in flows}) == 1


def test_fix_reuses_the_typo_suggestions_of_its_lint_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    from n8n_doctor import rules

    calls: list[str] = []
    real = rules._rename_target

    def counted(index: Any, missing: str) -> str | None:
        calls.append(missing)
        return real(index, missing)

    monkeypatch.setattr(rules, "_rename_target", counted)
    code = "$('Fetch custmer').item;\n$('Gone').item;\n$('Fetch custmer').first();"
    data = workflow([trigger(), node("Fetch customer", "noOp"), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"))
    result = fix_workflow(from_data(data, "x")[0])
    assert any('"Fetch custmer" -> "Fetch customer"' in c for c in result.changes)
    assert sorted(calls) == ["Fetch custmer", "Gone"]  # once each, over every round of the fix


def test_code_is_stripped_once_per_value_across_rules_and_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    from n8n_doctor import expressions

    calls: Counter[tuple[str, bool]] = Counter()
    real = expressions._strip_js_comments

    def counted(code: str, blank: bool) -> str:
        calls[code, blank] += 1
        return real(code, blank)

    monkeypatch.setattr(expressions, "_strip_js_comments", counted)
    codes = [f"// node {i}\nconst apiKey = 'Q1w2E3r4T5y6U7i8{i}';\nreturn $('Gone {i}').all();" for i in range(60)]
    nodes = [trigger(), *(node(f"Code {i}", "code", {"jsCode": c}, 2) for i, c in enumerate(codes))]
    wf = from_data(workflow(nodes, link("Start", *[f"Code {i}" for i in range(60)])), "x")[0]
    run([wf])
    fix_workflow(wf)
    assert calls and max(calls.values()) == 1


def test_findings_past_the_run_limit_are_counted_cheaply() -> None:
    """1,000 workflows with 2,420 distinct unknown references each: past --max-findings-total they are only counted."""
    chars = string.ascii_letters + string.digits
    names = ["".join(p) for p in itertools.product(chars, repeat=2)][:2420]
    code = "\n".join(f"$('{n}').item" for n in names) + "\nreturn [];"
    flows = [
        wf
        for i in range(1000)
        for wf in from_data(workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"), name=f"W{i}"), f"w{i}.json")
    ]
    started = time.perf_counter()
    found = run(flows)
    elapsed = time.perf_counter() - started
    listed = [f for f in found if not f.extra.get("omitted")]
    counted = sum(sum(f.extra["omitted"].values()) for f in found if f.extra.get("omitted"))
    assert len(listed) == 20_000 and len(listed) + counted == 2_420_000
    assert found[-1].extra["omitted_by_rule"] == {"N8D207": 2_420_000 - 20_000 - 99 * 2220}  # the 100th workflow reaches the run limit
    assert elapsed < 10, elapsed


def _repeated_references(count: int) -> dict[str, Any]:
    return workflow([trigger(), node("Mizing", "noOp"), node("C", "code", {"jsCode": "$('Mising').all();\n" * count}, 2)], link("Start", "Mizing", "C"))


def test_many_references_in_one_value_fix_in_one_pass() -> None:
    limits = BIG
    wf = from_data(_repeated_references(1_000_000), "x.json", limits=limits)[0]
    started = time.perf_counter()
    result = fix_workflow(wf, {"N8D207"})
    assert time.perf_counter() - started < 60  # one copy of 18 MB per reference would take hours
    assert result.fixed["nodes"][2]["parameters"]["jsCode"] == "$('Mizing').all();\n" * 1_000_000
    assert sum(1 for c in result.changes if "1,000,000 times" in c) == 1


def test_replace_refs_matches_replacing_one_by_one() -> None:
    text = "a $('One') b $(\"Two\") c $node['Three'] d $node.Four e $items('Five', 0) f _('Six') g"
    refs = [*find_refs(text), *find_python_refs(text)]
    pairs = [(ref, ref.name + "!") for ref in refs]
    one_by_one = text
    for ref, target in sorted(pairs, key=lambda p: p[0].start, reverse=True):
        one_by_one = replace_ref(one_by_one, ref, target)
    assert replace_refs(text, pairs) == one_by_one
    assert replace_refs(text, []) == text


def test_fix_tool_of_the_mcp_server_handles_many_references(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "wf.json").write_text(json.dumps(_repeated_references(1_000_000)))
    started = time.perf_counter()
    text = mcp.call_tool("n8n_fix", {"path": "wf.json"})["content"][0]["text"]
    assert time.perf_counter() - started < 60
    assert "Mizing" in text
