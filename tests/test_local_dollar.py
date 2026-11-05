"""A Code node that declares its own ``$`` (cheerio, jQuery): its ``$()`` calls are not node references."""

from __future__ import annotations

import time
from typing import Any

import pytest

from n8n_doctor.fix import fix_workflow

from .conftest import link, load, node, of, trigger, workflow


def _code(text: str) -> dict[str, Any]:
    return workflow([trigger(), node("Title", "noOp"), node("C", "code", {"jsCode": text}, 2)], link("Start", "Title", "C"))


LOCAL = [
    "const $ = cheerio.load(html);\nconst t = $('title').text();",
    "let $ = cheerio.load(html); $('table tbody tr').each(() => {});",
    "var $ = require('cheerio').load(html); $('#__NEXT_DATA__');",
    "let $;\n$ = cheerio.load(html);\n$('title');",
    "const cheerio = require('cheerio'), $ = cheerio.load(html);\n$('title');",
    "function parse($) { return $('title').text(); }",
    "function parse(html, $, opts) { return $('title').text(); }",
    "const parse = ($) => $('title').text();",
    "const parse = (html, $) => $('title').text();",
    "const parse = $ => $('title').text();",
    "const o = { parse($) { return $('title'); } };",
]


@pytest.mark.parametrize("text", LOCAL)
def test_a_local_dollar_is_no_node_reference(text: str) -> None:
    data = _code(text)
    assert of(data, "N8D207") == []
    assert not [c for c in fix_workflow(load(data)).changes if "N8D207" in c]


NOT_LOCAL = [
    "const x = $('title').first();",
    "// const $ = cheerio.load(html);\nconst x = $('title').first();",
    "const s = 'const $ = cheerio.load(html);';\nconst x = $('title').first();",
    "const a = {}; a.$ = 1;\nconst x = $('title').first();",
    "const $x = 1; const a$ = 2;\nconst x = $('title').first();",
    "if ($input.first() === $json) { const x = $('title').first(); }",
    "const ok = $json.a == 1; const f = (a, b) => a; const x = $('title').first();",
]


@pytest.mark.parametrize("text", NOT_LOCAL)
def test_n8n_dollar_stays_a_node_reference(text: str) -> None:
    data = _code(text)
    assert of(data, "N8D207")
    assert fix_workflow(load(data)).fixed["nodes"][2]["parameters"]["jsCode"] == text.replace("$('title')", "$('Title')")


def test_only_the_dollar_is_local() -> None:
    data = _code("const $ = cheerio.load(html);\n$('title');\nconst a = $node['Gone'].json;\nconst b = $items('Lost');")
    assert sorted(f.message for f in of(data, "N8D207")) == [
        'jsCode references node "Gone", which does not exist',
        'jsCode references node "Lost", which does not exist',
    ]


def test_the_declaration_counts_in_its_own_node_only() -> None:
    data = workflow(
        [trigger(), node("A", "code", {"jsCode": "const $ = cheerio.load(h); $('Gone');"}, 2), node("B", "code", {"jsCode": "$('Gone').first();"}, 2)],
        link("Start", "A", "B"),
    )
    assert [f.node for f in of(data, "N8D207")] == ["B"]


def test_an_expression_field_is_not_affected() -> None:
    data = workflow([trigger(), node("S", "set", {"a": "={{ $('Gone').first().json.x }}", "b": "const $ = 1"}, 1)], link("Start", "S"))
    assert of(data, "N8D207")


def test_looking_for_the_declaration_is_linear() -> None:
    text = "$('Gone');\n" + "(a, b, c, d, e, f, g, h, i, " * 100_000 + " " * 100_000 + "$ " * 100_000
    started = time.perf_counter()
    assert of(_code(text), "N8D207")
    assert time.perf_counter() - started < 10
