"""Every rule with at least one workflow that triggers it and one that must not."""

from __future__ import annotations

import json
from typing import Any

import pytest

from n8n_doctor.fix import fix_workflow
from n8n_doctor.lint import run
from n8n_doctor.model import Severity
from n8n_doctor.rules import RULES, resolve
from n8n_doctor.workflow import from_data, parse_text

from .conftest import REGRESSION_FIXTURES, findings, link, load, merge, node, of, trigger, workflow

# Token-shaped strings are assembled at runtime so this file never contains a real-looking secret.
SLACK = "xox" + "b-" + "1234567890-1234567890123-" + "a" * 24
GITHUB = "gh" + "p_" + "A" * 36
AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
OPENAI = "sk" + "-proj-" + "x1Y2z3" * 8
STRIPE = "sk" + "_live_" + "a1B2c3D4" * 3
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
TELEGRAM = "123456789:AA" + "b" * 33


def http(name: str = "HTTP", **params: Any) -> dict[str, Any]:
    raw = params.pop("raw", {})
    return node(name, "httpRequest", {"url": "https://api.example.com/x", "options": {"timeout": 5000}, **params}, 4.2, **raw)


def run_http(n: dict[str, Any]) -> dict[str, Any]:
    return workflow([trigger(), n], link("Start", n["name"]))


def test_rule_ids_and_names_are_unique_and_stable() -> None:
    ids = [r.id for r in RULES]
    names = [r.meta.name for r in RULES]
    assert len(ids) == len(set(ids)) and len(names) == len(set(names))
    assert all(len(i) == 6 and i.startswith("N8D") for i in ids)
    assert resolve("n8d101").name == "hardcoded-secret"
    assert resolve("hardcoded-secret").id == "N8D101"
    with pytest.raises(KeyError):
        resolve("nope")


# --- N8D101 hardcoded-secret ------------------------------------------------------------------


@pytest.mark.parametrize("token", [SLACK, GITHUB, AWS, OPENAI, STRIPE, JWT, TELEGRAM])
def test_secret_patterns_in_any_parameter(token: str) -> None:
    wf = run_http(http(url=f"https://api.example.com/x?key={token}"))
    found = of(wf, "N8D101")
    assert len(found) == 1 and found[0].node == "HTTP"
    assert token not in found[0].message  # never echo the secret


def test_secret_in_sensitive_header_value() -> None:
    wf = run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": "X-API-Key", "value": "q8w7e6r5t4y3u2i1"}]}))
    found = of(wf, "N8D101")
    assert found and found[0].parameter == "headerParameters.parameters[0].value"
    assert "q8w7e6r5t4y3u2i1" not in found[0].message


def test_bearer_and_url_password() -> None:
    assert of(run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": "Auth", "value": "Bearer " + "z" * 30}]})), "N8D101")
    assert of(run_http(http(url="postgres://admin:hunter2secret@db.example.com/app")), "N8D101")


def test_secret_in_json_headers_and_code_and_private_key() -> None:
    assert of(run_http(http(specifyHeaders="json", jsonHeaders='{"Authorization": "Token abcdefgh12345678"}')), "N8D101")
    assert of(run_http(http(specifyHeaders="json", jsonHeaders='{"x-api-key": "abcdefgh12345678"}')), "N8D101")
    code = node("Code", "code", {"jsCode": 'const apiKey = "s3cr3tV4lu3Abc123";\nreturn [];'}, 2)
    assert of(workflow([trigger(), code], link("Start", "Code")), "N8D101")
    pem = node("Code", "code", {"jsCode": "const k = `-----BEGIN RSA PRIVATE KEY-----\\nMII...`;"}, 2)
    assert of(workflow([trigger(), pem], link("Start", "Code")), "N8D101")


@pytest.mark.parametrize(
    "value",
    [
        "={{ $credentials.token }}",
        "={{ 'Bearer ' + $env.API_TOKEN }}",
        "YOUR_API_KEY",
        "<token>",
        "xxxxxxxxxxxx",
        "short",
    ],
)
def test_no_secret_for_expressions_and_placeholders(value: str) -> None:
    wf = run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": "Authorization", "value": value}]}))
    assert of(wf, "N8D101") == []


@pytest.mark.parametrize(
    "value",
    [
        "POSTIZ_API_KEY",
        "CLIENTSECRET",
        "enter-your-api-key",
        "=add-your-api-key",
        "REPLACE_ME",
        "%API_KEY%",
        "<YOUR_TOKEN>",
        "sk-" + "x" * 40,
        "ghp_" + "x" * 36,
        "ghp_" + "0" * 36,
        "AKIA" + "X" * 16,
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-your-token-here",
        "sk_live_" + "*" * 24,
    ],
)
def test_placeholders_are_not_secrets(value: str) -> None:
    header = run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": "Authorization", "value": value}]}))
    assert of(header, "N8D101") == []
    field = workflow([trigger(), node("S", "set", {"options": {"password": value}})], link("Start", "S"))
    assert of(field, "N8D101") == []
    code = node("Code", "code", {"jsCode": f'const apiKey = "{value}";\nreturn [];'}, 2)
    assert of(workflow([trigger(), code], link("Start", "Code")), "N8D101") == []


@pytest.mark.parametrize(
    "value",
    [
        "sk-proj-" + "Q7wE9rT2yU4iO6pA8sD0fG1hJ3kL5zX7cV9bN2mQ4",
        "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
        "AKIA" + "Q7WE9RT2YU4IO6PA",
        "xoxb-" + "1234567890-0987654321-aB3dE5fG7hJ9kL1mN3pQ5r",
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "a1dd9f3k2Lm8Qz7Xw4",  # "dd" and digits: not a placeholder word between punctuation
        "Zq8vR2mK-add9xT4pL7wB3nY",  # a word between a letter run and a digit is part of the key
        "API_KEY_7Q2W9E4R8T1Y",  # capitals with underscores, but generated
        # template-like, but not one of the clear forms: reported (and masked in any case)
        "insert_token_here_please",
        "my-example-password-1",
        "sk-proj-yourKeyGoesHere0123456789abcdef",
    ],
)
def test_real_looking_tokens_stay_secrets(value: str) -> None:
    field = workflow([trigger(), node("S", "set", {"options": {"password": value}})], link("Start", "S"))
    assert of(field, "N8D101")


@pytest.mark.parametrize(
    ("name", "value", "found"),
    [
        ("X-Custom-Auth", "Zq8vR2mK9xT4pL7wB3nY", True),
        ("X-Partner-Token", "a8F3kQ9zL2mW7vB1nX5c", True),
        ("x-service-key", "Q7wE9rT2yU4iO6pA8sD0", True),
        ("X-Custom-Auth", "enabled", False),
        ("X-Custom-Auth", "my-service-name", False),
        ("X-Custom-Auth", "aaaaaaaa11111111", False),  # too few distinct characters
        ("X-Monkey-Id", "customer-2024-01-01", False),
        ("X-Request-Key", "Zq8vR2mK9xT4pL7wB3nY", False),  # a request id, not a credential
        ("X-Custom-Auth", "ENTER_YOUR_KEY_123", True),  # not a clear placeholder form: reported
        # a secret word only as a whole word, and not the keys of caches, partitions or the WebSocket handshake
        ("X-Author-Id", "Zq8vR2mK9xT4pL7wB3nY", False),
        ("X-Keyword", "Zq8vR2mK9xT4pL7wB3nY", False),
        ("X-Tokenizer-Model", "Zq8vR2mK9xT4pL7wB3nY", False),
        ("X-Cache-Key", "Zq8vR2mK9xT4pL7wB3nY", False),
        ("X-Partition-Key", "Zq8vR2mK9xT4pL7wB3nY", False),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", False),
        ("X-Api-Key", "Zq8vR2mK9xT4pL7wB3nY", True),
        ("XApiKey", "Zq8vR2mK9xT4pL7wB3nY", True),
        ("X-AuthToken", "Zq8vR2mK9xT4pL7wB3nY", True),
    ],
)
def test_custom_auth_header_names(name: str, value: str, found: bool) -> None:
    wf = run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": name, "value": value}]}))
    assert bool(of(wf, "N8D101")) is found


def test_no_secret_for_normal_values_and_commented_code() -> None:
    wf = run_http(http(sendHeaders=True, headerParameters={"parameters": [{"name": "Accept", "value": "application/json-patch+json"}]}))
    assert of(wf, "N8D101") == []
    code = node("Code", "code", {"jsCode": f"// old: {SLACK}\nconst token = $env.TOKEN;\nreturn [];"}, 2)
    assert of(workflow([trigger(), code], link("Start", "Code")), "N8D101") == []


def test_secret_allowlist_from_config() -> None:
    from n8n_doctor.config import Config

    from .conftest import findings

    wf = run_http(http(url=f"https://x.example.com/?k={STRIPE}"))
    cfg = Config(options={"N8D101": {"allow": ["_live_a1B2"]}})
    assert [f for f in findings(wf, cfg) if f.rule.id == "N8D101"] == []


# --- N8D102 / N8D103 / N8D104 / N8D105 ---------------------------------------------------------


def test_webhook_without_auth() -> None:
    open_hook = node("Hook", "webhook", {"httpMethod": "POST", "path": "in"}, 2)
    assert of(workflow([open_hook]), "N8D102")[0].message == "POST /in has no authentication"
    closed = node("Hook", "webhook", {"path": "in", "authentication": "headerAuth"}, 2, credentials={"httpHeaderAuth": {"id": "1", "name": "h"}})
    assert of(workflow([closed]), "N8D102") == []
    assert of(workflow([{**open_hook, "disabled": True}]), "N8D102") == []


def test_webhook_test_url() -> None:
    assert of(run_http(http(url="https://n8n.example.com/webhook-test/abc")), "N8D103")
    assert of(run_http(http(url="https://n8n.example.com/webhook/abc")), "N8D103") == []


def test_wait_resume_without_auth() -> None:
    wait = node("Wait", "wait", {"resume": "webhook"}, 1.1)
    assert of(workflow([trigger(), wait], link("Start", "Wait")), "N8D104")
    wait_auth = node("Wait", "wait", {"resume": "webhook", "incomingAuthentication": "basicAuth"}, 1.1)
    assert of(workflow([trigger(), wait_auth], link("Start", "Wait")), "N8D104") == []
    timed = node("Wait", "wait", {"amount": 5, "unit": "seconds"}, 1.1)
    assert of(workflow([trigger(), timed], link("Start", "Wait")), "N8D104") == []


def test_tls_verification_disabled() -> None:
    assert of(run_http(http(options={"allowUnauthorizedCerts": True, "timeout": 1})), "N8D105")
    assert of(run_http(http(options={"allowUnauthorizedCerts": False, "timeout": 1})), "N8D105") == []


# --- structure ----------------------------------------------------------------------------------


def test_unreachable_and_orphan_nodes() -> None:
    wf = workflow(
        [trigger(), node("A", "noOp"), node("Orphan", "noOp"), node("B", "noOp"), node("C", "noOp"), node("Off", "noOp", disabled=True)],
        merge(link("Start", "A"), link("B", "C")),
    )
    found = {f.node: f for f in of(wf, "N8D201")}
    assert set(found) == {"Orphan", "B", "C", "Off"}
    assert "not connected to anything" in found["Orphan"].message
    assert "not reachable" in found["B"].message
    assert found["Off"].severity == Severity.INFO


def test_ai_sub_nodes_and_sticky_notes_are_reachable() -> None:
    agent = node("Agent", "@n8n/n8n-nodes-langchain.agent", {}, 1.7)
    model = node("Model", "@n8n/n8n-nodes-langchain.lmChatOpenAi", {}, 1)
    tool = node("Tool", "@n8n/n8n-nodes-langchain.toolHttpRequest", {}, 1)
    sticky = node("Note", "stickyNote", {"content": "hello"})
    conns = merge(
        link("Start", "Agent"),
        {"Model": {"ai_languageModel": [[{"node": "Agent", "type": "ai_languageModel", "index": 0}]]}},
        {"Tool": {"ai_tool": [[{"node": "Agent", "type": "ai_tool", "index": 0}]]}},
    )
    assert of(workflow([trigger(), agent, model, tool, sticky], conns), "N8D201") == []


def test_no_trigger() -> None:
    assert of(workflow([node("A", "noOp")]), "N8D202")
    assert of(workflow([trigger()]), "N8D202") == []
    assert [f.message for f in of(workflow([node("Note", "stickyNote")]), "N8D202")] == ["the workflow has no nodes (only sticky notes)"]
    # unreachable is not reported on top of no-trigger
    assert of(workflow([node("A", "noOp")]), "N8D201") == []


def _if(left: Any, right: Any, single: bool = False, version: float = 2) -> dict[str, Any]:
    op = {"type": "string", "operation": "equals", **({"singleValue": True} if single else {})}
    return node("IF", "if", {"conditions": {"conditions": [{"leftValue": left, "rightValue": right, "operator": op}], "combinator": "and"}}, version)


@pytest.mark.parametrize(("left", "right", "single"), [("status", "ok", False), ("", "", False), ("company", "", True), (5, 5, False)])
def test_constant_condition(left: Any, right: Any, single: bool) -> None:
    wf = workflow([trigger(), _if(left, right, single)], link("Start", "IF"))
    assert of(wf, "N8D203")


@pytest.mark.parametrize(("left", "right", "single"), [("={{ $json.status }}", "ok", False), ("ok", "={{ $json.x }}", False), ("={{ $json.c }}", "", True)])
def test_condition_with_expression_is_fine(left: Any, right: Any, single: bool) -> None:
    wf = workflow([trigger(), _if(left, right, single)], link("Start", "IF"))
    assert of(wf, "N8D203") == []


def test_constant_condition_if_v1_and_switch_v3() -> None:
    v1 = node("IF", "if", {"conditions": {"string": [{"value1": "a", "value2": "b"}]}}, 1)
    assert of(workflow([trigger(), v1], link("Start", "IF")), "N8D203")
    v1_ok = node("IF", "if", {"conditions": {"string": [{"value1": "={{ $json.a }}", "value2": "b"}]}}, 1)
    assert of(workflow([trigger(), v1_ok], link("Start", "IF")), "N8D203") == []
    sw = node("Switch", "switch", {"rules": {"values": [{"conditions": {"conditions": [{"leftValue": "x", "rightValue": "x", "operator": {}}]}}]}}, 3)
    found = of(workflow([trigger(), sw], link("Start", "Switch")), "N8D203")
    assert found[0].parameter == "rules.values[0]" and found[0].message.startswith("rule 1 ")


def _switch(n_rules: int, fallback: str | None = None) -> dict[str, Any]:
    values = [
        {"conditions": {"conditions": [{"leftValue": "={{ $json.k }}", "rightValue": str(i), "operator": {}}]}, "renameOutput": True, "outputKey": f"r{i}"}
        for i in range(n_rules)
    ]
    return node("Switch", "switch", {"rules": {"values": values}, "options": {"fallbackOutput": fallback} if fallback else {}}, 3.2)


def test_unconnected_switch_output() -> None:
    nodes = [trigger(), _switch(3, "extra"), node("A", "noOp")]
    found = of(workflow(nodes, merge(link("Start", "Switch"), link("Switch", "A"))), "N8D204")
    assert found and "r1, r2, fallback" in found[0].message
    all_connected = merge(link("Start", "Switch"), *(link("Switch", "A", output=i) for i in range(4)))
    assert of(workflow(nodes, all_connected), "N8D204") == []
    # a Switch with nothing connected is not reported here (the flow just ends)
    assert of(workflow([trigger(), _switch(2)], link("Start", "Switch")), "N8D204") == []


def test_switch_expression_mode_and_v2() -> None:
    expr = node("Switch", "switch", {"mode": "expression", "numberOutputs": 3, "output": "={{ 0 }}"}, 3)
    found = of(workflow([trigger(), expr, node("A", "noOp")], merge(link("Start", "Switch"), link("Switch", "A"))), "N8D204")
    assert found and "1, 2" in found[0].message
    v2 = node("Switch", "switch", {"rules": {"rules": [{"outputKey": "a"}, {"outputKey": "b"}]}, "fallbackOutput": -1}, 2)
    assert of(workflow([trigger(), v2, node("A", "noOp")], merge(link("Start", "Switch"), link("Switch", "A"))), "N8D204")


def test_dangling_connection() -> None:
    wf = workflow([trigger(), node("A", "noOp")], merge(link("Start", "A"), link("A", "Gone"), link("Ghost", "A")))
    messages = sorted(f.message for f in of(wf, "N8D205"))
    assert len(messages) == 2 and any('to missing node "Gone"' in m for m in messages) and any('from missing node "Ghost"' in m for m in messages)
    assert of(workflow([trigger(), node("A", "noOp")], link("Start", "A")), "N8D205") == []


def test_duplicate_node_name() -> None:
    assert of(workflow([trigger(), node("A", "noOp"), node("A", "set")], link("Start", "A")), "N8D206")
    assert of(workflow([trigger(), node("A", "noOp")], link("Start", "A")), "N8D206") == []


@pytest.mark.parametrize(
    "expr",
    ["={{ $('Missing').item.json.x }}", '={{ $node["Missing"].json.x }}', "={{ $items('Missing')[0].json }}", "={{ $node.Missing.json.x }}"],
)
def test_unknown_node_reference(expr: str) -> None:
    wf = workflow([trigger(), node("Set", "set", {"value": expr}, 3.4)], link("Start", "Set"))
    found = of(wf, "N8D207")
    assert len(found) == 1 and '"Missing"' in found[0].message


def test_known_references_and_plain_text_are_fine() -> None:
    params = {"a": "={{ $('Start').item.json }}", "b": '={{ $node["Start"].json }}', "c": "$('Missing') in plain text", "d": "={{ $node.context }}"}
    assert of(workflow([trigger(), node("Set", "set", params, 3.4)], link("Start", "Set")), "N8D207") == []


def test_unknown_reference_in_code_and_suggestion() -> None:
    code = node("Code", "code", {"jsCode": "// $('Ignored in comment')\nconst x = $('Fetch Lead').first();\nreturn [x];"}, 2)
    wf = workflow([trigger(), node("Fetch lead", "noOp"), code], link("Start", "Fetch lead", "Code"))
    found = of(wf, "N8D207")
    assert len(found) == 1 and found[0].fix_hint and '"Fetch lead"' in found[0].fix_hint and found[0].fixable


def test_missing_credentials() -> None:
    no_id = node("Sheet", "googleSheets", {}, 4, credentials={"googleSheetsOAuth2Api": {"name": "acct"}})
    assert of(workflow([trigger(), no_id], link("Start", "Sheet")), "N8D208")
    ok = node("Sheet", "googleSheets", {}, 4, credentials={"googleSheetsOAuth2Api": {"id": "4", "name": "acct"}})
    assert of(workflow([trigger(), ok], link("Start", "Sheet")), "N8D208") == []
    h = http(authentication="genericCredentialType", genericAuthType="httpHeaderAuth")
    assert of(run_http(h), "N8D208")
    h_ok = http(authentication="genericCredentialType", genericAuthType="httpHeaderAuth", raw={"credentials": {"httpHeaderAuth": {"id": "1", "name": "x"}}})
    assert of(run_http(h_ok), "N8D208") == []
    h_wrong = http(authentication="predefinedCredentialType", nodeCredentialType="githubApi", raw={"credentials": {"slackApi": {"id": "1", "name": "x"}}})
    assert of(run_http(h_wrong), "N8D208")
    slack = node("Slack", "slack", {"authentication": "oAuth2"}, 2)
    assert of(workflow([trigger(), slack], link("Start", "Slack")), "N8D208")
    hook = node("Hook", "webhook", {"authentication": "basicAuth", "path": "x"}, 2)
    assert of(workflow([hook]), "N8D208")


def test_respond_to_webhook_mismatch() -> None:
    params = {"path": "x", "responseMode": "responseNode", "authentication": "headerAuth"}
    hook = node("Hook", "webhook", params, 2, credentials={"httpHeaderAuth": {"id": "1"}})
    respond = node("Reply", "respondToWebhook", {}, 1.1)
    assert of(workflow([hook, node("A", "noOp")], link("Hook", "A")), "N8D209")
    assert of(workflow([hook, node("A", "noOp"), respond], link("Hook", "A", "Reply")), "N8D209") == []
    immediate = {**hook, "parameters": {"path": "x", "responseMode": "onReceived", "authentication": "headerAuth"}}
    found = of(workflow([immediate, respond], link("Hook", "Reply")), "N8D209")
    assert found and '"Reply"' in found[0].message
    assert of(workflow([immediate, node("A", "noOp")], link("Hook", "A")), "N8D209") == []


def test_disabled_node_in_path() -> None:
    nodes = [trigger(), node("Mid", "set", disabled=True), node("End", "noOp")]
    assert of(workflow(nodes, link("Start", "Mid", "End")), "N8D210")
    assert of(workflow(nodes[:2], link("Start", "Mid")), "N8D210") == []  # disabled at the end: nothing after it


def test_pinned_data() -> None:
    found = of(workflow([trigger()], pinData={"Start": [{"json": {"a": 1}}, {"json": {"a": 2}}]}), "N8D211")
    assert found and found[0].node == "Start" and "2 pinned items" in found[0].message
    assert of(workflow([trigger()], pinData={}), "N8D211") == []


# --- reliability ---------------------------------------------------------------------------------


def test_no_error_workflow() -> None:
    sched = node("Every hour", "scheduleTrigger", {"rule": {"interval": [{"field": "hours"}]}}, 1.2)
    found = of(workflow([sched], active=True), "N8D301")
    assert found and found[0].severity == Severity.WARNING
    assert of(workflow([sched], active=False), "N8D301")[0].severity == Severity.INFO
    assert of(workflow([sched], active=True, settings={"errorWorkflow": "5"}), "N8D301") == []
    assert of(workflow([trigger()], active=True), "N8D301") == []  # manual only
    assert of(workflow([node("On error", "errorTrigger"), node("A", "noOp")], link("On error", "A"), active=True), "N8D301") == []


def test_http_timeout_and_retry() -> None:
    bare = node("HTTP", "httpRequest", {"url": "https://x.example.com"}, 4.2)
    assert of(run_http(bare), "N8D302") and of(run_http(bare), "N8D303")
    assert of(run_http(http()), "N8D302") == []
    retried = http(raw={"retryOnFail": True, "maxTries": 3})
    assert of(run_http(retried), "N8D303") == []
    handled = http(raw={"onError": "continueErrorOutput"})
    assert of(run_http(handled), "N8D303") == []
    post = of(run_http(http(method="POST")), "N8D303")
    assert post and "duplicates" in post[0].message and not post[0].fixable


def _loop(version: float = 3) -> dict[str, Any]:
    return node("Loop", "splitInBatches", {"batchSize": 10}, version)


def test_loop_not_closed() -> None:
    body = node("Body", "noOp")
    open_loop = merge(link("Start", "Loop"), link("Loop", "Body", output=1))
    assert of(workflow([trigger(), _loop(), body], open_loop), "N8D304")
    closed = merge(open_loop, link("Body", "Loop"))
    assert of(workflow([trigger(), _loop(), body], closed), "N8D304") == []
    done_only = merge(link("Start", "Loop"), link("Loop", "Body", output=0))
    assert "'loop' output is not connected" in of(workflow([trigger(), _loop(), body], done_only), "N8D304")[0].message
    assert of(workflow([trigger(), _loop(2), body], done_only), "N8D304") == []  # v2 has a single output


def test_unbounded_cycle() -> None:
    nodes = [trigger(), node("Fetch", "httpRequest", {"url": "https://x.example.com", "options": {"timeout": 1}}, 4.2), node("Save", "set")]
    cyc = merge(link("Start", "Fetch", "Save"), link("Save", "Fetch"))
    found = of(workflow(nodes, cyc), "N8D305")
    assert found and '"Fetch" -> "Save"' in found[0].message
    with_if = [*nodes, node("More?", "if", {"conditions": {"conditions": [{"leftValue": "={{ $json.next }}", "rightValue": ""}]}}, 2)]
    guarded = merge(link("Start", "Fetch", "Save", "More?"), link("More?", "Fetch"))
    assert of(workflow(with_if, guarded), "N8D305") == []
    self_loop = merge(link("Start", "Save"), link("Save", "Save"))
    assert of(workflow(nodes, self_loop), "N8D305")
    loop_ok = merge(link("Start", "Loop"), link("Loop", "Save", output=1), link("Save", "Loop"))
    assert of(workflow([trigger(), _loop(), node("Save", "set")], loop_ok), "N8D305") == []


def _sched(field: str, n: int | None = None, **extra: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {"field": field, **extra}
    if n is not None:
        rule[f"{field}Interval"] = n
    return node("Schedule", "scheduleTrigger", {"rule": {"interval": [rule]}}, 1.2)


def test_schedule_overlap() -> None:
    wait = node("Wait", "wait", {"amount": 10, "unit": "minutes"}, 1.1)
    found = of(workflow([_sched("minutes", 5), wait], link("Schedule", "Wait")), "N8D306")
    assert found and found[0].severity == Severity.WARNING and "5 minutes" in found[0].message
    assert of(workflow([_sched("minutes", 15), wait], link("Schedule", "Wait")), "N8D306") == []
    fast = of(workflow([_sched("seconds", 10), node("A", "noOp")], link("Schedule", "A")), "N8D306")
    assert fast and fast[0].severity == Severity.INFO
    assert of(workflow([_sched("hours", 1)]), "N8D306") == []
    cron = _sched("cronExpression", expression="*/2 * * * *")
    assert of(workflow([cron, wait], link("Schedule", "Wait")), "N8D306")
    legacy = node("Cron", "cron", {"triggerTimes": {"item": [{"mode": "everyMinute"}]}})
    assert of(workflow([legacy, wait], link("Cron", "Wait")), "N8D306")


def test_wait_without_limit() -> None:
    w = node("Wait", "wait", {"resume": "form", "incomingAuthentication": "basicAuth"}, 1.1)
    assert of(workflow([trigger(), w], link("Start", "Wait")), "N8D307")
    limited = node("Wait", "wait", {"resume": "webhook", "limitWaitTime": True, "incomingAuthentication": "basicAuth"}, 1.1)
    assert of(workflow([trigger(), limited], link("Start", "Wait")), "N8D307") == []


def test_unhandled_error_output() -> None:
    h = http(raw={"onError": "continueErrorOutput"})
    nodes = [trigger(), h, node("Log", "noOp")]
    assert of(workflow(nodes, merge(link("Start", "HTTP"), link("HTTP", "Log"))), "N8D308")
    assert of(workflow(nodes, merge(link("Start", "HTTP"), link("HTTP", "Log", output=1))), "N8D308") == []
    ifn = {**_if("={{ $json.a }}", "b"), "onError": "continueErrorOutput"}
    assert of(workflow([trigger(), ifn, node("Log", "noOp")], merge(link("Start", "IF"), link("IF", "Log", output=2))), "N8D308") == []


def test_execute_workflow_without_target() -> None:
    empty = node("Run", "executeWorkflow", {"workflowId": {"__rl": True, "value": "", "mode": "list"}}, 1.2)
    assert of(workflow([trigger(), empty], link("Start", "Run")), "N8D309")
    ok = node("Run", "executeWorkflow", {"workflowId": {"__rl": True, "value": "42", "mode": "id"}}, 1.2)
    assert of(workflow([trigger(), ok], link("Start", "Run")), "N8D309") == []
    legacy_ok = node("Run", "executeWorkflow", {"workflowId": "42"}, 1)
    assert of(workflow([trigger(), legacy_ok], link("Start", "Run")), "N8D309") == []
    inline = node("Run", "executeWorkflow", {"source": "parameter", "workflowJson": ""}, 1)
    assert of(workflow([trigger(), inline], link("Start", "Run")), "N8D309")


def test_failed_executions_not_saved() -> None:
    assert of(workflow([trigger()], settings={"saveDataErrorExecution": "none"}), "N8D310")
    assert of(workflow([trigger()], settings={"saveDataErrorExecution": "all"}), "N8D310") == []


# --- code ----------------------------------------------------------------------------------------


def test_deprecated_function_node() -> None:
    for t in ("function", "functionItem"):
        assert of(workflow([trigger(), node("F", t, {"functionCode": "return items;"})], link("Start", "F")), "N8D401")
    assert of(workflow([trigger(), node("C", "code", {"jsCode": "return [];"}, 2)], link("Start", "C")), "N8D401") == []


def _code(src: str, mode: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"jsCode": src}
    if mode:
        params["mode"] = mode
    return workflow([trigger(), node("C", "code", params, 2)], link("Start", "C"))


@pytest.mark.parametrize(
    "src",
    ["for (const item of items) { item.json.x = 1 }\nreturn items;", 'const a = $node["Start"].json;\nreturn [];', "const b = $items('Start');\nreturn b;"],
)
def test_legacy_code_syntax(src: str) -> None:
    assert of(_code(src), "N8D402")


@pytest.mark.parametrize(
    "src",
    [
        "const items = $input.all();\nreturn items;",
        "return $input.all().map(i => ({ json: { items: i.json.items } }));",
        "// items, $node['x']\nreturn $input.all();",
        "const s = 'items';\nreturn [{ json: { s } }];",
        "return $('Start').all();",
    ],
)
def test_modern_code_is_fine(src: str) -> None:
    assert of(_code(src), "N8D402") == []


def test_python_code_is_not_checked_as_js() -> None:
    wf = workflow([trigger(), node("C", "code", {"language": "python", "pythonCode": "return items"}, 2)], link("Start", "C"))
    assert of(wf, "N8D402") == [] and of(wf, "N8D403") == []


def test_code_mode_mismatch() -> None:
    assert of(_code("const all = $input.all();\nreturn all[0];", "runOnceForEachItem"), "N8D403")
    assert of(_code("return { json: { n: items.length } };", "runOnceForEachItem"), "N8D403")
    assert of(_code("return $input.item;", "runOnceForEachItem"), "N8D403") == []
    assert of(_code("return $input.all();"), "N8D403") == []
    assert of(_code("const first = $input.first();\nreturn [first];"), "N8D403") == []


def test_every_rule_is_covered_by_this_file() -> None:
    import inspect
    import re
    import sys

    source = inspect.getsource(sys.modules[__name__])
    covered = set(re.findall(r"N8D\d{3}", source))
    assert {r.id for r in RULES} <= covered


# --- edge cases across rules: Switch versions, Code parsing, defaults, odd parameter types ---------


def test_switch_v1_only_reports_outputs_rules_use() -> None:
    v1 = node("Switch", "switch", {"rules": {"rules": [{"output": 0}, {"output": 1}]}}, 1)
    both = merge(link("Start", "Switch"), link("Switch", "A", output=0), link("Switch", "A", output=1))
    assert of(workflow([trigger(), v1, node("A", "noOp")], both), "N8D204") == []
    one = merge(link("Start", "Switch"), link("Switch", "A", output=0))
    assert "output 1 not" in of(workflow([trigger(), v1, node("A", "noOp")], one), "N8D204")[0].message


def test_switch_v2_expression_mode() -> None:
    v2 = node("Switch", "switch", {"mode": "expression", "outputsAmount": 3, "output": "={{ 1 }}"}, 2)
    found = of(workflow([trigger(), v2, node("A", "noOp")], merge(link("Start", "Switch"), link("Switch", "A"))), "N8D204")
    assert found and "1, 2" in found[0].message


def test_template_literals_and_shorthand_items_are_not_code() -> None:
    each = "runOnceForEachItem"
    assert of(_code("return { json: { msg: `found ${n} items` } };", each), "N8D403") == []
    assert of(_code("const { items } = $json;\nreturn { json: { items } };", each), "N8D403") == []
    assert of(_code("// was $input.all()\nreturn $input.item;", each), "N8D403") == []  # n8n skips comment lines
    assert of(_code("return $input.item; // not $input.all()", each), "N8D403")  # but not trailing comments


def test_code_regex_is_linear_on_backslashes() -> None:
    import time

    start = time.monotonic()
    _ = of(_code("// don't: " + "\\" * 5000, "runOnceForEachItem"), "N8D403")
    assert time.monotonic() - start < 2


def test_imap_email_trigger_is_a_trigger() -> None:
    imap = node("Mail", "emailReadImap", {}, 2)
    wf = workflow([imap, node("A", "noOp")], link("Mail", "A"), active=True)
    from .conftest import findings

    ids = {f.rule.id for f in findings(wf)}
    assert "N8D202" not in ids and "N8D301" in ids


def test_schedule_and_wait_defaults() -> None:
    wait = node("Wait", "wait", {"amount": 2, "unit": "minutes"}, 1.1)
    assert of(workflow([_sched("minutes"), wait], link("Schedule", "Wait")), "N8D306") == []  # default is every 5 minutes
    fast = of(workflow([_sched("seconds"), node("A", "noOp")], link("Schedule", "A")), "N8D306")
    assert fast and "30 seconds" in fast[0].message
    default_wait = node("Wait", "wait", {}, 1.1)
    assert of(workflow([_sched("seconds", 3), default_wait], link("Schedule", "Wait")), "N8D306")[0].severity == Severity.WARNING


def test_respond_after_wait_is_for_the_resume_call() -> None:
    hook = node("Hook", "webhook", {"path": "x", "authentication": "headerAuth"}, 2, credentials={"httpHeaderAuth": {"id": "1"}})
    wait = node("Approve", "wait", {"resume": "webhook", "responseMode": "responseNode", "incomingAuthentication": "basicAuth"}, 1.1)
    reply = node("Reply", "respondToWebhook", {}, 1.1)
    assert of(workflow([hook, wait, reply], link("Hook", "Approve", "Reply")), "N8D209") == []
    streaming = {**hook, "parameters": {"path": "x", "responseMode": "streaming", "authentication": "headerAuth"}}
    assert of(workflow([streaming, node("A", "noOp")], link("Hook", "A")), "N8D209") == []


def test_secrets_in_expression_bodies_and_basic_auth() -> None:
    body = '={"api_key": "q8w7e6r5t4y3u2i1", "q": "{{ $json.q }}"}'
    assert of(run_http(http(sendBody=True, specifyBody="json", jsonBody=body)), "N8D101")
    basic = http(sendHeaders=True, headerParameters={"parameters": [{"name": "Authorization", "value": "Basic dXNlcjpzM2NyZXQxMjM="}]})
    found = of(run_http(basic), "N8D101")
    assert found and "dXNlcjpz" not in found[0].message


def test_no_suggestion_for_numbered_copies() -> None:
    s = node("Set", "set", {"x": "={{ $('HTTP Request').item.json }}"}, 3.4)
    found = of(workflow([trigger(), node("HTTP Request1", "noOp"), s], link("Start", "HTTP Request1", "Set")), "N8D207")
    assert found and '"HTTP Request1"' in (found[0].fix_hint or "") and not found[0].fixable and not found[0].autofix


def test_ai_agent_error_output() -> None:
    agent = node("Agent", "@n8n/n8n-nodes-langchain.agent", {}, 1.7, onError="continueErrorOutput")
    wf = workflow([trigger(), agent, node("A", "noOp")], merge(link("Start", "Agent"), link("Agent", "A")))
    assert of(wf, "N8D308")


def test_cycles_through_split_out_can_end() -> None:
    nodes = [trigger(), node("Fetch", "noOp"), node("Split", "splitOut"), node("Save", "set")]
    cyc = merge(link("Start", "Fetch", "Split", "Save"), link("Save", "Fetch"))
    assert of(workflow(nodes, cyc), "N8D305") == []


def test_credentials_edge_cases() -> None:
    oauth_hook = node("Hook", "webhook", {"path": "x", "authentication": "n8nOAuth2"}, 2)
    assert of(workflow([oauth_hook]), "N8D208") == []
    old_http = node("H", "httpRequest", {"url": "https://x.example.com", "authentication": "headerAuth", "options": {"timeout": 1}}, 2)
    assert of(run_http(old_http), "N8D208")


def test_odd_parameter_types_do_not_crash() -> None:
    wait = node("Wait", "wait", {"unit": ["seconds"], "amount": "x"}, 1.1)
    sched = node("S", "scheduleTrigger", {"rule": {"interval": [{"field": ["minutes"]}, "x", {"field": "minutes", "minutesInterval": "abc"}]}}, 1.2)
    sw = node("Sw", "switch", {"rules": {"values": "bad"}, "options": "bad"}, 3)
    weird = {"name": "W", "type": "n8n-nodes-base.httpRequest", "typeVersion": "x", "parameters": "bad"}
    wf = workflow([sched, wait, sw, weird], link("S", "Wait", "Sw", "W"))
    from .conftest import findings

    findings(wf)


# --- expressions, Respond to Webhook paths, AI nodes, loops and URL secrets -------------------------


def test_expression_without_prefix() -> None:
    s = node("Set", "set", {"assignments": {"assignments": [{"name": "email", "value": "{{ $json.body.email }}"}]}}, 3.4)
    found = of(workflow([trigger(), s], link("Start", "Set")), "N8D212")
    assert found and found[0].parameter == "assignments.assignments[0].value" and found[0].fixable
    ok = node("Set", "set", {"a": "={{ $json.x }}", "tpl": "Hello {{name}}", "code": "{{ x }}"}, 3.4)
    assert of(workflow([trigger(), ok], link("Start", "Set")), "N8D212") == []
    code = node("Code", "code", {"jsCode": "const t = '{{ $json.x }}';"}, 2)
    assert of(workflow([trigger(), code], link("Start", "Code")), "N8D212") == []


@pytest.mark.parametrize(
    ("kind", "version", "params", "flagged"),
    [
        ("postgres", 2.5, {"operation": "executeQuery", "query": "SELECT * FROM t WHERE id = {{ $json.id }}"}, False),
        ("mySql", 2.4, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("microsoftSql", 1.1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("snowflake", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("googleBigQuery", 2.1, {"operation": "executeQuery", "sqlQuery": "SELECT {{ $json.id }}"}, False),
        ("merge", 3.1, {"mode": "combineBySql", "query": "SELECT * FROM input1 WHERE id = {{ $json.id }}"}, False),
        ("html", 1.2, {"operation": "generateHtmlTemplate", "html": "<p>{{ $json.name }}</p>"}, False),
        ("oracleDatabase", 1, {"operation": "execute", "query": "SELECT {{ $json.id }} FROM dual"}, False),
        ("postgres", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("mySql", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("questDb", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("timescaleDb", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        ("crateDb", 1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, False),
        # the Set node resolves its JSON only as an expression (with the leading =)
        ("set", 3.4, {"mode": "raw", "jsonOutput": '{"id": "{{ $json.id }}"}'}, True),
        ("googleBigQuery", 2.1, {"operation": "executeQuery", "query": "SELECT {{ $json.id }}"}, True),
        ("oracleDb", 1, {"operation": "execute", "query": "SELECT {{ $json.id }} FROM dual"}, True),  # no such node type
        # the same text elsewhere is still sent literally
        ("postgres", 2.5, {"operation": "insert", "table": {"value": "{{ $json.table }}"}}, True),
        ("merge", 3.1, {"mode": "combine", "query": "{{ $json.id }}"}, True),
        ("set", 3.4, {"mode": "raw", "jsonOutput": "{}", "options": {"note": "{{ $json.id }}"}}, True),
        ("html", 1.2, {"operation": "extractHtmlContent", "dataPropertyName": "{{ $json.field }}"}, True),
    ],
)
def test_expression_without_prefix_in_fields_n8n_resolves(kind: str, version: float, params: dict[str, Any], flagged: bool) -> None:
    wf = workflow([trigger(), node("N", kind, params, version)], link("Start", "N"))
    assert bool(of(wf, "N8D212")) is flagged


def test_respond_on_every_path() -> None:
    params = {"path": "x", "responseMode": "responseNode", "authentication": "headerAuth"}
    hook = node("Hook", "webhook", params, 2, credentials={"httpHeaderAuth": {"id": "1"}})
    check = _if("={{ $json.ok }}", "yes")
    reply = node("Reply", "respondToWebhook", {}, 1.1)
    partial = merge(link("Hook", "IF"), link("IF", "Reply", output=0))
    found = of(workflow([hook, check, reply], partial), "N8D209")
    assert found and found[0].severity == Severity.WARNING and '"IF" [false]' in found[0].message
    both = merge(partial, link("IF", "Reply", output=1))
    assert of(workflow([hook, check, reply], both), "N8D209") == []
    stop = node("Fail", "stopAndError", {}, 1)
    with_stop = merge(partial, link("IF", "Fail", output=1))
    assert of(workflow([hook, check, reply, stop], with_stop), "N8D209") == []
    missing = of(workflow([hook, node("A", "noOp")], link("Hook", "A")), "N8D209")
    assert missing[0].severity == Severity.ERROR and missing[0].fix_hint and "Add a Respond" in missing[0].fix_hint


def test_public_chat_without_auth() -> None:
    chat = node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", {"public": True}, 1.1)
    assert of(workflow([chat]), "N8D102")
    private = node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", {"public": False}, 1.1)
    assert of(workflow([private]), "N8D102") == []
    authed = node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", {"public": True, "authentication": "n8nUserAuth"}, 1.1)
    assert of(workflow([authed]), "N8D102") == []


def test_ai_sub_node_wired_with_main_gets_a_hint() -> None:
    agent = node("Agent", "@n8n/n8n-nodes-langchain.agent", {}, 1.7)
    tool = node("Escalate", "@n8n/n8n-nodes-langchain.toolHttpRequest", {}, 1.1)
    wf = workflow([trigger(), agent, tool], merge(link("Start", "Agent"), link("Escalate", "Agent")))
    found = of(wf, "N8D201")
    assert found and found[0].fix_hint and "ai_tool" in found[0].fix_hint and "main connection" in found[0].fix_hint


def test_swapped_loop_outputs() -> None:
    body = node("Body", "noOp")
    swapped = merge(link("Start", "Loop"), link("Loop", "Body", output=0), link("Body", "Loop"), link("Loop", "After", output=1))
    found = of(workflow([trigger(), _loop(), body, node("After", "noOp")], swapped), "N8D304")
    assert found and "swapped" in found[0].message


def test_tool_workflow_without_target_and_empty_workflow() -> None:
    tool = node("Lookup", "@n8n/n8n-nodes-langchain.toolWorkflow", {"workflowId": {"__rl": True, "value": ""}}, 2)
    agent = node("Agent", "@n8n/n8n-nodes-langchain.agent", {}, 1.7)
    conns = merge(link("Start", "Agent"), {"Lookup": {"ai_tool": [[{"node": "Agent", "type": "ai_tool", "index": 0}]]}})
    assert of(workflow([trigger(), agent, tool], conns), "N8D309")
    assert of(workflow([]), "N8D202")[0].message == "the workflow has no nodes"


def test_same_type_hint() -> None:
    s = node("Set", "set", {"x": "={{ $('Webhook').item.json }}"}, 3.4)
    hook = node("Lead Webhook", "webhook", {"path": "x", "authentication": "headerAuth"}, 2)
    found = of(workflow([hook, s], link("Lead Webhook", "Set")), "N8D207")
    assert found and found[0].fix_hint and '"Lead Webhook"' in found[0].fix_hint and not found[0].fixable


def test_message_for_braces_without_equals_in_if() -> None:
    found = of(workflow([trigger(), _if("{{ $json.a }}", "b")], link("Start", "IF")), "N8D203")
    assert "no leading =" in found[0].message


@pytest.mark.parametrize(
    "src",
    [
        "let total = 0, items = [];\nreturn { json: { n: items.length } };",
        "const n = [1].reduce((acc, items) => acc + items, 0);\nreturn { json: { n } };",
        "const { items = [] } = $input.item.json;\nreturn { json: { n: items.length } };",
    ],
)
def test_code_that_declares_items_is_fine(src: str) -> None:
    assert of(_code(src, "runOnceForEachItem"), "N8D403") == []


def test_guardrails_outputs_are_not_guessed() -> None:
    g = node("Guard", "@n8n/n8n-nodes-langchain.guardrails", {"operation": "classify"}, 1, onError="continueErrorOutput")
    wf = workflow([trigger(), g, node("A", "noOp")], merge(link("Start", "Guard"), link("Guard", "A", output=2)))
    assert of(wf, "N8D308") == []


def test_code_assignments_that_are_not_secrets() -> None:
    src = (
        "const tokenUrl = 'https://auth.example.com/oauth/token';\n"
        "const secretHeader = 'x-hub-signature-256';\n"
        "const passwordField = 'password_hash';\n"
        "const tokenType = 'access_token';\n"
        "const apiKeyHeader = 'X-Api-Key-Header';\nreturn [];"
    )
    assert of(_code(src), "N8D101") == []
    assert of(_code("const BOT_TOKEN = 'a8f3k2l9q7w1e5r4t6y0';\nreturn [];"), "N8D101")


def test_idempotency_key_header_is_not_a_secret() -> None:
    h = http(sendHeaders=True, headerParameters={"parameters": [{"name": "X-Idempotency-Key", "value": "order-2026-11-04-0001"}]})
    assert of(run_http(h), "N8D101") == []


def test_swapped_loop_outputs_with_loop_output_empty() -> None:
    body = node("Body", "noOp")
    done_loops_back = merge(link("Start", "Loop"), link("Loop", "Body", output=0), link("Body", "Loop"))
    found = of(workflow([trigger(), _loop(), body], done_loops_back), "N8D304")
    assert len(found) == 1 and "swapped" in found[0].message and "is not connected" in found[0].message


def test_mcp_trigger_without_auth() -> None:
    open_mcp = node("MCP", "@n8n/n8n-nodes-langchain.mcpTrigger", {"path": "tools"}, 2)
    found = of(workflow([open_mcp]), "N8D102")
    assert found and found[0].message.startswith("MCP server /tools has no authentication")
    for auth in ("bearerAuth", "headerAuth", "n8nOAuth2"):
        authed = node("MCP", "@n8n/n8n-nodes-langchain.mcpTrigger", {"path": "tools", "authentication": auth}, 2)
        assert of(workflow([authed]), "N8D102") == []


@pytest.mark.parametrize(
    "url",
    ["https://api.example.com/v1?api_key=Q1w2E3r4T5y6U7i8O9p0", "https://api.example.com/v1?format=json&access_token=Q1w2E3r4T5y6U7i8O9p0"],
)
def test_secret_in_url_query_string(url: str) -> None:
    h = node("H", "httpRequest", {"url": url, "options": {}}, 4.2)
    found = of(workflow([trigger(), h], link("Start", "H")), "N8D101")
    assert len(found) == 1 and "query string" in found[0].message and "Q1w2E3r4T5y6U7i8O9p0" not in found[0].message


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/v1?api_key={{ $env.KEY }}",
        "https://api.example.com/v1?token=YOUR_TOKEN",
        "https://api.example.com/v1?page=2&keyword=abcdefgh123",
    ],
)
def test_url_query_without_literal_secret(url: str) -> None:
    h = node("H", "httpRequest", {"url": url, "options": {}}, 4.2)
    assert of(workflow([trigger(), h], link("Start", "H")), "N8D101") == []


@pytest.mark.parametrize(
    "src",
    [
        "const re = /items/g;\nreturn $input.all().filter(i => re.test(i.json.name));",
        "return $input.all().filter(i => /^items?$/i.test(i.json.kind));",
        "const half = $input.all().length / 2; const x = half / 1;\nreturn $input.all();",
    ],
)
def test_regex_literals_are_not_code(src: str) -> None:
    assert of(_code(src), "N8D402") == []


def test_items_after_a_division_is_still_found() -> None:
    assert of(_code("const n = items.length / 2;\nreturn items;"), "N8D402")


def test_webhook_sharing_its_name_with_a_form_still_finds_its_respond_node() -> None:
    # n8n does not allow duplicate names, but hand-edited exports have them; graph rules must not take one node for another
    form = node("N5", "form", {}, 1)
    hook = node("N5", "webhook", {"path": "p", "responseMode": "responseNode"}, 2)
    data = workflow([form, hook, node("Reply", "respondToWebhook", {}, 1.1)], link("N5", "Reply"))
    assert not of(data, "N8D209")
    lone = workflow([node("N5", "form", {}, 1), node("N5", "webhook", {"path": "p", "responseMode": "responseNode"}, 2)])
    assert [f.node for f in of(lone, "N8D209")] == ["N5"]


def test_schedule_sharing_its_name_with_a_wait_is_not_followed_by_it() -> None:
    sched = node("N0", "scheduleTrigger", {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}}, 1.2)
    wait = node("N0", "wait", {"amount": 3600, "unit": "seconds"}, 1.1)
    data = workflow([sched, wait, node("Next", "set", {}, 3.4)], link("N0", "Next"))
    assert not of(data, "N8D306")
    after = workflow([sched, wait, node("Pause", "wait", {"amount": 900, "unit": "seconds"}, 1.1)], link("N0", "Pause"))
    assert [f.message for f in of(after, "N8D306")] == ['runs every 5 minutes but "Pause" alone waits 15 minutes, so runs always overlap']


def test_cycles_and_loops_with_duplicate_names() -> None:
    a, b = node("A", "set", {}, 3.4), node("A", "set", {}, 3.4)
    cyc = workflow([trigger(), a, b], merge(link("Start", "A"), link("A", "A")))
    assert [f.message for f in of(cyc, "N8D305")] == ['loop through "A" has no exit condition']
    loop = node("Batch", "splitInBatches", {}, 3)
    twin = node("Batch", "set", {}, 3.4)
    closed = workflow(
        [trigger(), loop, twin, node("Work", "set", {}, 3.4)], merge(link("Start", "Batch"), link("Batch", "Work", output=1), link("Work", "Batch"))
    )
    assert not of(closed, "N8D304")


def test_entries_of_the_nodes_array_that_are_not_nodes() -> None:
    data = workflow([trigger(), None, "x", 3, [], node("A", "noOp")], link("Start", "A"))  # type: ignore[list-item]
    found = of(data, "N8D213")
    assert [f.message for f in found] == [
        "nodes[1] is null, not a node object",
        "nodes[2] is a string, not a node object",
        "nodes[3] is a number, not a node object",
        "nodes[4] is an array, not a node object",
    ]
    assert of(data, "N8D201") == []  # "A" is still found at its position in the array


def test_entries_that_are_not_nodes_have_their_line_numbers() -> None:
    text = json.dumps(workflow([trigger(), None, node("A", "noOp")], link("Start", "A")), indent=2)  # type: ignore[list-item]
    found = [f for f in run(parse_text(text, "x")) if f.rule.id == "N8D213"]
    assert len(found) == 1 and text.splitlines()[found[0].line - 1].strip() == "null,"


@pytest.mark.parametrize(
    ("params", "type_", "version", "message"),
    [
        ({"amount": 1e308, "unit": "weeks"}, "wait", 1.1, "the amount is too large to be a time"),
        ({"amount": float("inf"), "unit": "seconds"}, "wait", 1.1, "the amount is inf, not a finite number"),
        ({"amount": -5, "unit": "seconds"}, "wait", 1.1, "the amount is negative"),
        ({"rule": {"interval": [{"field": "minutes", "minutesInterval": "²"}]}}, "scheduleTrigger", 1.2, 'the interval is "²", not a whole number'),
        ({"rule": {"interval": [{"field": "hours", "hoursInterval": 0}]}}, "scheduleTrigger", 1.2, "the interval is 0, not a positive number"),
        ({"rule": {"interval": [{"field": "hours", "hoursInterval": "5" * 5000}]}}, "scheduleTrigger", 1.2, "text that is not a whole number"),
        ({"rule": {"interval": [{"field": "cronExpression", "expression": "*/" + "7" * 5000 + " * * * *"}]}}, "scheduleTrigger", 1.2, "not a whole number"),
        ({"rule": {"interval": [{"field": "cronExpression", "expression": "*/0 * * * *"}]}}, "scheduleTrigger", 1.2, "has the step /0"),
        ({"triggerTimes": {"item": [{"mode": "everyX", "value": 2.5, "unit": "minutes"}]}}, "cron", 1, "the interval is not a whole number"),
        ({"interval": float("nan"), "unit": "seconds"}, "interval", 1, "the interval is nan, not a finite number"),
    ],
)
def test_invalid_time_values_are_reported_not_raised(params: dict[str, Any], type_: str, version: float, message: str) -> None:
    data = workflow([trigger(), node("T", type_, params, version)], link("Start", "T"))
    found = of(data, "N8D214")
    assert len(found) == 1 and message in found[0].message and found[0].severity.label == "warning"
    run([load(data)])  # every other rule copes too


def test_valid_time_values_are_not_reported() -> None:
    sched = node("S", "scheduleTrigger", {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}, {"field": "hours", "hoursInterval": "2"}]}}, 1.2)
    cron = node("C", "cron", {"triggerTimes": {"item": [{"mode": "custom", "cronExpression": "0 */15 * * * *"}, {"mode": "everyX", "value": "={{ 3 }}"}]}}, 1)
    wait = node("W", "wait", {"amount": 2.5, "unit": "minutes"}, 1.1)
    assert not of(workflow([sched, cron, wait], link("S", "W")), "N8D214")


def test_code_over_the_analysed_length_is_reported_by_n8d001() -> None:
    from n8n_doctor.limits import Limits

    code = '$("A").item;\n' + "x" * 5000 + '\n$("Missing").item;'
    data = workflow([trigger(), node("A", "noOp"), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"))
    found = run(from_data(data, "x", limits=Limits(max_code_chars=2048)))
    assert [f.message for f in found if f.rule.id == "N8D001"] == [
        "jsCode is 5,032 characters long: only its first 2 KB were checked for node references and legacy syntax"
    ]
    assert not [f for f in found if f.rule.id == "N8D207"]  # the reference past the cut was not read
    assert [f.rule.id for f in of(data, "N8D207")] == ["N8D207"]  # with the default limit it is


@pytest.mark.parametrize(
    ("code", "flagged"),
    [
        ("const html = \"<script>$('#go').click()</script>\";\nreturn [{json: {html}}];", False),
        ("const html = '<script>$(\"Missing\").hide()</script>';\nreturn [];", False),
        ("const page = `<button onclick=\"$('Missing').show()\">Go</button>`;\nreturn [];", False),
        ("const r = /\\$\\('Missing'\\)/;\nreturn [];", False),
        ("const page = `<p>${$('Missing').first().json.name}</p>`;\nreturn [];", True),
        ("const x = $('Missing').first().json;\nreturn [];", True),
        ("const msg = 'hi'; const x = $('Missing').all();\nreturn [];", True),
        # outside a string literal $() is n8n's, whatever the name looks like
        ("const x = $('.item').text();\nreturn [];", True),
        ("const x = $('ul li.active');\nreturn [];", True),
        # inside a template literal's ${ } a selector-shaped name is taken for jQuery in generated HTML
        ("const page = `<p>${$('#go').text()}</p>`;\nreturn [];", False),
        ("const page = `<p>${$('ul li.active').text()}</p>`;\nreturn [];", False),
        ("const page = `<p>${$('[PROD] Get Lead').first().json.x}</p>`;\nreturn [];", True),
    ],
)
def test_unknown_reference_in_code_strings(code: str, flagged: bool) -> None:
    wf = workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code"))
    assert bool(of(wf, "N8D207")) is flagged


def test_unknown_reference_css_selector_in_expression() -> None:
    params = {"assignments": {"assignments": [{"name": "a", "value": "={{ $('#go').item.json.x }}"}, {"name": "b", "value": "={{ $('Gone').item.json.x }}"}]}}
    found = of(workflow([trigger(), node("Set", "set", params, 3.4)], link("Start", "Set")), "N8D207")
    assert len(found) == 2  # an expression's $() always names a node


@pytest.mark.parametrize("name", ["[PROD] Get Lead", ".env loader", "#1 Fetch"])
def test_unknown_reference_with_selector_characters_is_reported(name: str) -> None:
    existing = node(name + " X", "noOp")
    params = {"assignments": {"assignments": [{"name": "url", "value": f"={{{{ $('{name}').item.json.url }}}}"}]}}
    data = workflow([trigger(), existing, node("Set", "set", params, 3.4)], link("Start", name + " X", "Set"))
    assert len(of(data, "N8D207")) == 1
    html = node("Page", "html", {"operation": "generateHtmlTemplate", "html": f"=<p>{{{{ $('{name}').item.json.url }}}}</p>"}, 1.2)
    assert len(of(workflow([trigger(), existing, html], link("Start", name + " X", "Page")), "N8D207")) == 1
    code = node("Code", "code", {"jsCode": f"const page = `<p>${{$('{name}').first().json.url}}</p>`;\nreturn [];"}, 2)
    assert len(of(workflow([trigger(), existing, code], link("Start", name + " X", "Code")), "N8D207")) == 1


def test_reference_inside_the_html_template_braces_is_an_expression() -> None:
    # n8n evaluates every {{ }} of the template (getResolvables): $('table') there names a node, it is not jQuery
    for value in ("=<p>{{ $('#go').text() }}</p>", "<p>{{ $('table').item.json.x }}</p>"):
        html = node("Page", "html", {"operation": "generateHtmlTemplate", "html": value}, 1.2)
        assert len(of(workflow([trigger(), html], link("Start", "Page")), "N8D207")) == 1
    script = node("Page", "html", {"operation": "generateHtmlTemplate", "html": "<script>$('table').hide()</script>"}, 1.2)
    assert of(workflow([trigger(), script], link("Start", "Page")), "N8D207") == []


# --- B4: N8D207 in fields n8n resolves without the = ------------------------------------------------------------


def test_unknown_reference_in_self_resolved_fields() -> None:

    data = json.loads((REGRESSION_FIXTURES / "t4.json").read_text())
    found = {f.node for f in of(data, "N8D207")}
    assert {"PG", "HTML"} <= found
    old = node("PG", "postgres", {"operation": "executeQuery", "query": "SELECT {{ $('Gone').item.json.id }}"}, 1)
    assert of(workflow([trigger(), old], link("Start", "PG")), "N8D207")
    merge_sql = node("M", "merge", {"mode": "combineBySql", "query": "SELECT * FROM input1 WHERE x = '{{ $('Gone').item.json.x }}'"}, 3)
    assert of(workflow([trigger(), merge_sql], link("Start", "M")), "N8D207")
    not_sql = node("M", "merge", {"mode": "append", "query": "{{ $('Gone').item.json.x }}"}, 3)
    assert of(workflow([trigger(), not_sql], link("Start", "M")), "N8D207") == []


def test_unknown_reference_in_form_html_fields() -> None:
    field = {"fieldType": "html", "html": "<p>{{ $('Gone').item.json.x }}</p>"}
    other = {"fieldType": "text", "fieldLabel": "x", "html": "<p>{{ $('Gone2').item.json.x }}</p>"}
    form = node("Form", "form", {"formFields": {"values": [field, other]}}, 2.3)
    found = of(workflow([trigger(), form], link("Start", "Form")), "N8D207")
    assert len(found) == 1 and "Gone2" not in found[0].message
    assert not [f for f in findings(workflow([trigger(), form], link("Start", "Form"))) if f.rule.id == "N8D212" and "values[0]" in f.message]


def test_fix_renames_references_in_self_resolved_fields() -> None:
    from n8n_doctor.fix import fix_workflow

    pg = node("PG", "postgres", {"operation": "executeQuery", "query": "SELECT {{ $('fetch lead').item.json.id }}"}, 2.5)
    data = workflow([trigger(), node("Fetch lead", "noOp"), pg], link("Start", "Fetch lead", "PG"))
    result = fix_workflow(load(data))
    assert result.fixed["nodes"][2]["parameters"]["query"] == "SELECT {{ $('Fetch lead').item.json.id }}"  # no = added


def _regression(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((REGRESSION_FIXTURES / name).read_text())
    return data


@pytest.mark.parametrize(
    "name",
    [
        "langchain_code_template_literal.json",  # LangChain Code: code.execute.code
        "langchain_code_reference_and_template.json",
        "sort_code_template_literal.json",  # Sort node: code
        "tool_code_python_template.json",  # LangChain Code Tool: pythonCode
    ],
)
def test_code_fields_never_get_the_expression_prefix(name: str) -> None:
    data = _regression(name)
    assert not of(data, "N8D212")
    assert not fix_workflow(load(data)).changes


@pytest.mark.parametrize(
    ("name", "path"),
    [
        ("langchain_code_reference_and_template.json", "code.execute.code"),
        ("sort_code_reference.json", "code"),
        ("python_code_reference.json", "pythonCode"),  # _('Ghost') in Python
    ],
)
def test_references_in_code_fields_are_checked(name: str, path: str) -> None:
    found = of(_regression(name), "N8D207")
    assert [(f.parameter, "Ghost" in f.message) for f in found] == [(path, True)]


def test_langchain_supply_data_code_is_code() -> None:
    code = "const apiKey = 'Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Se';\nconst m = $('Fech data').first();\nreturn `{{ $json.x }}`;"
    lc = node("LC", "@n8n/n8n-nodes-langchain.code", {"code": {"supplyData": {"code": code}}})
    data = workflow([trigger(), node("Fetch data", "noOp"), lc], link("Start", "LC"))
    assert [f.parameter for f in of(data, "N8D101")] == ["code.supplyData.code"]
    assert not of(data, "N8D212")
    result = fix_workflow(load(data))
    assert result.changes == ['N8D207 "LC" code.supplyData.code: "Fech data" -> "Fetch data"']
    assert "$('Fetch data')" in result.fixed["nodes"][2]["parameters"]["code"]["supplyData"]["code"]


def test_python_code_secrets_and_references() -> None:
    assert [f.parameter for f in of(_regression("python_code_secret.json"), "N8D101")] == ["pythonCode"]
    code = "# _('Old comment')\nrows = _('Fech data').all()\ntext = \"_('In a string')\"\napi_key = 'Zq7Lm2Xp9Rt4Vw8Ny3Kb6Hc1Jd5Fg0Se'\nreturn rows"
    py = node("Py", "code", {"language": "python", "pythonCode": code}, 2)
    data = workflow([trigger(), node("Fetch data", "noOp"), py], link("Start", "Py"))
    assert ["Fech data" in f.message for f in of(data, "N8D207")] == [True]
    assert [f.parameter for f in of(data, "N8D101")] == ["pythonCode"]
    fixed = fix_workflow(load(data)).fixed["nodes"][2]["parameters"]["pythonCode"]
    assert "rows = _('Fetch data').all()" in fixed and "_('Old comment')" in fixed


@pytest.mark.parametrize("name", ["postgres_query_replacement.json", "ldap_custom_filter.json"])
def test_fields_the_node_resolves_itself(name: str) -> None:
    data = _regression(name)
    assert not of(data, "N8D212")  # n8n resolves {{ }} there without the =
    assert ["Ghost" in f.message for f in of(data, "N8D207")] == [True]  # so their references are checked


def test_ldap_search_fields_resolve_themselves() -> None:
    params = {"operation": "search", "searchFor": "{{ $json.cls }}", "attribute": "uid", "searchText": "{{ $json.uid }}"}
    data = workflow([trigger(), node("LDAP", "ldap", params)], link("Start", "LDAP"))
    assert not of(data, "N8D212")
    old = node("PG", "postgres", {"operation": "executeQuery", "query": "select $1", "options": {"queryReplacement": "{{ $json.id }}"}}, 1)
    assert of(workflow([trigger(), old], link("Start", "PG")), "N8D212")  # Postgres v1 has no query replacement


def test_expression_with_braces_inside_needs_the_prefix() -> None:
    found = of(_regression("expression_with_braces_inside.json"), "N8D212")
    assert [f.parameter for f in found] == ["assignments.assignments[0].value"]
    assert not of(workflow([trigger(), node("S", "set", {"value": "{ {a: 1} }"})], link("Start", "S")), "N8D212")


def test_execution_order_v0_runs_the_parents_of_a_merge() -> None:
    data = _regression("execution_order_v0_merge.json")  # no executionOrder: v0, which runs "Static" for the Merge
    assert not of(data, "N8D201")
    data["settings"] = {"executionOrder": "v1"}
    assert [f.node for f in of(data, "N8D201")] == ["Static"]


@pytest.mark.parametrize(
    ("type_", "version", "params"),
    [
        ("postgresTool", 2.6, {"operation": "executeQuery", "query": "SELECT $1", "options": {"queryReplacement": "{{ $('Lookup').item.json.id }}"}}),
        ("mySqlTool", 2.4, {"operation": "executeQuery", "query": "SELECT * FROM t WHERE id = {{ $('Lookup').item.json.id }}"}),
        ("microsoftSqlTool", 1.1, {"operation": "executeQuery", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("snowflakeTool", 1, {"operation": "executeQuery", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("googleBigQueryTool", 2.1, {"operation": "executeQuery", "sqlQuery": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("oracleDatabaseTool", 1, {"operation": "execute", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("questDbTool", 1, {"operation": "executeQuery", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("timescaleDbTool", 1, {"operation": "executeQuery", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("crateDbTool", 1, {"operation": "executeQuery", "query": "SELECT {{ $('Lookup').item.json.id }}"}),
        ("ldapTool", 1, {"operation": "search", "searchFor": "(cn={{ $('Lookup').item.json.id }})"}),
    ],
)
def test_tool_variants_resolve_their_fields_like_the_node(type_: str, version: float, params: dict[str, Any]) -> None:
    tool = node("Tool", type_, params, version)
    ok = workflow([trigger(), node("Lookup", "noOp"), tool], link("Start", "Lookup"))
    assert of(ok, "N8D212") == [] and of(ok, "N8D207") == []
    renamed = workflow([trigger(), node("Lookup2", "noOp"), tool], link("Start", "Lookup2"))
    assert [f.rule.id for f in of(renamed, "N8D207")] == ["N8D207"]


@pytest.mark.parametrize(
    ("written", "language"),
    [
        (r"$('\x41PI')", "js"),
        (r"$('API')", "js"),
        (r"$('\u{41}PI')", "js"),
        (
            r"$('A\
PI')",
            "js",
        ),
        (r"_('\x41PI')", "python"),
        (r"_('API')", "python"),
        (r"_('\U00000041PI')", "python"),
        (r"_('\101PI')", "python"),
        (r"_('\N{LATIN CAPITAL LETTER A}PI')", "python"),
    ],
)
def test_string_escapes_in_references_are_decoded(written: str, language: str) -> None:
    params = {"jsCode": f"return {written}.all();"} if language == "js" else {"language": "python", "pythonCode": f"return {written}.all()"}
    data = workflow([trigger(), node("API", "noOp"), node("Code", "code", params, 2)], link("Start", "API", "Code"))
    assert of(data, "N8D207") == []
    missing = workflow([trigger(), node("API2", "noOp"), node("Code", "code", params, 2)], link("Start", "API2", "Code"))
    assert ['references node "API"' in f.message for f in of(missing, "N8D207")] == [True]


@pytest.mark.parametrize("type_", ["code", "@n8n/n8n-nodes-langchain.toolCode"])
@pytest.mark.parametrize("language", ["python", "pythonNative"])
def test_code_of_the_language_not_selected_is_ignored(type_: str, language: str) -> None:
    py = node("Code", type_, {"language": language, "pythonCode": "return _('API').all()", "jsCode": "return $('Gone').all();"}, 2)
    js = node("Code", type_, {"jsCode": "return $('API').all();", "pythonCode": "return _('Gone').all()"}, 2)
    for code in (py, js):
        data = workflow([trigger(), node("API", "noOp"), code], link("Start", "API", "Code"))
        assert of(data, "N8D207") == []
        assert fix_workflow(load(data)).changes == []
    leftover = node("Code", type_, {"language": language, "pythonCode": "return []", "jsCode": "const apiKey = 'Zq7Wv2Lp9Rk4Tn8Ym3Xc';"}, 2)
    assert of(workflow([trigger(), leftover], link("Start", "Code")), "N8D101")  # a secret is in the export all the same


@pytest.mark.parametrize(
    "code",
    ["const s = `${$('form').first().json.a}`;", "const s = `a ${ $('form').first().json.a } b`;"],
)
def test_reference_inside_template_substitution_is_an_n8n_reference(code: str) -> None:
    found = of(workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code")), "N8D207")
    assert len(found) == 1 and "form" in found[0].message


@pytest.mark.parametrize(
    "code",
    [
        "const s = `<script>$('form').submit()</script>`;",
    ],
)
def test_jquery_in_the_text_of_a_template_is_not_a_reference(code: str) -> None:
    assert of(workflow([trigger(), node("Code", "code", {"jsCode": code}, 2)], link("Start", "Code")), "N8D207") == []


def test_mixed_template_and_expression_is_reported_but_not_fixable() -> None:
    value = "{{name}} {{ $json.x }}"
    data = workflow([trigger(), node("S", "set", {"plain": value})], link("Start", "S"))
    found = of(data, "N8D212")
    assert len(found) == 1 and not found[0].fixable and "{{name}}" in found[0].message
    result = fix_workflow(from_data(data, "x.json")[0], {"N8D212"})
    assert result.fixed["nodes"][1]["parameters"]["plain"] == value and result.changes == []
