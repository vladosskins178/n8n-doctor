"""N8D209 after n8n's checkResponseModeConfiguration (nodes-base/nodes/Webhook/utils.ts, called from Webhook.node.ts
for a Webhook of version 2 or later), and how disabled nodes and Filter outputs carry the flow."""

from __future__ import annotations

from typing import Any

import pytest

from n8n_doctor.explain import outline
from n8n_doctor.model import Severity
from n8n_doctor.nodes import output_labels

from .conftest import link, load, merge, node, of, workflow


def _hook(mode: str, version: float = 2) -> dict[str, Any]:
    return node("Hook", "webhook", {"path": "x", "responseMode": mode}, version)


def _wait(resume: str = "webhook", mode: str | None = None, **raw: Any) -> dict[str, Any]:
    params = {"resume": resume, **({"responseMode": mode} if mode else {})}
    return node("Wait", "wait", params, 1.1, **raw)


REPLY = node("Reply", "respondToWebhook", {}, 1.1)
OFF_REPLY = node("Reply", "respondToWebhook", {}, 1.1, disabled=True)


@pytest.mark.parametrize("mode", ["onReceived", "lastNode"])
@pytest.mark.parametrize(
    "between",
    [
        _wait("webhook"),
        _wait("form"),
        _wait("webhook", "onReceived"),
        _wait("form", "lastNode"),
        _wait("webhook", "responseNode", disabled=True),
        _wait("form", "responseNode", disabled=True),
        _wait("timeInterval"),
        _wait("timeInterval", "responseNode"),
        _wait("webhook", "={{ 'responseNode' }}"),
        node("Wait", "form", {"operation": "page"}, 1),
    ],
)
def test_respond_nobody_owns_fails_the_run(mode: str, between: dict[str, Any]) -> None:
    found = of(workflow([_hook(mode), between, REPLY], link("Hook", "Wait", "Reply")), "N8D209")
    assert len(found) == 1
    assert found[0].severity == Severity.ERROR
    assert '"Reply"' in found[0].message


@pytest.mark.parametrize("mode", ["onReceived", "lastNode"])
@pytest.mark.parametrize("resume", ["webhook", "form"])
def test_respond_owned_by_a_wait_is_fine(mode: str, resume: str) -> None:
    assert of(workflow([_hook(mode), _wait(resume, "responseNode"), REPLY], link("Hook", "Wait", "Reply")), "N8D209") == []


def test_owner_anywhere_before_the_respond_counts() -> None:
    a = node("A", "noOp")
    data = workflow([_hook("onReceived"), a, _wait("webhook", "responseNode"), REPLY], merge(link("Hook", "A", "Wait", "Reply"), link("A", "Reply")))
    assert of(data, "N8D209") == []  # a parent Wait is all n8n asks for, even with a path around it


def test_one_unowned_respond_is_enough() -> None:
    other = node("Other", "respondToWebhook", {}, 1.1)
    data = workflow([_hook("onReceived"), _wait("webhook", "responseNode"), REPLY, other], merge(link("Hook", "Wait", "Reply"), link("Hook", "Other")))
    found = of(data, "N8D209")
    assert len(found) == 1
    assert '"Other"' in found[0].message
    assert '"Reply"' not in found[0].message


def test_owner_must_follow_this_webhook() -> None:
    second = node("Second", "webhook", {"path": "y", "responseMode": "onReceived"}, 2)
    data = workflow([_hook("onReceived"), second, _wait("webhook", "responseNode"), REPLY], merge(link("Second", "Wait", "Reply"), link("Hook", "Reply")))
    found = of(data, "N8D209")
    assert [f.node for f in found] == ["Hook"]


@pytest.mark.parametrize("mode", ["onReceived", "lastNode"])
def test_disabled_respond_counts_for_n8n(mode: str) -> None:
    found = of(workflow([_hook(mode), OFF_REPLY], link("Hook", "Reply")), "N8D209")
    assert len(found) == 1
    assert found[0].severity == Severity.ERROR
    assert "disabled" in found[0].message


def test_disabled_respond_behind_an_owner_is_fine() -> None:
    assert of(workflow([_hook("onReceived"), _wait("webhook", "responseNode"), OFF_REPLY], link("Hook", "Wait", "Reply")), "N8D209") == []


def test_error_names_what_n8n_says() -> None:
    found = of(workflow([_hook("onReceived"), REPLY], link("Hook", "Reply")), "N8D209")
    assert "Unused Respond to Webhook node" in found[0].message


def test_webhook_before_version_2_has_no_such_check() -> None:
    assert of(workflow([_hook("onReceived", 1.1), _wait("webhook"), REPLY], link("Hook", "Wait", "Reply")), "N8D209") == []
    assert of(workflow([_hook("onReceived", 1.1), OFF_REPLY], link("Hook", "Reply")), "N8D209") == []


def test_streaming_and_response_node_are_outside_this_check() -> None:
    assert of(workflow([_hook("streaming"), _wait("webhook"), REPLY], link("Hook", "Wait", "Reply")), "N8D209") == []
    found = of(workflow([_hook("responseNode"), REPLY], link("Hook", "Reply")), "N8D209")
    assert found == []


def test_disabled_webhook_is_not_checked() -> None:
    hook = {**_hook("onReceived"), "disabled": True}
    assert of(workflow([hook, REPLY], link("Hook", "Reply")), "N8D209") == []


def test_disabled_wait_passes_through_to_the_respond() -> None:
    data = workflow([_hook("responseNode"), _wait("webhook", "responseNode", disabled=True), REPLY], link("Hook", "Wait", "Reply"))
    assert of(data, "N8D209") == []
    dead_end = workflow([_hook("responseNode"), _wait("webhook", "responseNode", disabled=True), node("A", "noOp")], link("Hook", "Wait", "A"))
    assert "no Respond to Webhook node follows" in of(dead_end, "N8D209")[0].message


def test_enabled_wait_still_starts_a_new_request() -> None:
    data = workflow(
        [_hook("responseNode"), REPLY, _wait("webhook", "responseNode"), node("A", "noOp")], merge(link("Hook", "Reply"), link("Hook", "Wait", "A"))
    )
    assert of(data, "N8D209") == []


def _if(**raw: Any) -> dict[str, Any]:
    return node("Check", "if", {}, 2, **raw)


def test_disabled_if_only_uses_its_first_output() -> None:
    a, b = node("A", "noOp"), node("B", "noOp")
    # Respond on the second output only: a disabled IF never gets there
    second_only = workflow([_hook("responseNode"), _if(disabled=True), REPLY], merge(link("Hook", "Check"), link("Check", "Reply", output=1)))
    assert "no Respond to Webhook node follows" in of(second_only, "N8D209")[0].message
    # Respond on the first, nothing on the second: no gap
    first_only = workflow([_hook("responseNode"), _if(disabled=True), REPLY], merge(link("Hook", "Check"), link("Check", "Reply")))
    assert of(first_only, "N8D209") == []
    # first goes to a dead end, second answers: it can end unanswered
    data = workflow(
        [_hook("responseNode"), _if(disabled=True), a, REPLY, b], merge(link("Hook", "Check"), link("Check", "A"), link("Check", "Reply", output=1))
    )
    assert of(data, "N8D209")
    # the same enabled: partly answered is a warning, not "none follows"
    enabled = workflow([_hook("responseNode"), _if(), a, REPLY], merge(link("Hook", "Check"), link("Check", "A"), link("Check", "Reply", output=1)))
    found = of(enabled, "N8D209")
    assert found[0].severity == Severity.WARNING


def test_filter_has_a_discarded_output() -> None:
    assert output_labels(load(workflow([node("F", "filter", {}, 2)])).nodes[0]) == ["kept", "discarded"]
    assert output_labels(load(workflow([node("F", "filter", {}, 2.2, onError="continueErrorOutput")])).nodes[0]) == ["kept", "error"]


def test_filter_discarded_is_shown_when_connected_and_answers() -> None:
    other = node("Other", "respondToWebhook", {}, 1.1)
    conns = merge(link("Hook", "F"), link("F", "Reply"), link("F", "Other", output=1))
    data = workflow([_hook("responseNode"), node("F", "filter", {}, 2), REPLY, other], conns)
    assert of(data, "N8D209") == []
    assert "discarded" in outline(load(data))


def test_filter_discarded_left_open_is_no_gap() -> None:
    # the editor offers one connector on a Filter, so there is nothing to connect it to
    data = workflow([_hook("responseNode"), node("F", "filter", {}, 2), REPLY], merge(link("Hook", "F"), link("F", "Reply")))
    assert of(data, "N8D209") == []
