"""What fix may rename a reference to: one clearly best node, never the neighbour of a numbered copy."""

from __future__ import annotations

import pytest

from n8n_doctor.fix import fix_workflow
from n8n_doctor.rules import suggest_name

from .conftest import link, load, node, of, trigger, workflow


def _flow(names: list[str], ref: str) -> dict[str, object]:
    nodes = [trigger(), *[node(n, "noOp") for n in names], node("C", "code", {"jsCode": f"$('{ref}').all();"}, 2)]
    return workflow(nodes, link("Start", names[0], "C"))


def _code_after_fix(names: list[str], ref: str) -> object:
    return fix_workflow(load(_flow(names, ref)), {"N8D207"}).fixed["nodes"][-1]["parameters"]["jsCode"]


def test_numbered_copy_is_not_renamed_to_the_neighbour() -> None:
    names = ["Content Database (Posts)", "Content Database (Video)"]
    ref = "Content Database (Posts)1"
    assert suggest_name(load(_flow(names, ref)), ref) is None
    assert _code_after_fix(names, ref) == f"$('{ref}').all();"
    found = of(_flow(names, ref), "N8D207")
    assert found[0].autofix is False
    assert '"Content Database (Posts)"' in (found[0].fix_hint or "")
    assert "(Video)" not in (found[0].fix_hint or "")


@pytest.mark.parametrize(
    ("names", "ref"),
    [
        (["Get Lead1", "Get Leads"], "Get Lead"),  # same stem as Get Lead1
        (["Get Lead", "get lead2"], "Get Lead2"),  # a case variant of the name, but Get Lead has its stem
    ],
)
def test_same_stem_stops_every_rename(names: list[str], ref: str) -> None:
    assert suggest_name(load(_flow(names, ref)), ref) is None


def test_several_copies_suggest_only_the_plain_stem() -> None:
    plain = of(_flow(["Step", "Step1"], "Step3"), "N8D207")[0]
    assert '"Step"' in (plain.fix_hint or "")
    assert not plain.autofix
    numbered = of(_flow(["Step1", "Step2"], "Step3"), "N8D207")[0]
    assert "Did you mean" not in (numbered.fix_hint or "")


@pytest.mark.parametrize(
    ("names", "ref"),
    [
        (["Fetch A"], "Fetch B"),  # one candidate, another word
        (["Sheet Orders", "Sheet Orderz"], "Sheet Orderx"),  # two equally close
        (["Report v2"], "Report v3"),
        (["Content Database (Video)"], "Content Database (Posts)"),
    ],
)
def test_no_rename_without_one_clearly_best_name(names: list[str], ref: str) -> None:
    assert suggest_name(load(_flow(names, ref)), ref) is None


def test_only_a_unique_best_candidate_is_renamed_to() -> None:
    assert suggest_name(load(_flow(["Transfarmirs", "Transfo"], "Transformers")), "Transformers") == "Transfarmirs"
    assert suggest_name(load(_flow(["Sheet Orders", "Sheet Ordersx"], "Sheet Orderx")), "Sheet Orderx") is None  # one edit from both
    assert suggest_name(load(_flow(["Send Email", "Send Emilia"], "Send Emial")), "Send Emial") == "Send Email"  # one edit against three


@pytest.mark.parametrize(
    ("names", "ref", "target"),
    [
        (["Mizing"], "Mising", "Mizing"),
        (["HTTP Request"], "http request", "HTTP Request"),
        (["Send Email"], "Send Emial", "Send Email"),
        (["get_customer orders"], "Get Customer Orders", "get_customer orders"),
        (["Get-Data"], "get data", "Get-Data"),
        (["GetData"], "Get Data", "GetData"),
        (["⚙️ Configuration"], "Configuration", "⚙️ Configuration"),
        (["Report (Monthly)"], "Report Monthly", "Report (Monthly)"),
        (["Customers"], "Custmoers", "Customers"),  # a transposition
        (["Get Customers"], "Get Custoemrs", "Get Customers"),
        (["Approve Order"], "Aproove Order", "Approve Order"),  # two edits in a long word
        (["Получить заказы"], "Получить закзы", "Получить заказы"),
    ],
)
def test_clear_typos_are_still_renamed(names: list[str], ref: str, target: str) -> None:
    assert suggest_name(load(_flow(names, ref)), ref) == target


@pytest.mark.parametrize(
    ("name", "ref"),
    [
        ("Set Data", "Get Data"),
        ("Export Rows", "Import Rows"),
        ("Decode Text", "Encode Text"),
        ("Decrypt File", "Encrypt File"),
        ("Outbound Call", "Inbound Call"),
        ("Decrease Stock", "Increase Stock"),
        ("Exclude Users", "Include Users"),
        ("Folder", "Filter"),  # two edits, the same first letter: another word, not a typo
        ("Purge", "Parse"),
        ("Treat", "Trend"),
        ("Score < 5", "Score > 5"),
        ("Profit +", "Profit -"),
        ("Step 12", "Step 1 2"),
        ("Fetch Users1", "Fetch Users2"),
    ],
)
def test_another_word_is_never_renamed_to(name: str, ref: str) -> None:
    assert suggest_name(load(_flow([name], ref)), ref) is None
    assert _code_after_fix([name], ref) == f"$('{ref}').all();"


@pytest.mark.parametrize(
    ("name", "ref"),
    [
        ("Get Customer", "Get Customer Orders"),
        ("Set", "Set Variables"),
        ("github", "github change trigger"),
        ("Enrich lead", "Enrich"),
        ("Sort Instagram Results", "Sort Instagram"),
        ("Organize & Generate Order ID", "Organize"),
        ("Post Reply", "Post Replies Now"),
    ],
)
def test_prefix_and_subset_are_suggestions_only(name: str, ref: str) -> None:
    assert suggest_name(load(_flow([name], ref)), ref) is None
    assert _code_after_fix([name], ref) == f"$('{ref}').all();"
    found = of(_flow([name], ref), "N8D207")[0]
    assert found.autofix is False


def test_a_suggestion_names_the_node_and_says_fix_leaves_it() -> None:
    hint = of(_flow(["Get Customer"], "Get Customer Orders"), "N8D207")[0].fix_hint or ""
    assert '"Get Customer"' in hint and "leaves" in hint and "can rewrite" not in hint


@pytest.mark.parametrize(
    ("names", "ref"),
    [
        (["Get-Data", "get data"], "GET DATA"),  # two names differ only by case and punctuation
        (["Post"], "Posts"),  # a word under 5 letters
        (["Emails Now"], "Emials Sent"),  # two words differ
        (["Custmer Odrers"], "Customer Orders"),
    ],
)
def test_conservative_edges_are_not_renamed(names: list[str], ref: str) -> None:
    assert suggest_name(load(_flow(names, ref)), ref) is None
