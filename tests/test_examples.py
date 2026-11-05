"""The shipped examples double as regression fixtures: each one shows a known set of rules."""

from __future__ import annotations

from n8n_doctor.lint import run
from n8n_doctor.workflow import load_file

from .conftest import EXAMPLES


def _ids(name: str) -> set[str]:
    return {f.rule.id for f in run(load_file(EXAMPLES / name))}


def test_lead_intake() -> None:
    assert _ids("lead-intake.json") == {"N8D101", "N8D102", "N8D103", "N8D201", "N8D203", "N8D207", "N8D208", "N8D209", "N8D211", "N8D301", "N8D302", "N8D303"}


def test_order_sync() -> None:
    assert _ids("order-sync.json") == {"N8D204", "N8D210", "N8D302", "N8D304", "N8D306", "N8D308", "N8D310", "N8D401", "N8D403"}


def test_healthy() -> None:
    assert _ids("healthy.json") == set()
