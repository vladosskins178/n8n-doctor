"""Shared types: severities, rules and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


def plural(n: int, word: str, many: str | None = None) -> str:
    """``1 finding``, ``2 findings`` (``many``: an irregular plural)."""
    return f"{n:,} {word if n == 1 else many or word + 's'}"


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        key = value.strip().lower()
        aliases = {"warn": "warning", "err": "error", "note": "info"}
        key = aliases.get(key, key)
        for sev in cls:
            if sev.label == key:
                return sev
        raise ValueError(f"unknown severity {value!r} (use error, warning or info)")


DOCS_URL = "https://github.com/vladosskins178/n8n-doctor/blob/main/docs/rules.md"


@dataclass(frozen=True)
class Rule:
    id: str  # stable, e.g. N8D101
    name: str  # stable slug, e.g. hardcoded-secret
    severity: Severity
    summary: str  # one line: what is wrong
    fix: str  # one line: what to do about it
    fixable: bool = False

    @property
    def doc_url(self) -> str:
        return f"{DOCS_URL}#{self.id.lower()}-{self.name}"


@dataclass
class Finding:
    rule: Rule
    message: str
    severity: Severity
    source: str = ""
    workflow: str = ""
    workflow_id: str | None = None
    position: int = 0
    node: str | None = None
    node_type: str | None = None
    parameter: str | None = None
    line: int = 1
    fix_hint: str | None = None
    suppressed: str | None = None  # "node notes" or "sticky note" when silenced inline
    autofix: bool = True  # False when this instance of a fixable rule cannot be fixed automatically
    extra: dict[str, Any] = field(default_factory=dict)
    # where the node is in the workflow's node list: ``node`` is the name as shown (secrets masked)
    node_index: int | None = None

    @property
    def fixable(self) -> bool:
        return self.rule.fixable and self.autofix

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule.id,
            "name": self.rule.name,
            "severity": self.severity.label,
            "message": self.message,
            "fix": self.fix_hint or self.rule.fix,
            "fixable": self.fixable,
            "file": self.source,
            "line": self.line,
            "workflow": self.workflow,
            "workflow_id": self.workflow_id,
            "node": self.node,
            "node_type": self.node_type,
            "parameter": self.parameter,
            "docs": self.rule.doc_url,
        }
        if self.suppressed:
            out["suppressed"] = self.suppressed
        if self.position:
            out["index"] = self.position
        if self.extra.get("omitted"):
            out["omitted"] = dict(self.extra["omitted"])  # findings past the per-rule limit, by severity
        if self.extra.get("omitted_by_rule"):
            out["omitted_by_rule"] = dict(self.extra["omitted_by_rule"])  # past the per-run limit, by rule
        return out
