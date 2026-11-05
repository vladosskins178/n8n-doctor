"""Helpers to build small n8n workflows in tests."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from n8n_doctor.config import Config
from n8n_doctor.limits import MB, Limits
from n8n_doctor.lint import run
from n8n_doctor.model import Finding
from n8n_doctor.workflow import Workflow, from_data

ROOT = Path(__file__).resolve().parents[1]

# For tests of how the algorithms scale: far above the default resource limits.
BIG = Limits(
    max_nodes=100_000,
    max_file_nodes=10**9,
    max_connections=1_000_000,
    max_outputs=1_000_000,
    max_targets=1_000_000,
    max_name_chars=10**9,
    max_path_chars=10**9,
    max_parameter_values=10**9,
    max_list_length=10**9,
    max_value_chars=64 * MB,
    max_code_chars=64 * MB,
    max_findings_per_rule=10**9,
    max_findings=10**9,
    max_findings_total=10**9,
    max_secrets=10**9,
    max_secret_chars=10**10,
    max_output_bytes=10**10,
)
EXAMPLES = ROOT / "examples"
REGRESSION_FIXTURES = ROOT / "tests" / "fixtures" / "regressions"  # inputs that once broke a command


def node(name: str, type_: str, params: dict[str, Any] | None = None, version: float = 1, **raw: Any) -> dict[str, Any]:
    full = type_ if "." in type_ else f"n8n-nodes-base.{type_}"
    return {"parameters": params or {}, "name": name, "type": full, "typeVersion": version, "position": [0, 0], **raw}


def link(*names: str, output: int = 0) -> dict[str, Any]:
    """Connections for a straight chain ``a -> b -> c`` (from ``output`` of each node)."""
    conns: dict[str, Any] = {}
    for a, b in itertools.pairwise(names):
        outs = conns.setdefault(a, {"main": []})["main"]
        while len(outs) <= output:
            outs.append([])
        outs[output].append({"node": b, "type": "main", "index": 0})
    return conns


def merge(*conns: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for c in conns:
        for src, kinds in c.items():
            for kind, outputs in kinds.items():
                dest = out.setdefault(src, {}).setdefault(kind, [])
                for i, targets in enumerate(outputs):
                    while len(dest) <= i:
                        dest.append([])
                    dest[i].extend(targets)
    return out


def workflow(nodes: list[dict[str, Any]], connections: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    return {"name": extra.pop("name", "Test"), "nodes": nodes, "connections": connections or {}, **extra}


def trigger(name: str = "Start") -> dict[str, Any]:
    return node(name, "manualTrigger")


def load(data: dict[str, Any]) -> Workflow:
    return from_data(data, "test.json")[0]


def findings(data: dict[str, Any], cfg: Config | None = None) -> list[Finding]:
    return run([load(data)], cfg)


def rule_ids(data: dict[str, Any], rule: str | None = None) -> list[str]:
    ids = [f.rule.id for f in findings(data)]
    return [i for i in ids if i == rule] if rule else ids


def of(data: dict[str, Any], rule: str) -> list[Finding]:
    return [f for f in findings(data) if f.rule.id == rule]


@pytest.fixture
def write_json(tmp_path: Path) -> Any:
    def _write(data: Any, name: str = "wf.json") -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    return _write
