"""Resource limits: the size and shape of input n8n-doctor accepts, and how much it prints.

Real workflows have tens to a few hundred nodes. The limits keep the work per file
bounded on crafted input. They are checked once, when a file is loaded (see
:func:`workflow.from_data`), so every rule and every output works on bounded data:

- hard limits refuse the input with an error and exit code 2: file size, workflows per
  file, nesting depth, nodes, connections, outputs per node, connections per output,
  name length, parameter values per workflow, array length and path length inside
  parameters, and the
  number and total length of distinct secrets (found while the secrets are collected,
  before any output), and the nodes plus workflows of one file;
- soft limits check part of a large input and say so in an info finding (N8D001 or
  N8D101): the length of a value scanned for secrets, the length of Code analysed, the
  embedded workflows read as workflows (those past the file's budget of nodes plus
  workflows are scanned as text), and the text scanned where an embedded workflow does
  not parse;
- output limits cap what is printed: findings per rule, per workflow and per run (the
  rest are counted in one summary finding), and the size and depth of ``explain`` output;
- the workflow JSON ``executions`` reads to mask workflow secrets in error messages: past
  it, the messages of the remaining executions are hidden.

Change them with command line flags or a ``[limits]`` table in the config file.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

MAX_TIMEOUT_MS = 2_147_483_647  # the longest delay a Node.js timer takes: a longer one fires at once
MB = 1024 * 1024
HARD_MAX_FILE_BYTES = 64 * MB  # no setting goes above this


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 20 * MB  # a workflow file, stdin, an MCP inline workflow
    max_workflows: int = 1_000  # workflows in one file (an array of exports)
    max_depth: int = 64  # nesting of arrays and objects anywhere in the file
    max_nodes: int = 5_000  # entries in one workflow's "nodes" array
    max_file_nodes: int = 50_000  # nodes plus workflows in one file, those embedded in node parameters included
    max_connections: int = 50_000  # connections (edges) in one workflow, and output lists in its connections
    max_outputs: int = 1_000  # outputs of one node: output lists in its connections, Switch rules
    max_targets: int = 1_000  # connections from one output of a node
    max_name_chars: int = 1_024  # a node or workflow name (also node types, workflow ids, names in connections and pinned data)
    max_path_chars: int = 1_024  # the path of a value inside node parameters, as findings show it (options.headers[0].value)
    max_parameter_values: int = 200_000  # values (strings, numbers, objects, arrays...) in all node parameters of a workflow
    max_list_length: int = 10_000  # entries of one array inside node parameters
    max_value_chars: int = 256 * 1024  # a longer string is checked for secrets at its start and end only (half each)
    max_secrets: int = 50_000  # distinct secrets found in one workflow's parameters (every output masks all of them)
    max_secret_chars: int = 2 * MB  # their total length, in every spelling the masker looks for
    max_raw_scan_bytes: int = 8 * MB  # embedded text that does not parse, read as raw text per file (at each level of escapes)
    max_code_chars: int = 1 * MB  # Code node source analysed for references and legacy syntax (from the start)
    max_findings_per_rule: int = 200  # per workflow; the rest are counted in one summary finding
    max_findings: int = 5_000  # per workflow, all rules together; the rest are counted in one summary finding
    max_findings_total: int = 20_000  # per run, all workflows together; the rest are counted in one summary finding
    max_explain_depth: int = 50  # tree levels in `explain`; deeper branches continue without indentation
    max_output_bytes: int = 2 * MB  # bytes of `explain` text and Mermaid output per run, all workflows together (UTF-8)
    max_masker_chars: int = 16 * MB  # workflow JSON `executions` reads per run to mask workflow secrets in messages


DEFAULT = Limits()

# name in the config file and on the command line -> (field, unit multiplier, minimum)
SETTINGS: dict[str, tuple[str, int, int]] = {
    "max-file-mb": ("max_file_bytes", MB, 1),
    "max-workflows-per-file": ("max_workflows", 1, 1),
    "max-depth": ("max_depth", 1, 8),
    "max-nodes": ("max_nodes", 1, 1),
    "max-file-nodes": ("max_file_nodes", 1, 1),
    "max-connections": ("max_connections", 1, 0),
    "max-outputs": ("max_outputs", 1, 1),
    "max-targets-per-output": ("max_targets", 1, 1),
    "max-name-length": ("max_name_chars", 1, 1),
    "max-path-length": ("max_path_chars", 1, 1),
    "max-parameter-values": ("max_parameter_values", 1, 1),
    "max-list-length": ("max_list_length", 1, 1),
    "max-value-kb": ("max_value_chars", 1024, 2),
    "max-secrets": ("max_secrets", 1, 1),
    "max-secret-kb": ("max_secret_chars", 1024, 1),
    "max-raw-scan-mb": ("max_raw_scan_bytes", MB, 1),
    "max-code-kb": ("max_code_chars", 1024, 1),
    "max-findings-per-rule": ("max_findings_per_rule", 1, 1),
    "max-findings": ("max_findings", 1, 1),
    "max-findings-total": ("max_findings_total", 1, 1),
    "max-explain-depth": ("max_explain_depth", 1, 1),
    "max-output-kb": ("max_output_bytes", 1024, 1),
    "max-masker-mb": ("max_masker_chars", MB, 1),
}

# Settings that only one command uses: the others do not offer them as flags.
LINT_ONLY = frozenset({"max-findings-per-rule", "max-findings", "max-findings-total"})
EXPLAIN_ONLY = frozenset({"max-explain-depth", "max-output-kb"})
EXECUTIONS_ONLY = frozenset({"max-masker-mb"})
# The JSON parser itself stops near 1,000 levels; max-depth stays well below that.
HARD_MAX_DEPTH = 512


def _shown(text: object) -> str:
    from .rules import shorten  # rules imports this module

    return repr(shorten(str(text), 40))


def with_settings(base: Limits, values: dict[str, Any], where: str) -> Limits:
    """``base`` with the settings in ``values`` (config names, numbers in the units of the name) applied.

    Raises ValueError for an unknown name or a value that is not a whole number in range.
    """
    changes: dict[str, int] = {}
    for key, value in values.items():
        if key not in SETTINGS:
            raise ValueError(f"{where}: unknown limit {_shown(key)}; allowed: {', '.join(SETTINGS)}")
        attr, unit, minimum = SETTINGS[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValueError(f"{where}: {key} must be a whole number of at least {minimum}")
        amount = value * unit
        if attr == "max_file_bytes" and amount > HARD_MAX_FILE_BYTES:
            raise ValueError(f"{where}: {key} can be at most {HARD_MAX_FILE_BYTES // MB}")
        if attr == "max_depth" and amount > HARD_MAX_DEPTH:
            raise ValueError(f"{where}: {key} can be at most {HARD_MAX_DEPTH}")
        changes[attr] = amount
    return replace(base, **changes)
