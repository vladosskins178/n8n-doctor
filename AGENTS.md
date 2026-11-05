# Notes for coding agents

This file is for agents working **on this repository**. To use n8n-doctor on n8n
workflows, load [`skills/n8n-doctor/SKILL.md`](skills/n8n-doctor/SKILL.md) instead (Claude
Code picks it up as a skill; for other agents, `n8n-doctor skill print >> AGENTS.md` in
the project that holds the workflows).

## Layout

- `src/n8n_doctor/workflow.py` loads workflow JSON (single, arrays, API wrappers), builds
  the node/edge model and computes node line numbers for reports.
- `src/n8n_doctor/rules.py` holds every rule; `nodes.py` has node-type knowledge (outputs,
  schedules, summaries); `expressions.py` finds node references in expressions and code.
- `lint.py` runs the rules (config, suppressions), `report.py` renders text, JSON, SARIF and
  GitHub annotations, `fix.py` computes the fixes, `explain.py` the outline and Mermaid chart.
- `api.py` is the read-only n8n API client (GET only, no redirects), `executions.py` groups
  failed executions, `mcp.py` is a dependency-free MCP server, `cli.py` the entry point.
- `examples/`: two workflows broken on purpose (`lead-intake.json`, `order-sync.json`) and
  one clean one (`healthy.json`), used by tests, CI and the README. `tests/test_examples.py`
  pins the exact rules each one triggers.

## Checks before you finish

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
pytest
```

## Rules

- Standard library only (plus `tomli` on Python 3.10). Ask before adding dependencies.
- The API client must only ever send GET requests and never print `N8N_API_KEY`; tests
  assert both.
- `fix` never modifies its input file.
- Every rule needs tests (positive and negative) and an entry in `docs/rules.md`.
