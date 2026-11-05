# Contributing

Thanks for helping. The most useful bug report is a workflow JSON (with secrets and
customer data removed) plus the `n8n-doctor lint --format json` output and what you
expected instead. False positives are bugs too.

## Setup

```bash
git clone https://github.com/vladosskins178/n8n-doctor
cd n8n-doctor
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

```bash
ruff check . && ruff format --check .
mypy --strict src tests
pytest
```

## Adding a rule

- Pick the next free id in its group (`N8D1xx` security, `N8D2xx` structure, `N8D3xx`
  reliability, `N8D4xx` code) and a short kebab-case name. Ids and names are permanent;
  a retired id is never reused.
- Only add rules that can be decided from the workflow JSON alone, with few false
  positives. When in doubt, use `info`. `error` is for things that fail at run time or leak
  secrets.
- Register it with `@rule(...)` in `src/n8n_doctor/rules.py`, with a `fix` text a person can
  act on.
- Add positive and negative cases to `tests/test_rules.py`, and a section plus a table row
  to `docs/rules.md` (a test checks both).
- If it can be fixed safely, add the patch to `src/n8n_doctor/fix.py` and mark it `fixable`.
- Never print secret values in messages.

## Releasing

1. Update `version` in `pyproject.toml`, `src/n8n_doctor/__init__.py` and
   `.claude-plugin/plugin.json` (a test checks they match).
2. Move the "Unreleased" notes in `CHANGELOG.md` under the new version.
3. Tag `vX.Y.Z`, move the major tag (`v0`) to it for the GitHub Action, and push both.
