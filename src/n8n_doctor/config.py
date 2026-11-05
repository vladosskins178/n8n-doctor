"""``.n8n-doctor.toml``: disable rules, change severities, exclude files.

Example::

    disable = ["N8D303", "pinned-data"]     # rule ids or names
    fail-on = "warning"                     # error (default), warning, info or never
    exclude = ["drafts/**", "*.backup.json"]

    [severity]
    http-without-timeout = "error"

    [rules.hardcoded-secret]
    allow = ["^pk_test_"]                   # regexes for values that are not secrets

    [limits]
    max-nodes = 10000                       # resource limits, see README "Resource limits"

The same keys work under ``[tool.n8n-doctor]`` in ``pyproject.toml``.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .limits import DEFAULT, Limits, with_settings
from .model import Severity

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 only
    import tomli as tomllib

CONFIG_NAMES = (".n8n-doctor.toml", "n8n-doctor.toml")
FAIL_ON = ("error", "warning", "info", "never")
_KEYS = {"disable", "enable", "fail-on", "exclude", "severity", "rules", "limits"}


# `allow` regexes come from a config file, which a pull request can change: their size is capped,
# and they are only matched against values up to ALLOW_MAX_INPUT characters, so a pathological
# pattern costs bounded time per value.
ALLOW_MAX_PATTERN = 200
ALLOW_MAX_INPUT = 1024


class ConfigError(Exception):
    pass


def _shown(text: str, limit: int = 80) -> str:
    """User text in an error message: masked, then shortened (see :func:`rules.shorten`)."""
    from .rules import shorten  # rules imports this module

    return repr(shorten(text, limit))


def compile_allow(pattern: str) -> re.Pattern[str]:
    """An ``allow`` regex, refusing long patterns."""
    if len(pattern) > ALLOW_MAX_PATTERN:
        raise ConfigError(f"allow pattern longer than {ALLOW_MAX_PATTERN} characters: {_shown(pattern, 40)}")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"bad regex {_shown(pattern)} ({exc})") from None


@dataclass
class Config:
    disabled: set[str] = field(default_factory=set)  # rule ids
    enabled_only: set[str] | None = None  # rule ids; None = all
    severity: dict[str, Severity] = field(default_factory=dict)  # rule id -> severity
    fail_on: str = "error"
    exclude: list[str] = field(default_factory=list)
    options: dict[str, dict[str, Any]] = field(default_factory=dict)  # rule id -> options
    path: Path | None = None
    limits: Limits = DEFAULT

    @property
    def root(self) -> Path:
        return self.path.parent if self.path else Path.cwd()

    def is_enabled(self, rule_id: str) -> bool:
        if rule_id in self.disabled:
            return False
        return self.enabled_only is None or rule_id in self.enabled_only

    def is_excluded(self, file: Path) -> bool:
        if not self.exclude:
            return False
        try:
            rel = PurePosixPath(file.resolve().relative_to(self.root.resolve()).as_posix())
        except ValueError:
            rel = PurePosixPath(file.as_posix())
        text = str(rel)
        for pattern in self.exclude:
            if fnmatch.fnmatchcase(text, pattern) or fnmatch.fnmatchcase(rel.name, pattern):
                return True
            if pattern.endswith("/**") and (text + "/").startswith(pattern[:-2]):
                return True
        return False


def find_config(start: Path, stop_at: Path | None = None) -> Path | None:
    """The nearest config file in ``start`` or its parents, stopping at a repository root (or at ``stop_at``)."""
    current = start.resolve()
    if current.is_file():
        current = current.parent
    stop = stop_at.resolve() if stop_at else None
    for folder in (current, *current.parents):
        if stop is not None and folder != stop and stop not in folder.parents:
            break
        for name in CONFIG_NAMES:
            candidate = folder / name
            if candidate.is_file():
                return candidate
        pyproject = folder / "pyproject.toml"
        if pyproject.is_file() and _pyproject_section(pyproject) is not None:
            return pyproject
        if (folder / ".git").exists():
            break
    return None


def _pyproject_section(path: Path) -> dict[str, Any] | None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    tool = data.get("tool")
    section = tool.get("n8n-doctor") if isinstance(tool, dict) else None
    return section if isinstance(section, dict) else None


def _string_list(data: dict[str, Any], key: str, where: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: '{key}' must be a list of strings")
    return list(value)


def load(path: Path | None, resolve_rule: Any) -> Config:
    """Read a config file. ``resolve_rule`` maps an id or name to a rule id (or raises KeyError)."""
    if path is None:
        return Config()
    where = str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{where}: cannot read ({exc})") from exc
    if path.name == "pyproject.toml":
        section = _pyproject_section(path)
        data: dict[str, Any] = section or {}
        where += " [tool.n8n-doctor]"
    else:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{where}: invalid TOML ({exc})") from exc
    unknown = set(data) - _KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(_shown(k, 40) for k in sorted(unknown)[:10])}; allowed: {', '.join(sorted(_KEYS))}")

    def rule_id(ref: str) -> str:
        try:
            return str(resolve_rule(ref))
        except KeyError:
            raise ConfigError(f"{where}: unknown rule {_shown(ref, 40)} (see `n8n-doctor rules`)") from None

    cfg = Config(path=path)
    cfg.disabled = {rule_id(r) for r in _string_list(data, "disable", where)}
    if "enable" in data:
        cfg.enabled_only = {rule_id(r) for r in _string_list(data, "enable", where)}
    cfg.exclude = _string_list(data, "exclude", where)
    fail_on = data.get("fail-on", "error")
    if fail_on not in FAIL_ON:
        raise ConfigError(f"{where}: 'fail-on' must be one of {', '.join(FAIL_ON)}")
    cfg.fail_on = fail_on
    severity = data.get("severity", {})
    if not isinstance(severity, dict):
        raise ConfigError(f'{where}: [severity] must be a table of rule = "error" | "warning" | "info"')
    for ref, level in severity.items():
        if not isinstance(level, str):
            raise ConfigError(f"{where}: severity for {_shown(ref, 40)} must be a string")
        try:
            cfg.severity[rule_id(ref)] = Severity.parse(level)
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from None
    rules = data.get("rules", {})
    if not isinstance(rules, dict) or not all(isinstance(v, dict) for v in rules.values()):
        raise ConfigError(f"{where}: [rules.<rule>] entries must be tables")
    for ref, options in rules.items():
        rid = rule_id(ref)
        allow = options.get("allow")
        if allow is not None:
            items = _string_list(options, "allow", f"{where} [rules.{_shown(ref, 40)}]")
            for pattern in items:
                try:
                    compile_allow(pattern)
                except ConfigError as exc:
                    raise ConfigError(f"{where} [rules.{_shown(ref, 40)}]: {exc}") from None
        cfg.options[rid] = dict(options)
    limits = data.get("limits", {})
    if not isinstance(limits, dict):
        raise ConfigError(f"{where}: [limits] must be a table")
    try:
        cfg.limits = with_settings(DEFAULT, limits, f"{where} [limits]")
    except ValueError as exc:
        raise ConfigError(str(exc)) from None
    return cfg
